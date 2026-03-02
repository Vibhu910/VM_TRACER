// SPDX-License-Identifier: GPL-2.0
// vm_tracer.bpf.c
// Traces per-process: page faults (address, type, flags),
// VMA changes (mmap, munmap, mprotect, mremap, brk, stack growth)
// Requires: libbpf + CO-RE (kernel BTF)
//
// FIXED for Linux 6.1+ where mm->mmap and vma->vm_next were removed

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────
#define TASK_COMM_LEN  16
#define PATH_LEN       64

// Event type tags
#define EVT_FAULT_ANON     1   // page fault on anonymous memory
#define EVT_FAULT_FILE     2   // page fault on file-backed memory
#define EVT_FAULT_COW      3   // copy-on-write fault
#define EVT_FAULT_MINOR    4   // minor fault (page already in memory, just not mapped)
#define EVT_MMAP           5   // mmap() called — new VMA created
#define EVT_MUNMAP         6   // munmap() called — VMA destroyed
#define EVT_MPROTECT       7   // mprotect() called — VMA permissions changed
#define EVT_MREMAP         8   // mremap() called — VMA moved/resized
#define EVT_BRK            9   // brk() called — heap expanded/shrunk
#define EVT_STACK_GROW     10  // stack VMA expanded downward
#define EVT_FORK_MM        11  // child process mm cloned from parent (fork)
#define EVT_EXIT_MM        12  // process mm torn down (exit)
#define EVT_MMAP_FILE      13  // mmap() of a named file specifically

// Page fault flag bits (mirrors kernel FAULT_FLAG_*)
#define FF_WRITE       (1 << 0)
#define FF_MKWRITE     (1 << 1)
#define FF_ALLOW_RETRY (1 << 2)
#define FF_RETRY_NOWAIT (1 << 3)
#define FF_USER        (1 << 4)
#define FF_REMOTE      (1 << 5)
#define FF_INSTRUCTION (1 << 6)

// VMA protection flags (mirrors kernel VM_* bits we care about)
#define VMA_READ    0x0001
#define VMA_WRITE   0x0002
#define VMA_EXEC    0x0004
#define VMA_SHARED  0x0008
#define VMA_GROWSDOWN 0x0100  // stack

// ─────────────────────────────────────────────
//  Shared event struct (kernel → user space)
// ─────────────────────────────────────────────
struct vm_event {
    __u64  timestamp_ns;
    __u32  event_type;
    __u32  pid;
    __u32  tgid;
    char   comm[TASK_COMM_LEN];

    // ── fault / address info ──
    __u64  fault_addr;      // faulting virtual address
    __u64  fault_flags;     // FAULT_FLAG_* bitmask
    __u32  fault_is_write;  // 1 if write fault
    __u32  fault_is_exec;   // 1 if instruction fetch fault
    __u32  fault_is_user;   // 1 if fault came from user space

    // ── VMA snapshot at time of event ──
    __u64  vma_start;       // vm_area_struct->vm_start
    __u64  vma_end;         // vm_area_struct->vm_end
    __u64  vma_flags;       // vm_area_struct->vm_flags (VM_READ|WRITE|EXEC|SHARED...)
    __u64  vma_pgoff;       // vm_area_struct->vm_pgoff (page offset into file)
    __u64  vma_size;        // vma_end - vma_start (bytes)

    // ── file backing (if file-mapped VMA) ──
    char   file_path[PATH_LEN];  // backing file name (empty if anonymous)
    __u64  file_inode;           // inode number

    // ── mmap / mremap arguments (captured from syscall entry) ──
    __u64  mmap_addr;       // requested address
    __u64  mmap_len;        // requested length
    __u32  mmap_prot;       // PROT_READ|WRITE|EXEC
    __u32  mmap_flags;      // MAP_SHARED|PRIVATE|ANON|FIXED...
    __u64  mmap_result;     // returned address (from syscall exit)

    // ── mremap extra ──
    __u64  old_addr;
    __u64  old_len;
    __u64  new_len;
    __u64  new_addr;        // result

    // ── brk extra ──
    __u64  brk_old;         // heap end before
    __u64  brk_new;         // heap end after (requested)
    __u64  brk_result;      // actual new heap end

    // ── mprotect extra ──
    __u64  mprot_addr;
    __u64  mprot_len;
    __u32  mprot_prot;      // new protection flags

    // ── process mm snapshot ──
    __u64  mm_start_code;   // start of code segment
    __u64  mm_end_code;     // end of code segment
    __u64  mm_start_data;   // start of data segment
    __u64  mm_end_data;     // end of data segment
    __u64  mm_start_heap;   // start of heap
    __u64  mm_brk;          // current heap end (brk)
    __u64  mm_start_stack;  // start of stack
    __u64  mm_mmap_base;    // base address for mmap region
    __u32  mm_map_count;    // number of VMAs in this mm
    __u64  mm_total_vm;     // total virtual memory pages
    __u64  mm_locked_vm;    // locked pages
    __u64  mm_data_vm;      // data + stack pages
    __u64  mm_exec_vm;      // executable pages

    // ── parent info (for fork) ──
    __u32  parent_pid;
    char   parent_comm[TASK_COMM_LEN];
};

// ─────────────────────────────────────────────
//  Maps
// ─────────────────────────────────────────────

// Ring buffer — events flow kernel → user space
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024); // 32 MB
} events SEC(".maps");

// Scratch map to pass syscall args from entry → exit probe
// (we need to correlate mmap entry args with exit return value)
struct mmap_args {
    __u64 addr;
    __u64 len;
    __u32 prot;
    __u32 flags;
    char  comm[TASK_COMM_LEN];
    __u32 tgid;
};
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);   // pid
    __type(value, struct mmap_args);
} mmap_scratch SEC(".maps");

struct brk_args {
    __u64 old_brk;
    __u64 requested;
    __u32 tgid;
};
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);
    __type(value, struct brk_args);
} brk_scratch SEC(".maps");

struct mremap_args {
    __u64 old_addr;
    __u64 old_len;
    __u64 new_len;
    __u64 new_addr;
    __u32 tgid;
};
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);
    __type(value, struct mremap_args);
} mremap_scratch SEC(".maps");

// Target PID filter — 0 means trace all
// Set from user space via bpf_map_update_elem before attaching
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

static __always_inline int should_trace(__u32 pid)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (tpid && *tpid != 0 && *tpid != pid)
        return 0;
    return 1;
}

static __always_inline void fill_base(struct vm_event *e,
                                      __u32 pid, __u32 tgid,
                                      const char *comm_src)
{
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid  = pid;
    e->tgid = tgid;
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), comm_src);
}

// Read mm_struct layout snapshot into event
static __always_inline void fill_mm(struct vm_event *e, struct mm_struct *mm)
{
    if (!mm) return;
    e->mm_start_code  = BPF_CORE_READ(mm, start_code);
    e->mm_end_code    = BPF_CORE_READ(mm, end_code);
    e->mm_start_data  = BPF_CORE_READ(mm, start_data);
    e->mm_end_data    = BPF_CORE_READ(mm, end_data);
    e->mm_start_heap  = BPF_CORE_READ(mm, start_brk);
    e->mm_brk         = BPF_CORE_READ(mm, brk);
    e->mm_start_stack = BPF_CORE_READ(mm, start_stack);
    e->mm_mmap_base   = BPF_CORE_READ(mm, mmap_base);
    e->mm_map_count   = BPF_CORE_READ(mm, map_count);
    e->mm_total_vm    = BPF_CORE_READ(mm, total_vm);
    e->mm_locked_vm   = BPF_CORE_READ(mm, locked_vm);
    e->mm_data_vm     = BPF_CORE_READ(mm, data_vm);
    e->mm_exec_vm     = BPF_CORE_READ(mm, exec_vm);
}

// Read VMA fields into event
static __always_inline void fill_vma(struct vm_event *e,
                                     struct vm_area_struct *vma)
{
    if (!vma) return;
    e->vma_start = BPF_CORE_READ(vma, vm_start);
    e->vma_end   = BPF_CORE_READ(vma, vm_end);
    e->vma_flags = BPF_CORE_READ(vma, vm_flags);
    e->vma_pgoff = BPF_CORE_READ(vma, vm_pgoff);
    e->vma_size  = e->vma_end - e->vma_start;

    // Try to get backing file name
    struct file *f = BPF_CORE_READ(vma, vm_file);
    if (f) {
        struct dentry *de = BPF_CORE_READ(f, f_path.dentry);
        if (de) {
            bpf_core_read_str(e->file_path, sizeof(e->file_path),
                              &de->d_iname);
        }
        struct inode *inode = BPF_CORE_READ(f, f_inode);
        if (inode) {
            e->file_inode = BPF_CORE_READ(inode, i_ino);
        }
    }
}

// Helper to find VMA by address using bpf_find_vma
// This is the modern way to look up VMAs in kernel 5.17+
static __always_inline struct vm_area_struct *
find_vma_by_addr(struct mm_struct *mm, __u64 addr)
{
    // Note: bpf_find_vma() is only available in newer kernels (5.17+)
    // For older kernels, you would need to use vma_find() kfunc or
    // iterate through the maple tree (complex)
    
    // We'll use a simpler approach: rely on context when VMA is passed to us
    // or use the fault handler's vma parameter
    return NULL; // Placeholder - actual VMA lookup needs kernel helpers
}

// ─────────────────────────────────────────────
//  1.  Page fault handler
//      Captures all page faults, determines type
// ─────────────────────────────────────────────
SEC("fentry/handle_mm_fault")
int BPF_PROG(trace_page_fault,
             struct vm_area_struct *vma,
             unsigned long address,
             unsigned int flags,
             struct pt_regs *regs)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    // Determine fault type
    __u32 evt_type = EVT_FAULT_ANON;
    struct file *f = BPF_CORE_READ(vma, vm_file);
    if (f) {
        evt_type = EVT_FAULT_FILE;
    }
    if (flags & 0x2) { // FAULT_FLAG_WRITE  
        __u64 vm_flags = BPF_CORE_READ(vma, vm_flags);
        if ((vm_flags & 0x0002) == 0) { // not writable -> COW
            evt_type = EVT_FAULT_COW;
        }
    }

    e->timestamp_ns    = bpf_ktime_get_ns();
    e->event_type      = evt_type;
    e->pid             = pid;
    e->tgid            = tgid;
    e->fault_addr      = address;
    e->fault_flags     = flags;
    e->fault_is_write  = (flags & 0x2) ? 1 : 0;   // FAULT_FLAG_WRITE
    e->fault_is_exec   = (flags & 0x40) ? 1 : 0;  // FAULT_FLAG_INSTRUCTION
    e->fault_is_user   = (flags & 0x10) ? 1 : 0;  // FAULT_FLAG_USER

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), task->comm);

    fill_vma(e, vma);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  2.  mmap() — new VMA created
// ─────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct mmap_args args = {};
    args.addr  = (unsigned long)ctx->args[0];
    args.len   = (unsigned long)ctx->args[1];
    args.prot  = (__u32)ctx->args[2];
    args.flags = (__u32)ctx->args[3];
    args.tgid  = tgid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(args.comm, sizeof(args.comm), task->comm);

    bpf_map_update_elem(&mmap_scratch, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct mmap_args *args = bpf_map_lookup_elem(&mmap_scratch, &pid);
    if (!args) return 0;
    bpf_map_delete_elem(&mmap_scratch, &pid);

    if (!should_trace(tgid)) return 0;

    long result = ctx->ret;
    if (result < 0) return 0; // failed mmap

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = (args->flags & 0x20) ? EVT_MMAP : EVT_MMAP_FILE;
    e->pid          = pid;
    e->tgid         = tgid;
    e->mmap_addr    = args->addr;
    e->mmap_len     = args->len;
    e->mmap_prot    = args->prot;
    e->mmap_flags   = args->flags;
    e->mmap_result  = (__u64)result;

    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), args->comm);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    fill_mm(e, mm);

    // Note: We can't easily find the exact VMA for the newly mapped region
    // without iterating the maple tree, which is complex in BPF.
    // The user-space program has the result address to work with.

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  3.  munmap() — VMA destroyed
// ─────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct mmap_args args = {};
    args.addr = (unsigned long)ctx->args[0];
    args.len  = (unsigned long)ctx->args[1];
    args.tgid = tgid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(args.comm, sizeof(args.comm), task->comm);

    bpf_map_update_elem(&mmap_scratch, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int trace_munmap_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct mmap_args *args = bpf_map_lookup_elem(&mmap_scratch, &pid);
    if (!args) return 0;
    bpf_map_delete_elem(&mmap_scratch, &pid);

    if (!should_trace(tgid)) return 0;

    long result = ctx->ret;
    if (result != 0) return 0; // failed munmap

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_MUNMAP;
    e->pid          = pid;
    e->tgid         = tgid;
    e->mmap_addr    = args->addr;
    e->mmap_len     = args->len;

    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), args->comm);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    fill_mm(e, mm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  4.  mprotect() — VMA permissions changed
// ─────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns  = bpf_ktime_get_ns();
    e->event_type    = EVT_MPROTECT;
    e->pid           = pid;
    e->tgid          = tgid;
    e->mprot_addr    = (unsigned long)ctx->args[0];
    e->mprot_len     = (unsigned long)ctx->args[1];
    e->mprot_prot    = (__u32)ctx->args[2];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), task->comm);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    fill_mm(e, mm);

    // Can't easily find specific VMA without maple tree iteration
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  5.  mremap() — VMA moved or resized
// ─────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_mremap")
int trace_mremap_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct mremap_args args = {};
    args.old_addr = (unsigned long)ctx->args[0];
    args.old_len  = (unsigned long)ctx->args[1];
    args.new_len  = (unsigned long)ctx->args[2];
    args.new_addr = (unsigned long)ctx->args[4];
    args.tgid     = tgid;

    bpf_map_update_elem(&mremap_scratch, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mremap")
int trace_mremap_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct mremap_args *args = bpf_map_lookup_elem(&mremap_scratch, &pid);
    if (!args) return 0;
    bpf_map_delete_elem(&mremap_scratch, &pid);

    if (!should_trace(tgid)) return 0;

    long result = ctx->ret;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_MREMAP;
    e->pid          = pid;
    e->tgid         = tgid;
    e->old_addr     = args->old_addr;
    e->old_len      = args->old_len;
    e->new_len      = args->new_len;
    e->new_addr     = (__u64)result;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), task->comm);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    fill_mm(e, mm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  6.  brk() — heap moved
// ─────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_brk")
int trace_brk_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);

    struct brk_args args = {};
    args.old_brk   = BPF_CORE_READ(mm, brk);
    args.requested = (unsigned long)ctx->args[0];
    args.tgid      = tgid;

    bpf_map_update_elem(&brk_scratch, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_brk")
int trace_brk_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct brk_args *args = bpf_map_lookup_elem(&brk_scratch, &pid);
    if (!args) return 0;
    bpf_map_delete_elem(&brk_scratch, &pid);

    if (!should_trace(tgid)) return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_BRK;
    e->pid          = pid;
    e->tgid         = tgid;
    e->brk_old      = args->old_brk;
    e->brk_new      = args->requested;
    e->brk_result   = (__u64)ctx->ret;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), task->comm);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    fill_mm(e, mm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  7.  Stack growth (expand_stack)
//      Fires when the stack VMA is grown downward
//      in response to a fault below the current stack bottom
// ─────────────────────────────────────────────
SEC("fexit/expand_stack")
int BPF_PROG(trace_stack_grow,
             struct vm_area_struct *vma,
             unsigned long address,
             int ret)
{
    if (ret != 0) return 0; // only log successful expansions

    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (!should_trace(tgid)) return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_STACK_GROW;
    e->pid          = pid;
    e->tgid         = tgid;
    e->fault_addr   = address;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), task->comm);

    fill_vma(e, vma);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    fill_mm(e, mm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  8.  Fork — child's mm cloned from parent
// ─────────────────────────────────────────────
SEC("tp_btf/sched_process_fork")
int BPF_PROG(trace_fork,
             struct task_struct *parent,
             struct task_struct *child)
{
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    __u32 par_tgid   = BPF_CORE_READ(parent, tgid);

    if (!should_trace(child_tgid) && !should_trace(par_tgid)) return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_FORK_MM;
    e->pid          = BPF_CORE_READ(child, pid);
    e->tgid         = child_tgid;
    bpf_core_read_str(e->comm, sizeof(e->comm), &child->comm);

    e->parent_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read_str(e->parent_comm, sizeof(e->parent_comm), &parent->comm);

    struct mm_struct *mm = BPF_CORE_READ(child, mm);
    fill_mm(e, mm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  9.  Exit — mm torn down
// ─────────────────────────────────────────────
SEC("tp_btf/sched_process_exit")
int BPF_PROG(trace_exit, struct task_struct *p)
{
    __u32 tgid = BPF_CORE_READ(p, tgid);
    if (!should_trace(tgid)) return 0;

    struct vm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_EXIT_MM;
    e->pid          = BPF_CORE_READ(p, pid);
    e->tgid         = tgid;
    bpf_core_read_str(e->comm, sizeof(e->comm), &p->comm);

    struct mm_struct *mm = BPF_CORE_READ(p, mm);
    fill_mm(e, mm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
