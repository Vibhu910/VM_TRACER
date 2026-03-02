// vm_tracer.c
// User-space loader: loads BPF object, optionally filters by PID or
// by watching a command from launch to exit, pretty-prints every event.
//
// Usage:
//   sudo ./vm_tracer -p <pid>           # trace an already-running process
//   sudo ./vm_tracer -c "ls -la"        # launch a command and trace it
//   sudo ./vm_tracer                    # trace everything (noisy)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vm_tracer.skel.h"

// ── Must mirror kernel-side struct exactly ───────────────────────────────────
#define TASK_COMM_LEN 16
#define PATH_LEN      64

#define EVT_FAULT_ANON  1
#define EVT_FAULT_FILE  2
#define EVT_FAULT_COW   3
#define EVT_FAULT_MINOR 4
#define EVT_MMAP        5
#define EVT_MUNMAP      6
#define EVT_MPROTECT    7
#define EVT_MREMAP      8
#define EVT_BRK         9
#define EVT_STACK_GROW  10
#define EVT_FORK_MM     11
#define EVT_EXIT_MM     12
#define EVT_MMAP_FILE   13

// PROT_* flags for printing
#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

// MAP_* flags
#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED     0x10

struct vm_event {
    unsigned long long timestamp_ns;
    unsigned int       event_type;
    unsigned int       pid;
    unsigned int       tgid;
    char               comm[TASK_COMM_LEN];

    unsigned long long fault_addr;
    unsigned long long fault_flags;
    unsigned int       fault_is_write;
    unsigned int       fault_is_exec;
    unsigned int       fault_is_user;

    unsigned long long vma_start;
    unsigned long long vma_end;
    unsigned long long vma_flags;
    unsigned long long vma_pgoff;
    unsigned long long vma_size;

    char               file_path[PATH_LEN];
    unsigned long long file_inode;

    unsigned long long mmap_addr;
    unsigned long long mmap_len;
    unsigned int       mmap_prot;
    unsigned int       mmap_flags;
    unsigned long long mmap_result;

    unsigned long long old_addr;
    unsigned long long old_len;
    unsigned long long new_len;
    unsigned long long new_addr;

    unsigned long long brk_old;
    unsigned long long brk_new;
    unsigned long long brk_result;

    unsigned long long mprot_addr;
    unsigned long long mprot_len;
    unsigned int       mprot_prot;

    unsigned long long mm_start_code;
    unsigned long long mm_end_code;
    unsigned long long mm_start_data;
    unsigned long long mm_end_data;
    unsigned long long mm_start_heap;
    unsigned long long mm_brk;
    unsigned long long mm_start_stack;
    unsigned long long mm_mmap_base;
    unsigned int       mm_map_count;
    unsigned long long mm_total_vm;
    unsigned long long mm_locked_vm;
    unsigned long long mm_data_vm;
    unsigned long long mm_exec_vm;

    unsigned int       parent_pid;
    char               parent_comm[TASK_COMM_LEN];
};

// ── formatters ───────────────────────────────────────────────────────────────

static void fmt_prot(char *buf, size_t sz, unsigned int prot)
{
    snprintf(buf, sz, "%s%s%s",
             (prot & PROT_READ)  ? "r" : "-",
             (prot & PROT_WRITE) ? "w" : "-",
             (prot & PROT_EXEC)  ? "x" : "-");
}

static void fmt_vma_flags(char *buf, size_t sz, unsigned long long f)
{
    snprintf(buf, sz, "%s%s%s%s%s",
             (f & 0x0001) ? "r" : "-",
             (f & 0x0002) ? "w" : "-",
             (f & 0x0004) ? "x" : "-",
             (f & 0x0008) ? "s" : "p",
             (f & 0x0100) ? " GROWSDOWN(stack)" : "");
}

static void fmt_map_flags(char *buf, size_t sz, unsigned int f)
{
    snprintf(buf, sz, "%s%s%s%s",
             (f & MAP_SHARED)    ? "SHARED "    : "",
             (f & MAP_PRIVATE)   ? "PRIVATE "   : "",
             (f & MAP_ANONYMOUS) ? "ANONYMOUS " : "FILE ",
             (f & MAP_FIXED)     ? "FIXED "     : "");
}

static void print_mm(const struct vm_event *e)
{
    printf("│  [mm layout]\n");
    printf("│    code  segment: 0x%016llx – 0x%016llx  (%llu KB)\n",
           e->mm_start_code, e->mm_end_code,
           (e->mm_end_code - e->mm_start_code) / 1024);
    printf("│    data  segment: 0x%016llx – 0x%016llx  (%llu KB)\n",
           e->mm_start_data, e->mm_end_data,
           (e->mm_end_data - e->mm_start_data) / 1024);
    printf("│    heap          : 0x%016llx – 0x%016llx  (%llu KB)\n",
           e->mm_start_heap, e->mm_brk,
           (e->mm_brk > e->mm_start_heap ?
            (e->mm_brk - e->mm_start_heap) / 1024 : 0));
    printf("│    stack base    : 0x%016llx\n", e->mm_start_stack);
    printf("│    mmap base     : 0x%016llx\n", e->mm_mmap_base);
    printf("│    VMA count     : %u\n",        e->mm_map_count);
    printf("│    total_vm      : %llu pages  (%llu KB)\n",
           e->mm_total_vm, e->mm_total_vm * 4);
    printf("│    exec_vm       : %llu pages\n", e->mm_exec_vm);
    printf("│    data_vm       : %llu pages\n", e->mm_data_vm);
    printf("│    locked_vm     : %llu pages\n", e->mm_locked_vm);
}

static void print_vma(const struct vm_event *e)
{
    if (!e->vma_start && !e->vma_end) return;
    char flags[32];
    fmt_vma_flags(flags, sizeof(flags), e->vma_flags);
    printf("│  [VMA]\n");
    printf("│    range : 0x%016llx – 0x%016llx  (%llu KB)\n",
           e->vma_start, e->vma_end, e->vma_size / 1024);
    printf("│    flags : %s\n", flags);
    printf("│    pgoff : %llu\n", e->vma_pgoff);
    if (e->file_path[0])
        printf("│    file  : %s  (inode %llu)\n",
               e->file_path, e->file_inode);
    else
        printf("│    file  : [anonymous]\n");
}

// ── main event handler ───────────────────────────────────────────────────────

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct vm_event *e = data;

    unsigned long long ts_s  = e->timestamp_ns / 1000000000ULL;
    unsigned long long ts_us = (e->timestamp_ns % 1000000000ULL) / 1000;

    char prot_str[8];
    char flags_str[32];

    printf("\n");

    switch (e->event_type) {

    // ── Page faults ──────────────────────────────────────────────────────────
    case EVT_FAULT_ANON:
    case EVT_FAULT_FILE:
    case EVT_FAULT_COW:
    case EVT_FAULT_MINOR: {
        const char *ftype =
            e->event_type == EVT_FAULT_COW   ? "PAGE_FAULT_COW  " :
            e->event_type == EVT_FAULT_FILE  ? "PAGE_FAULT_FILE " :
            e->event_type == EVT_FAULT_MINOR ? "PAGE_FAULT_MINOR" :
                                               "PAGE_FAULT_ANON ";
        printf("┌─ %s  pid=%-6u (%s)  cpu time=%llu.%06llus\n",
               ftype, e->pid, e->comm, ts_s, ts_us);
        printf("│  fault addr : 0x%016llx\n", e->fault_addr);
        printf("│  type       : %s%s%s\n",
               e->fault_is_write ? "WRITE " : "READ ",
               e->fault_is_exec  ? "EXEC "  : "",
               e->fault_is_user  ? "(user space)" : "(kernel)");
        print_vma(e);
        break;
    }

    // ── mmap ─────────────────────────────────────────────────────────────────
    case EVT_MMAP:
    case EVT_MMAP_FILE:
        fmt_prot(prot_str, sizeof(prot_str), e->mmap_prot);
        fmt_map_flags(flags_str, sizeof(flags_str), e->mmap_flags);
        printf("┌─ MMAP%s       pid=%-6u (%s)  time=%llu.%06llus\n",
               e->event_type == EVT_MMAP_FILE ? "_FILE" : "     ",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  requested  : addr=0x%016llx  len=%llu KB\n",
               e->mmap_addr, e->mmap_len / 1024);
        printf("│  prot       : %s   flags: %s\n", prot_str, flags_str);
        printf("│  result     : 0x%016llx  (mapped here)\n", e->mmap_result);
        print_vma(e);
        print_mm(e);
        break;

    // ── munmap ───────────────────────────────────────────────────────────────
    case EVT_MUNMAP:
        printf("┌─ MUNMAP       pid=%-6u (%s)  time=%llu.%06llus\n",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  addr       : 0x%016llx  len=%llu KB\n",
               e->mmap_addr, e->mmap_len / 1024);
        print_vma(e);
        print_mm(e);
        break;

    // ── mprotect ─────────────────────────────────────────────────────────────
    case EVT_MPROTECT:
        fmt_prot(prot_str, sizeof(prot_str), e->mprot_prot);
        printf("┌─ MPROTECT     pid=%-6u (%s)  time=%llu.%06llus\n",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  addr       : 0x%016llx  len=%llu KB\n",
               e->mprot_addr, e->mprot_len / 1024);
        printf("│  new prot   : %s\n", prot_str);
        print_vma(e);
        print_mm(e);
        break;

    // ── mremap ───────────────────────────────────────────────────────────────
    case EVT_MREMAP:
        printf("┌─ MREMAP       pid=%-6u (%s)  time=%llu.%06llus\n",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  old        : 0x%016llx  len=%llu KB\n",
               e->old_addr, e->old_len / 1024);
        printf("│  new        : 0x%016llx  len=%llu KB\n",
               e->new_addr, e->new_len / 1024);
        if (e->old_addr != e->new_addr)
            printf("│  MOVED      : yes\n");
        else
            printf("│  resized in place\n");
        print_mm(e);
        break;

    // ── brk ──────────────────────────────────────────────────────────────────
    case EVT_BRK: {
        long long delta = (long long)e->brk_result - (long long)e->brk_old;
        printf("┌─ BRK (heap)   pid=%-6u (%s)  time=%llu.%06llus\n",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  heap before : 0x%016llx\n", e->brk_old);
        printf("│  requested   : 0x%016llx\n", e->brk_new);
        printf("│  heap after  : 0x%016llx\n", e->brk_result);
        printf("│  delta       : %+lld bytes (%s)\n",
               delta, delta > 0 ? "GROW" : delta < 0 ? "SHRINK" : "no change");
        print_mm(e);
        break;
    }

    // ── stack growth ─────────────────────────────────────────────────────────
    case EVT_STACK_GROW:
        printf("┌─ STACK_GROW   pid=%-6u (%s)  time=%llu.%06llus\n",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  fault addr  : 0x%016llx  (triggered expansion)\n",
               e->fault_addr);
        printf("│  new stack   : 0x%016llx – 0x%016llx  (%llu KB)\n",
               e->vma_start, e->vma_end, e->vma_size / 1024);
        printf("│  stack base  : 0x%016llx\n", e->mm_start_stack);
        print_mm(e);
        break;

    // ── fork ─────────────────────────────────────────────────────────────────
    case EVT_FORK_MM:
        printf("┌─ FORK         parent=%-6u (%s) → child=%-6u (%s)  time=%llu.%06llus\n",
               e->parent_pid, e->parent_comm, e->pid, e->comm, ts_s, ts_us);
        printf("│  child mm cloned from parent (copy-on-write)\n");
        print_mm(e);
        break;

    // ── exit ─────────────────────────────────────────────────────────────────
    case EVT_EXIT_MM:
        printf("┌─ EXIT         pid=%-6u (%s)  time=%llu.%06llus\n",
               e->pid, e->comm, ts_s, ts_us);
        printf("│  Final mm state at exit:\n");
        print_mm(e);
        break;

    default:
        printf("┌─ UNKNOWN EVENT %u\n", e->event_type);
        break;
    }

    printf("└──────────────────────────────────────────────────────────────\n");
    fflush(stdout);
    return 0;
}

// ── signal / globals ─────────────────────────────────────────────────────────
static volatile int stop = 0;
static void sig_handler(int sig) { stop = 1; }

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s -p <pid>         # trace existing process\n"
        "  %s -c <command>     # launch and trace command from start\n"
        "  %s                  # trace all processes (very noisy)\n"
        "\nExamples:\n"
        "  sudo %s -c 'ls -la /'\n"
        "  sudo %s -c 'cat /etc/passwd'\n"
        "  sudo %s -p 1234\n",
        prog, prog, prog, prog, prog, prog);
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    int    opt;
    pid_t  target_pid_val = 0;
    char  *cmd            = NULL;
    pid_t  child          = 0;

    while ((opt = getopt(argc, argv, "p:c:h")) != -1) {
        switch (opt) {
        case 'p': target_pid_val = (pid_t)atoi(optarg); break;
        case 'c': cmd = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    libbpf_set_print(NULL);

    struct vm_tracer_bpf *skel = vm_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    int err = vm_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF: %d\n", err);
        goto cleanup;
    }

    err = vm_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF: %d\n", err);
        goto cleanup;
    }

    // ── If launching a command, fork now and set the target PID ──────────────
    if (cmd) {
        // We need to fork, pause the child until BPF is ready, then exec
        child = fork();
        if (child < 0) {
            perror("fork");
            goto cleanup;
        }
        if (child == 0) {
            // Child: wait for parent to set up BPF filter, then exec
            // Use raise(SIGSTOP) so parent can resume us
            raise(SIGSTOP);
            // exec the command via shell
            execl("/bin/sh", "sh", "-c", cmd, NULL);
            perror("execl");
            _exit(1);
        }
        // Parent: set target_pid to child
        target_pid_val = child;
        printf("[*] Launched '%s' as pid %d — tracing...\n\n", cmd, child);
    }

    // ── Write target PID into BPF map ────────────────────────────────────────
    if (target_pid_val > 0) {
        int map_fd = bpf_map__fd(skel->maps.target_pid);
        __u32 key = 0;
        __u32 val = (__u32)target_pid_val;
        bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
        if (!cmd)
            printf("[*] Filtering to pid %d\n\n", target_pid_val);
    } else {
        printf("[*] No PID filter — tracing ALL processes (very noisy)\n\n");
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGCHLD, sig_handler); // stop when child exits

    // ── If we forked a child, resume it now ──────────────────────────────────
    if (child > 0) {
        // Wait for child to stop itself
        int wstatus;
        waitpid(child, &wstatus, WUNTRACED);
        // Now resume it — BPF is already attached
        kill(child, SIGCONT);
    }

    printf("=== VM Tracer ===\n");
    printf("Tracing: page faults, mmap/munmap/mprotect/mremap, brk, stack\n");
    printf("Press Ctrl-C to stop\n\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer error: %d\n", err);
            break;
        }
        // If we launched a child, check if it's done
        if (child > 0) {
            int wstatus;
            pid_t r = waitpid(child, &wstatus, WNOHANG);
            if (r == child && (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))) {
                // Drain remaining events
                ring_buffer__poll(rb, 200);
                break;
            }
        }
    }

    printf("\n=== VM Tracer stopped ===\n");
    ring_buffer__free(rb);

cleanup:
    vm_tracer_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
