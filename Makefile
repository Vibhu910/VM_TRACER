#
# Makefile for vm_tracer
# Builds:
#   - eBPF object (vm_tracer.bpf.o)
#   - BPF skeleton header (vm_tracer.skel.h)
#   - User-space loader binary (vm_tracer)
#
# Usage (most common):
#   make            # build everything
#   sudo ./vm_tracer -c "ls"      # trace a fresh command
#   sudo ./vm_tracer -p <pid>     # trace an existing process
#   make run CMD="ls -la /"       # build + run in one step
#   make clean      # remove build artifacts
#

# ── Toolchain configuration (override on command line if needed) ─────────────

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86

CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra

BPFTool ?= bpftool

# ── Files ─────────────────────────────────────────────────────────────────────

BPF_OBJ   := vm_tracer.bpf.o
BPF_SKEL  := vm_tracer.skel.h
BIN       := vm_tracer
VMLINUX_H := vmlinux.h

# ── libbpf flags (try pkg-config first, fall back to common defaults) ────────

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null)

ifeq ($(LIBBPF_CFLAGS),)
  # Fallback: system-wide libbpf in standard locations
  LIBBPF_CFLAGS := -I/usr/include
  LIBBPF_LDLIBS := -lbpf -lelf -lz
endif

.PHONY: all help clean run

all: $(BIN)

help:
	@echo "vm_tracer build targets:"
	@echo "  make / make all          Build eBPF object, skeleton, and vm_tracer binary"
	@echo "  make run CMD=\"ls -la\"   Build (if needed) and run vm_tracer -c \"ls -la\""
	@echo "  make clean               Remove generated files"
	@echo ""
	@echo "Environment overrides:"
	@echo "  BPF_CLANG=<clang>        e.g., clang-14"
	@echo "  BPFTool=<bpftool>        path to bpftool binary"

# ── vmlinux.h: CO-RE BTF header (generated once per kernel) ──────────────────

$(VMLINUX_H):
	@echo "[*] Generating $@ from /sys/kernel/btf/vmlinux (requires root or read access)..."
	$(BPFTool) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── eBPF object ───────────────────────────────────────────────────────────────

$(BPF_OBJ): vm_tracer.bpf.c $(VMLINUX_H)
	@echo "[*] Compiling BPF object $@"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# ── BPF skeleton header (CO-RE) ───────────────────────────────────────────────

$(BPF_SKEL): $(BPF_OBJ)
	@echo "[*] Generating BPF skeleton $@"
	$(BPFTool) gen skeleton $< > $@

# ── User-space loader binary ──────────────────────────────────────────────────

$(BIN): vm_tracer.c $(BPF_SKEL)
	@echo "[*] Building user-space loader $@"
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) vm_tracer.c $(LIBBPF_LDLIBS) -o $@

# ── Convenience targets ───────────────────────────────────────────────────────

run: $(BIN)
	@if [ -z "$$CMD" ]; then \
	  echo "Usage: make run CMD='ls -la /'"; \
	  exit 1; \
	fi
	@echo "[*] Running: sudo ./$(BIN) -c \"$(CMD)\""
	sudo ./$(BIN) -c "$(CMD)"

clean:
	@echo "[*] Cleaning generated files"
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(BIN)

