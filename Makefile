
CC := gcc
CLANG := clang
BPFTOOL := /usr/sbin/bpftool

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -g -O2

# Existing fanotify monitor
FANOTIFY_TARGET := build/fanotify_monitor
FANOTIFY_SOURCE := src/monitor/fanotify_monitor.c

# eBPF files
EBPF_TARGET := build/openat
EBPF_SOURCE := src/ebpf/openat.c
BPF_SOURCE := src/ebpf/openat.bpf.c
EBPF_HEADER := src/ebpf/openat.h

VMLINUX := build/vmlinux.h
BPF_OBJECT := build/openat.bpf.o
BPF_SKELETON := build/openat.skel.h

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
              -Ibuild -Isrc/ebpf

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

.PHONY: all fanotify ebpf clean

all: fanotify ebpf

fanotify: $(FANOTIFY_TARGET)

ebpf: $(EBPF_TARGET)

# Fanotify
$(FANOTIFY_TARGET): $(FANOTIFY_SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) $< -o $@

# Generate kernel type definitions from BTF
$(VMLINUX):
	@mkdir -p build
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile the eBPF program
$(BPF_OBJECT): $(BPF_SOURCE) $(EBPF_HEADER) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SOURCE) -o $@

# Generate libbpf skeleton
$(BPF_SKELETON): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace loader
$(EBPF_TARGET): $(EBPF_SOURCE) $(EBPF_HEADER) $(BPF_SKELETON)
	$(CC) $(CFLAGS) -Wno-overlength-strings -Isrc/ebpf -Ibuild \
	    $(LIBBPF_CFLAGS) $(EBPF_SOURCE) -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf build
