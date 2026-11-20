
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

# BPF LSM files
LSM_TARGET := build/file_open
LSM_SOURCE := src/ebpf/file_open.c
LSM_BPF_SOURCE := src/ebpf/file_open.bpf.c
LSM_HEADER := src/ebpf/file_open.h

LSM_BPF_OBJECT := build/file_open.bpf.o
LSM_BPF_SKELETON := build/file_open.skel.h

.PHONY: all fanotify ebpf lsm clean

all: fanotify ebpf lsm

fanotify: $(FANOTIFY_TARGET)

ebpf: $(EBPF_TARGET)

lsm: $(LSM_TARGET)

## Fanotify program ##
$(FANOTIFY_TARGET): $(FANOTIFY_SOURCE)
	@mkdir -p build
	$(CC) $(CFLAGS) $< -o $@

## eBPF program ##
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

## BPF LSM program ##
$(LSM_BPF_OBJECT): $(LSM_BPF_SOURCE) $(LSM_HEADER) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(LSM_BPF_SOURCE) -o $@

$(LSM_BPF_SKELETON): $(LSM_BPF_OBJECT)
	$(BPFTOOL) gen skeleton $< > $@

$(LSM_TARGET): $(LSM_SOURCE) $(LSM_HEADER) $(LSM_BPF_SKELETON)
	$(CC) $(CFLAGS) -Wno-overlength-strings -Isrc/ebpf -Ibuild \
	    $(LIBBPF_CFLAGS) $(LSM_SOURCE) -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf build
