
# Lab 04 — BPF LSM

## Objective

Explore Linux Security Module hooks using eBPF and implement
kernel-level file access enforcement.

## Environment

- Debian 13
- Linux 6.12
- Clang / LLVM
- libbpf
- bpftool
- BPF LSM enabled

## Architecture

The experiment uses two components:

- Kernel-side eBPF program attached to `lsm/file_open`.
- Userspace C agent responsible for loading the program and
  populating its BPF Hash Map.

The `protected_files` map stores file identities using:

- Device major number
- Device minor number
- Inode number

The userspace agent obtains these values using `stat()`,
`major()` and `minor()`.

The kernel program extracts the corresponding device numbers
from `struct file` and looks up the file identity in the map.

## Enforcement

When a file is present in the protected_files map, the BPF LSM
program returns -EACCES.

Otherwise, it returns 0 and does not deny the operation.

Existing denial decisions from previous LSM hooks are preserved.

## Build

    make lsm

## Run

    sudo ./build/file_open experiments/01-linux-audit/sensitive/secret.txt

## Test

Protected file:

    cat experiments/01-linux-audit/sensitive/secret.txt

Expected: Permission denied.

Unprotected file:

    cat /etc/hostname

Expected: successful read.

## Device number representation

The userspace stat() device representation and the kernel
internal dev_t representation are not directly interchangeable.

The experiment therefore extracts major/minor numbers in
userspace and in the BPF program before comparing identities.

## Limitations

- The current agent accepts one file path per execution.
- The map supports up to 1024 protected files.
- Rules are lost when the agent exits and its BPF map is destroyed.
- File identity uses device major/minor and inode.
- Inode reuse and filesystem lifecycle changes require consideration.
- The prototype does not yet implement policy persistence,
  dynamic rule management or production-grade logging.
- The file_open hook controls opening, not subsequent reads
  or writes through an already-open file descriptor.
- This is an educational prototype, not a production security agent.

## Key concepts

- BPF LSM hooks
- BPF Hash Maps
- Userspace/kernel communication
- BTF and CO-RE
- Device major/minor numbers
- Kernel access enforcement

