
# Linux Endpoint Security Lab

A practical Linux security laboratory focused on endpoint monitoring, access control and kernel-level security mechanisms.

## Objectives

Understand and experiment with Linux security mechanisms used by endpoint protection solutions.

The project explores:

- Linux processes, permissions and system calls
- Linux Audit subsystem
- Filesystem monitoring and access control with fanotify
- Kernel event monitoring with eBPF
- BPF-based Linux Security Modules (BPF LSM)
- Security policy enforcement
- Concurrency, race conditions and TOCTOU vulnerabilities
- C and C++ systems programming

## Experiments

| Lab | Topic | Status |
|---|---|---|
| 01 | Linux Audit — file access monitoring |
| 02 | fanotify — monitoring and access control |
| 03 | eBPF — syscall monitoring with bpftrace and libbpf |
| 04 | BPF LSM — kernel security policies |

Each experiment includes its implementation, test procedure, observations and limitations.

## Project Architecture

The project progressively develops a small Linux endpoint security agent.

Main components:

- Monitor: collects system and filesystem events
- eBPF: provides kernel-level event monitoring
- Policy: evaluates access-control rules
- Logger: records security-related events
- Tests: validates monitoring and enforcement behavior

## Development Environment

The project is developed and tested on Debian Linux.

Main technologies:

- C and C++
- Linux system calls and kernel interfaces
- Linux Audit and fanotify
- eBPF, bpftrace and libbpf
- Clang/LLVM, GCC and bpftool
- Make and Git

## Build

Build all components:

```bash
make clean
make all
```

Build individual components:

```bash
make fanotify
make ebpf
```

Generated files are stored in `build/` and are not tracked by Git.

## Safety

Some experiments require root privileges and can actively deny file access.

Run them only in a controlled test environment, using dedicated test files.
