# Linux Endpoint Security Lab

A practical Linux security laboratory focused on endpoint
monitoring, access control and kernel-level security mechanisms.

## Objectives

Understand and experiment with Linux security mechanisms used
by endpoint protection solutions.

The project focuses on:

- Linux processes, permissions and system calls
- Linux Audit subsystem
- Filesystem monitoring with fanotify
- Kernel event monitoring with eBPF
- Linux Security Modules (LSM)
- Security policy enforcement
- Concurrency and TOCTOU vulnerabilities
- C/C++ system programming

## Project Architecture

The laboratory will progressively implement a small Linux
endpoint security agent.

Main components:

- Monitor: collects system and filesystem events
- Policy: evaluates access-control rules
- Logger: records security-related events
- Tests: validates monitoring and enforcement behavior

## Experiments

| Lab | Topic | Status |
|---|---|---|
| 01 | Linux Audit — file access monitoring | Completed |
| 02 | fanotify — file access monitoring and enforcement | Completed |
| 03 | eBPF — kernel event monitoring | Planned |
| 04 | BPF LSM — kernel security policies | Planned |

See each experiment's README for its implementation, test
procedure, observations and limitations.

## Development Environment

Primary environment:
- Debian Linux
- C / C++
- GCC / G++
- Linux kernel interfaces
- Git

## Project Status

Initial repository setup.
