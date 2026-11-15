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

## Learning Roadmap

### 01 - Linux Audit
Observe and analyse security-relevant system events.

### 02 - fanotify
Monitor filesystem access and experiment with permission events.

### 03 - eBPF
Observe kernel events and communicate with userspace.

### 04 - BPF LSM
Explore kernel-level security policy enforcement.

## Development Environment

Primary environment:
- Debian Linux
- C / C++
- GCC / G++
- Linux kernel interfaces
- Git

## Project Status

Initial repository setup.
