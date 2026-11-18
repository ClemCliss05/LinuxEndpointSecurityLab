
# Linux Endpoint Security Architecture

## 1. Overview

This project explores Linux endpoint security mechanisms through
independent experiments and progressively builds the foundations
of a userspace endpoint security agent.

The architecture separates kernel-level event collection and
security enforcement from userspace processing and policy logic.

## 2. Architecture Layers

### 2.1 Linux Kernel

The kernel manages processes, memory, filesystems and access
to system resources.

The laboratory explores three kernel interfaces:

- **fanotify**: filesystem event notification and permission-based
  access control.
- **eBPF**: programmable kernel-level event monitoring.
- **BPF LSM**: security policy enforcement through Linux Security
  Module hooks.

Linux Audit is also explored as a kernel auditing subsystem,
with userspace event collection through auditd.

### 2.2 Monitoring and Enforcement

The mechanisms have different responsibilities:

| Mechanism | Monitoring | Enforcement |
|---|---|---|
| Linux Audit | Yes | No |
| fanotify | Yes | Yes, with permission events |
| eBPF tracepoints | Yes | No, in the current implementation |
| BPF LSM | Can observe security hooks | Yes |

The current eBPF experiment monitors `openat` system calls
through entry and exit tracepoints. It does not modify their
outcome.

The fanotify experiment demonstrates how a userspace process
can respond to permission events with an allow or deny decision.

BPF LSM will be explored as a way to implement security
decisions directly through kernel security hooks.

### 2.3 Userspace Security Agent

The target userspace agent is responsible for:

- Collecting events from kernel interfaces
- Processing and correlating events
- Identifying processes and accessed resources
- Evaluating security policies where appropriate
- Logging security-related activity
- Communicating with external services

The current experiments are independent prototypes and are
not yet integrated into a single production-ready agent.

## 3. Current Project Components

| Component | Implementation | Status |
|---|---|---|
| Linux Audit | auditd and audit rules | Experiment completed |
| Filesystem monitoring | fanotify userspace monitor | Experiment completed |
| Syscall monitoring | eBPF tracepoints and libbpf | Experiment completed |
| Kernel policy enforcement | BPF LSM | Planned |
| Unified userspace agent | Modular integration | Planned |

## 4. Security Considerations

The implementation must progressively address:

- Least-privilege execution
- Process and file identity
- Race conditions and TOCTOU vulnerabilities
- Event loss and buffer capacity
- Concurrent event processing
- Performance overhead
- Fail-open versus fail-closed behavior
- Robust error handling
- Secure communication between components

## 5. Development Strategy

The project follows an incremental approach:

1. Understand existing Linux security mechanisms.
2. Implement and test independent monitoring components.
3. Explore kernel-level enforcement with BPF LSM.
4. Integrate monitoring and policy components.
5. Evaluate reliability, performance and security limitations.

The objective is to understand the design principles behind
reliable Linux endpoint security sensors, rather than to
immediately build a production-ready security product.
