# Linux Endpoint Security Architecture

## 1. General Architecture

The security agent is divided into three main layers.

### Kernel

Responsible for operating system resources and kernel-level
security mechanisms.

Examples:
- Processes
- Filesystems
- Memory management
- Linux Security Modules
- eBPF hooks

### Monitoring Layer

Collects security-relevant events.

Possible technologies:
- Linux Audit
- fanotify
- eBPF

### Userspace Security Agent

Responsible for:
- Event processing
- Process identification
- Security policy evaluation
- Logging
- Communication with external services

## 2. Monitoring vs Enforcement

Monitoring:
Observe and record an operation without changing its outcome.

Enforcement:
Allow or deny an operation before it is completed.

These are different security responsibilities.

## 3. Security Considerations

- Least privilege
- Race conditions
- TOCTOU vulnerabilities
- Reliable event delivery
- Performance overhead
- Fail-open vs fail-closed behavior
- Process and file identity
- Secure communication between components
