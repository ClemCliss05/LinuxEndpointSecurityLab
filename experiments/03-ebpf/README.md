# Lab 03 — eBPF System Call Monitoring

## Objective

Explore eBPF as a kernel-level monitoring technology.

The objective is to observe file-opening system calls, correlate syscall entry and exit events, and transfer structured events from kernel space to userspace.

This experiment focuses on monitoring, not access-control enforcement.

## Part 1 — bpftrace

### Entry monitoring

A bpftrace program was attached to:

`tracepoint:syscalls:sys_enter_openat`

It captured:

- Process ID
- Process name
- Requested pathname

### Entry/exit correlation

Two tracepoints were used:

- `sys_enter_openat`
- `sys_exit_openat`

A map indexed by thread ID (TID) stored the pathname at syscall entry.

At syscall exit, the program retrieved the corresponding pathname and inspected the return value.

This allowed successful and failed operations to be distinguished.

## Part 2 — Native eBPF with libbpf

### Architecture

The implementation contains three main elements:

- Kernel-side eBPF program: `src/ebpf/openat.bpf.c`
- Shared event definition: `src/ebpf/openat.h`
- Userspace loader and collector: `src/ebpf/openat.c`

### Kernel-side processing

At syscall entry:

1. Capture PID, TID, UID and GID.
2. Capture the process command name.
3. Read the requested pathname.
4. Store the event in the `inflight` hash map, indexed by TID.

At syscall exit:

1. Retrieve the stored event.
2. Copy the event before deleting its map entry.
3. Add the syscall return value.
4. Reserve space in the ring buffer.
5. Submit the completed event to userspace.

### Maps

| Map | Purpose |
|---|---|
| `inflight` | Correlates syscall entry and exit |
| `events` | Transfers completed events to userspace |
| `stats` | Stores per-CPU internal error counters |

The statistics map tracks pathname read failures, inflight map update/delete failures and ring buffer reservation failures.

### Userspace collector

The userspace application:

- Opens and loads the generated eBPF skeleton.
- Attaches the program to both syscall tracepoints.
- Polls the ring buffer.
- Displays successful and failed operations.
- Aggregates per-CPU statistics at shutdown.

## Build and Run

```bash
make clean
make ebpf
sudo ./build/openat
```

Stop the collector with Ctrl+C.

## Test Procedure

In another terminal:

```bash
cat /etc/passwd
cat /does-not-exist
sudo -u nobody cat experiments/01-linux-audit/sensitive/secret.txt
```

Expected observations:

- Successful open operations.
- Failed operations with `ENOENT`.
- Permission-denied operations with `EACCES`.
- Internal eBPF statistics printed at shutdown.

## Observations

The experiment successfully demonstrated:

- Kernel-level observation without modifying monitored applications.
- Correlation of syscall entry and exit events using TID.
- Transfer of structured events through a ring buffer.
- Userspace aggregation of per-CPU statistics.
- Visibility of both successful and failed openat operations.

## Limitations

This implementation is a learning prototype, not a production endpoint sensor.

- Only `openat` is monitored; other interfaces such as `openat2` are not covered.
- The pathname is the userspace-provided string, not a canonical filesystem path.
- The process command name (`comm`) is limited and is not a reliable executable identity.
- Monitoring syscall return values does not provide complete visibility into subsequent file reads or writes.
- Ring buffer capacity and map limits can cause event loss.
- The program observes events but does not enforce access-control policies.

## Conclusion

eBPF provides an efficient way to observe kernel events and transfer structured telemetry to userspace.

Unlike fanotify permission events, the current tracepoint implementation does not block or deny file access.

The next experiment will explore BPF LSM to implement security decisions directly within Linux kernel security hooks.

