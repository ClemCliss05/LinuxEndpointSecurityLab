
# Lab 02 — Linux fanotify

## Objective

Explore Linux fanotify as a userspace mechanism for monitoring and
controlling file access.

Unlike Linux Audit, which records system activity, fanotify can
request a userspace permission decision before a monitored file
operation is allowed to proceed.

## Environment

- OS: Debian 13
- Kernel: Linux 6.12
- Filesystem: ext4
- Language: C11
- API: Linux fanotify
- Compiler: GCC

## Implementation

Source: `src/monitor/fanotify_monitor.c`

The monitor:

1. Initializes a fanotify group using `fanotify_init()`.
2. Marks one specific file using `fanotify_mark()`.
3. Receives `FAN_OPEN_PERM` events.
4. Retrieves the requesting process's effective UID from `/proc/<PID>/status`.
5. Retrieves file metadata using `fstat()`.
6. Applies an access policy.
7. Sends `FAN_ALLOW` or `FAN_DENY` to the kernel.

## Access policy

The current policy allows access only when:

    process effective UID == file owner UID

If the process identity cannot be retrieved, access is denied.

This is a deliberately simple educational policy, not a
production-grade identity or authorization system.

## Build

From the repository root:

    make

## Run

    sudo ./build/fanotify_monitor \
      "$PWD/experiments/01-linux-audit/sensitive/secret.txt"

The monitor requires sufficient privileges for the
FAN_CLASS_CONTENT permission event group.

## Tests

With the monitor running, test as the file owner:

    cat experiments/01-linux-audit/sensitive/secret.txt

Expected: access allowed.

Test as root:

    sudo cat experiments/01-linux-audit/sensitive/secret.txt

Expected: access denied by the custom fanotify policy.

Observed results:

| Process | Effective UID | File owner UID | Decision |
|---|---:|---:|---|
| cliss | 1000 | 1000 | ALLOW |
| root | 0 | 1000 | DENY |

The file remained readable by its owner after the monitor stopped.

## Cleanup

Stop the monitor with Ctrl+C.

The program closes its fanotify group descriptor. The associated
mark is removed when the group is released.

Remove build artifacts with:

    make clean

## Limitations

- Only one specific file is monitored.
- Only `FAN_OPEN_PERM` is handled.
- The policy compares effective UID with file owner UID.
- Process identity is retrieved through `/proc/<PID>/status`.
- No persistent policy, configuration file or daemon is implemented.
- Event queue overflow is reported, but lost events cannot be recovered.
- This is a learning prototype, not a production endpoint sensor.

## Key concepts

- File descriptors
- Inodes and file metadata
- VFS and filesystem access
- fanotify permission events
- Userspace monitoring and kernel enforcement
- Process credentials and Linux UIDs
