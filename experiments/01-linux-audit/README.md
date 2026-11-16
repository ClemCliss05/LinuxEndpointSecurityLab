# Experiment 01 — Linux Audit

## Objective

Monitor access to a sensitive file using the Linux Audit subsystem.

Understand how Linux records security events, including process identity, file information and system calls.

## Environment

- OS: Debian 13
- Kernel: Linux 6.12.116
- Audit daemon: auditd 4.0.2

## 1. Setup

Create a test file:

```bash
mkdir -p sensitive
echo "CONFIDENTIAL DATA" > sensitive/secret.txt
chmod 600 sensitive/secret.txt
```

Start the audit daemon:

```bash
sudo systemctl enable --now auditd
```

## 2. Configure monitoring

```bash
sudo auditctl -w "$(realpath sensitive/secret.txt)" \
    -p r -k endpoint_sensitive_file
```

This rule monitors read access to the selected file.

Check active rules:

```bash
sudo auditctl -l
```

## 3. Generate and inspect an event

```bash
cat sensitive/secret.txt
sudo ausearch -k endpoint_sensitive_file -i
```

## 4. Observations

The audit event contains several useful records:

- `SYSCALL`: system call information, process identity and operation result.
- `PATH`: file path, inode and ownership information.
- `CWD`: current working directory.
- `PROCTITLE`: command-line information associated with the process.

Important fields:

| Field | Meaning |
|---|---|
| `syscall=openat` | File opened through the openat system call |
| `success=yes` | Operation succeeded |
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `auid` | Original login identity |
| `uid` / `euid` | Real and effective user IDs |
| `comm` | Process command name |
| `exe` | Executable path |
| `inode` | Filesystem object identifier |
| `key` | Audit rule identifier |

### Successful access

The file owner (`cliss`) successfully opened the file.

- `success=yes`
- `exit=3`: file descriptor returned by openat.
- `euid=cliss`

### Denied access

The `nobody` user attempted to read the same file.

- `success=no`
- `exit=EACCES`: permission denied.
- `euid=nobody`
- `auid=cliss`: original login identity remained unchanged.

### Security observation

The Linux kernel enforced the file permissions and denied the unauthorized access.

Linux Audit recorded both the successful and denied attempts.

Audit provides visibility, while standard Linux permissions performed the access enforcement.

## 5. Main conclusion

Linux Audit provides visibility into security-relevant operations.

It records information about file access, processes and system calls, but it does not directly prevent the operation.

This is a monitoring mechanism, not an inline access-control mechanism.

## 6. Limitations and next steps

- The legacy `-w` watch syntax produces a performance warning.
- Audit events must be interpreted and correlated.
- Recording an event does not mean the operation was blocked.
- Next: compare successful and denied file access attempts.
