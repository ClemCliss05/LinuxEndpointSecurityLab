# Useful Commands

A concise reference of commands used in the Linux Endpoint Security Lab.

## Files and Permissions

| Command | Purpose |
|---|---|
| `chmod 600 FILE` | Give read/write permissions to the owner only |
| `ls -l FILE` | Display file permissions and ownership |
| `realpath FILE` | Resolve the absolute path of a file |
| `cat FILE` | Read file contents |

## Lab 01 — Linux Audit

| Command | Purpose |
|---|---|
| `systemctl status auditd` | Check the audit daemon status |
| `systemctl enable --now auditd` | Enable and start auditd |
| `auditctl -s` | Display kernel audit status and lost events |
| `auditctl -l` | List active audit rules |
| `auditctl -w PATH -p r -k KEY` | Monitor read access to a file |
| `ausearch -k KEY -i` | Search audit events by key |
| `ausearch -k KEY -ts recent -i` | Display recent events matching a key |

## Lab 02 — fanotify

### Build

```bash
make
make clean
```

### Run the monitor

```bash
sudo ./build/fanotify_monitor \
  "$PWD/experiments/01-linux-audit/sensitive/secret.txt"
```

### Test access policy

```bash
# Run as the file owner: expected ALLOW
cat experiments/01-linux-audit/sensitive/secret.txt

# Run as root: expected DENY with the current policy
sudo cat experiments/01-linux-audit/sensitive/secret.txt
```

### Inspect file metadata

```bash
stat experiments/01-linux-audit/sensitive/secret.txt
ls -i experiments/01-linux-audit/sensitive/secret.txt
```

### Inspect process file descriptors

```bash
# Current shell
ls -l /proc/$$/fd

# Another process (replace PID)
ls -l /proc/<PID>/fd
```

### Inspect fanotify limits

```bash
cat /proc/sys/fs/fanotify/max_queued_events
cat /proc/sys/fs/fanotify/max_user_marks
```
