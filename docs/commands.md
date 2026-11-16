# Useful Commands

A concise reference of commands used in the Linux Endpoint Security Lab.

## 1. Linux Audit

| Command | Purpose |
|---|---|
| `systemctl status auditd` | Check the audit daemon status |
| `systemctl enable --now auditd` | Enable and start auditd |
| `auditctl -s` | Display kernel audit status and lost events |
| `auditctl -l` | List active audit rules |
| `auditctl -w PATH -p r -k KEY` | Monitor read access to a file |
| `ausearch -k KEY -i` | Search audit events by key |
| `ausearch -k KEY -ts recent -i` | Display recent events matching a key |

## 2. Files and Permissions

| Command | Purpose |
|---|---|
| `chmod 600 FILE` | Give read/write permissions to the owner only |
| `ls -l FILE` | Display file permissions and ownership |
| `realpath FILE` | Resolve the absolute path of a file |
| `cat FILE` | Read file contents |

## 3. Git

| Command | Purpose |
|---|---|
| `git status` | Check working tree status |
| `git diff` | Inspect unstaged changes |
| `git add FILE` | Stage changes |
| `git commit -m "MESSAGE"` | Create a commit |
| `git log --oneline` | Display commit history |
