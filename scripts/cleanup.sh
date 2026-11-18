
#!/usr/bin/env bash

set -euo pipefail

echo "========== Linux Endpoint Security Lab Cleanup =========="

echo "[INFO] Checking for lab processes..."

# Future lab agents will be registered here.
# Do not terminate processes based only on generic names.

echo "[INFO] No lab agents registered yet."
echo "[INFO] auditd will remain running."
echo "[INFO] Cleanup completed."
