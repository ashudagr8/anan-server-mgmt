#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PATTERN='src/anan_client.py|python.*anan_client.py|uvicorn.*anan_client'

if [[ "${EUID}" -ne 0 ]]; then
    echo "This stop script must be run with sudo because the client is typically started as root."
    echo "Example: sudo ./stop_anan_client.sh"
    exit 1
fi

MATCHES="$(pgrep -af "$PATTERN" || true)"

if [[ -z "$MATCHES" ]]; then
    echo "No running anan client process found."
    exit 0
fi

echo "$MATCHES"

PIDS="$(pgrep -af "$PATTERN" | awk '{print $1}' | sort -u)"
if [[ -z "$PIDS" ]]; then
    echo "No PIDs found for the client process."
    exit 0
fi

for pid in $PIDS; do
    echo "Stopping client process PID $pid"
    kill "$pid" || true
done

for _ in $(seq 1 20); do
    if ! pgrep -af "$PATTERN" >/dev/null 2>&1; then
        echo "Client stopped successfully."
        exit 0
    fi
    sleep 0.5
done

echo "Client did not exit cleanly; forcing shutdown..." >&2
for pid in $PIDS; do
    kill -9 "$pid" || true
done

echo "Client process force-stopped."
