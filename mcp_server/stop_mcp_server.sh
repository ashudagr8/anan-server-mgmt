#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PATTERN='uvicorn.*anan_mcp_server\.server:app|python.*-m uvicorn.*anan_mcp_server\.server:app|python.*anan_mcp_server.*server\.py'

MATCHES="$(pgrep -af "$PATTERN" || true)"

if [[ -z "$MATCHES" ]]; then
    echo "No running MCP server process found."
    exit 0
fi

echo "$MATCHES"

PIDS="$(pgrep -af "$PATTERN" | awk '{print $1}' | sort -u)"
if [[ -z "$PIDS" ]]; then
    echo "No PIDs found for the MCP server process."
    exit 0
fi

for pid in $PIDS; do
    echo "Stopping MCP server PID $pid"
    kill "$pid" || true
done

for _ in $(seq 1 20); do
    if ! pgrep -af "$PATTERN" >/dev/null 2>&1; then
        echo "MCP server stopped successfully."
        exit 0
    fi
    sleep 0.5
done

echo "MCP server did not exit cleanly; forcing shutdown..." >&2
for pid in $PIDS; do
    kill -9 "$pid" || true
done

echo "MCP server force-stopped."
