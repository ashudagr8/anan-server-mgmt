#!/usr/bin/env bash
# start_anan_agent.sh — macOS-friendly startup script for anan_agent.py
# Usage:
#   ./start_anan_agent.sh [path/to/config.json]
# Environment overrides:
#   ANAN_AGENT_LOG_LEVEL (DEBUG|INFO|WARNING|ERROR)
#   ANAN_AGENT_CONSOLE_LEVEL (DEBUG|INFO|WARNING|ERROR)
#   ANAN_AGENT_CONFIG (alternative to passing config path)
#   ANAN_AGENT_MODEL_PROVIDER (ollama)

set -euo pipefail

# Move to repository root (script location)
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"
export PYTHONPATH="$REPO_DIR/src:${PYTHONPATH:-}"

# Activate virtualenv if it exists
if [ -f ".venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# Allow passing config path as first argument or via ANAN_AGENT_CONFIG
CONFIG_PATH=""
if [ $# -ge 1 ]; then
  CONFIG_PATH="$1"
elif [ -n "${ANAN_AGENT_CONFIG:-}" ]; then
  CONFIG_PATH="$ANAN_AGENT_CONFIG"
fi

# Export config path so the program can pick it up via env var
if [ -n "$CONFIG_PATH" ]; then
  export ANAN_AGENT_CONFIG="$CONFIG_PATH"
fi

# Optionally show effective settings
if [ -n "${ANAN_AGENT_LOG_LEVEL:-}" ]; then
  echo "ANAN_AGENT_LOG_LEVEL=${ANAN_AGENT_LOG_LEVEL}"
fi
if [ -n "${ANAN_AGENT_CONSOLE_LEVEL:-}" ]; then
  echo "ANAN_AGENT_CONSOLE_LEVEL=${ANAN_AGENT_CONSOLE_LEVEL}"
fi
if [ -n "$CONFIG_PATH" ]; then
  echo "Using config: $CONFIG_PATH"
fi

# Run the Python program
exec python3 -m anan_agent
