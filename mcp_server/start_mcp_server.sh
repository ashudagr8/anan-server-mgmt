#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_RESPONSE_BODY="${REQUEST_LOG_INCLUDE_RESPONSE_BODY:-false}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --log-response-body)
      LOG_RESPONSE_BODY=true
      shift
      ;;
    --no-log-response-body)
      LOG_RESPONSE_BODY=false
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./start_mcp_server.sh [options]

Options:
  --log-response-body      Include HTTP response body previews in request logs.
  --no-log-response-body   Disable HTTP response body previews in request logs.
  -h, --help               Show this help message.
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Use --help to see available options." >&2
      exit 1
      ;;
  esac
done

export MCP_SERVER_CONFIG="${MCP_SERVER_CONFIG:-${SCRIPT_DIR}/config/mcp_server_config.json}"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-8000}"
export REQUEST_LOG_FILE="${REQUEST_LOG_FILE:-${SCRIPT_DIR}/logs/request.log}"
export REQUEST_LOG_INCLUDE_RESPONSE_BODY="${LOG_RESPONSE_BODY}"
export UFW_AGENT_URL="${UFW_AGENT_URL:-https://127.0.0.1:8443}"
export ANAN_CLIENT_API_KEY="${ANAN_CLIENT_API_KEY:-abc}"
export UFW_CLIENT_SSL_VERIFY="${UFW_CLIENT_SSL_VERIFY:-false}"
export HTTPS_ENABLED="${HTTPS_ENABLED:-true}"
export SSL_DIR="${SSL_DIR:-${SCRIPT_DIR}/certs}"
export SSL_CERTFILE="${SSL_CERTFILE:-${SSL_DIR}/fullchain.pem}"
export SSL_KEYFILE="${SSL_KEYFILE:-${SSL_DIR}/privkey.pem}"
export ANAN_CLIENTS_FILE="${ANAN_CLIENTS_FILE:-${SCRIPT_DIR}/config/anan_clients.json}"
if [[ -z "${OAUTH_SERVERS_FILE:-}" && -f "${SCRIPT_DIR}/config/oauth_servers.json" ]]; then
  export OAUTH_SERVERS_FILE="${SCRIPT_DIR}/config/oauth_servers.json"
fi
export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

PYTHON_BIN="${PYTHON_BIN:-${SCRIPT_DIR}/.venv/bin/python}"
if [ ! -x "$PYTHON_BIN" ]; then
  echo "Python virtual environment not found at $PYTHON_BIN" >&2
  exit 1
fi

AUTH_TYPE="${AUTH_MODE:-}"
if [[ -z "$AUTH_TYPE" ]]; then
  AUTH_TYPE="$($PYTHON_BIN - <<'PY'
import json
import os

def extract_mode(payload):
    if isinstance(payload, dict):
        mode = payload.get("auth_mode", payload.get("AUTH_MODE"))
        if isinstance(mode, str):
            normalized = mode.strip().lower()
            if normalized in {"no_auth", "oauth"}:
                return normalized
    return ""

mode = ""
file_path = (os.getenv("OAUTH_SERVERS_FILE") or "").strip()
if file_path:
    try:
        with open(file_path, encoding="utf-8") as handle:
            mode = extract_mode(json.load(handle))
    except Exception:
        mode = ""

if not mode:
    raw_payload = (os.getenv("OAUTH_SERVERS") or "").strip()
    if raw_payload:
        try:
            mode = extract_mode(json.loads(raw_payload))
        except Exception:
            mode = ""

print(mode or "no_auth")
PY
)"
fi
AUTH_TYPE="$(printf '%s' "$AUTH_TYPE" | tr '[:upper:]' '[:lower:]')"
if [[ "$AUTH_TYPE" != "oauth" && "$AUTH_TYPE" != "no_auth" ]]; then
  AUTH_TYPE="no_auth"
fi

echo "[startup] auth_type=${AUTH_TYPE}"

if [ "${HTTPS_ENABLED:-true}" = "true" ]; then
    echo "[startup] ensuring HTTPS certificate files exist for ${SSL_CERTFILE} and ${SSL_KEYFILE}"
    exports="$($PYTHON_BIN - <<'PY' | awk '/^export /{print}'
import os
import shlex
from anan_mcp_server.server import ensure_https_certificates
import sys

try:
    certfile, keyfile = ensure_https_certificates()
    if os.path.exists(certfile) and os.path.exists(keyfile):
        print(f"[startup] using HTTPS certificate: {certfile}", file=sys.stderr)
        print(f"[startup] using HTTPS key: {keyfile}", file=sys.stderr)
    else:
        print(f"[startup] generated HTTPS certificate: {certfile}", file=sys.stderr)
        print(f"[startup] generated HTTPS key: {keyfile}", file=sys.stderr)
except Exception as exc:  # pragma: no cover - fail loudly in startup path
    raise SystemExit(str(exc))

print(f"export SSL_CERTFILE={shlex.quote(certfile)}")
print(f"export SSL_KEYFILE={shlex.quote(keyfile)}")
PY
)"
    eval "$exports"
    exec "$PYTHON_BIN" -m uvicorn anan_mcp_server.server:app --host "$HOST" --port "$PORT" --ssl-certfile "$SSL_CERTFILE" --ssl-keyfile "$SSL_KEYFILE"
fi

exec "$PYTHON_BIN" -m uvicorn anan_mcp_server.server:app --host "$HOST" --port "$PORT"
