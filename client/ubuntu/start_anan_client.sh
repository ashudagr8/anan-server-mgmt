#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export ANAN_CLIENT_API_KEY="${ANAN_CLIENT_API_KEY:-abc}"
export ANAN_CLIENT_HOST="${ANAN_CLIENT_HOST:-0.0.0.0}"
export ANAN_CLIENT_PORT="${ANAN_CLIENT_PORT:-8443}"

CERTS_DIR="$SCRIPT_DIR/certs"
DEFAULT_CERT="$CERTS_DIR/anan-client.crt"
DEFAULT_KEY="$CERTS_DIR/anan-client.key"
PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
	echo "Missing Python environment: $PYTHON_BIN" >&2
	echo "Fix with one of the following:" >&2
	echo "  1) sudo ./install_service.sh" >&2
	echo "  2) python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt" >&2
	exit 1
fi

# Backward compatibility for previously generated cert names.
LEGACY_CERT="$CERTS_DIR/anan_client_d1d5d5b5e81540269a8b8d2eca57cb82.crt"
LEGACY_KEY="$CERTS_DIR/anan_client_d1d5d5b5e81540269a8b8d2eca57cb82.key"

if [[ -z "${ANAN_CLIENT_HTTPS_CERT:-}" ]]; then
	export ANAN_CLIENT_HTTPS_CERT="$DEFAULT_CERT"
	if [[ ! -f "$ANAN_CLIENT_HTTPS_CERT" && -f "$LEGACY_CERT" ]]; then
		export ANAN_CLIENT_HTTPS_CERT="$LEGACY_CERT"
	fi
fi

if [[ -z "${ANAN_CLIENT_HTTPS_KEY:-}" ]]; then
	export ANAN_CLIENT_HTTPS_KEY="$DEFAULT_KEY"
	if [[ ! -f "$ANAN_CLIENT_HTTPS_KEY" && -f "$LEGACY_KEY" ]]; then
		export ANAN_CLIENT_HTTPS_KEY="$LEGACY_KEY"
	fi
fi

if [[ ! -f "$ANAN_CLIENT_HTTPS_CERT" || ! -f "$ANAN_CLIENT_HTTPS_KEY" ]]; then
	if ! command -v openssl >/dev/null 2>&1; then
		echo "openssl is required to generate TLS certificates." >&2
		exit 1
	fi

	mkdir -p "$(dirname "$ANAN_CLIENT_HTTPS_CERT")"
	mkdir -p "$(dirname "$ANAN_CLIENT_HTTPS_KEY")"

	CERT_HOSTNAME="$(hostname -f 2>/dev/null || hostname || echo localhost)"
	CERT_CN="$CERT_HOSTNAME"
	if [[ ${#CERT_CN} -gt 64 ]]; then
		CERT_CN="${CERT_CN:0:64}"
	fi

	if [[ ! -f "$ANAN_CLIENT_HTTPS_CERT" && -f "$ANAN_CLIENT_HTTPS_KEY" ]]; then
		echo "TLS key exists but certificate is missing. Generating certificate from existing key..."
		openssl req \
			-new \
			-x509 \
			-key "$ANAN_CLIENT_HTTPS_KEY" \
			-out "$ANAN_CLIENT_HTTPS_CERT" \
			-days 365 \
			-subj "/CN=${CERT_CN}"
	elif [[ -f "$ANAN_CLIENT_HTTPS_CERT" && ! -f "$ANAN_CLIENT_HTTPS_KEY" ]]; then
		echo "TLS certificate exists but key is missing. Generating a new key/certificate pair..."
		openssl req \
			-x509 \
			-nodes \
			-newkey rsa:2048 \
			-keyout "$ANAN_CLIENT_HTTPS_KEY" \
			-out "$ANAN_CLIENT_HTTPS_CERT" \
			-days 365 \
			-subj "/CN=${CERT_CN}"
	else
		echo "Generating self-signed TLS certificate for ${CERT_HOSTNAME}..."
		openssl req \
			-x509 \
			-nodes \
			-newkey rsa:2048 \
			-keyout "$ANAN_CLIENT_HTTPS_KEY" \
			-out "$ANAN_CLIENT_HTTPS_CERT" \
			-days 365 \
			-subj "/CN=${CERT_CN}"
	fi

	chmod 600 "$ANAN_CLIENT_HTTPS_KEY"
fi

if [[ "${EUID}" -ne 0 ]]; then
	sudo -E "$PYTHON_BIN" "$SCRIPT_DIR/src/policy_preflight.py"
	exec sudo -E "$PYTHON_BIN" "$SCRIPT_DIR/src/anan_client.py"
fi

"$PYTHON_BIN" "$SCRIPT_DIR/src/policy_preflight.py"
exec "$PYTHON_BIN" "$SCRIPT_DIR/src/anan_client.py"
