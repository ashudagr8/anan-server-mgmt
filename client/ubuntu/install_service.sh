#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="anan-client"
SYSTEMD_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE_PATH="/etc/default/${SERVICE_NAME}"
POLICY_DIR="/etc/anan-client"
POLICY_FILE_PATH="${POLICY_DIR}/command-policy.json"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
START_SCRIPT="${PROJECT_DIR}/start_anan_client.sh"
PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"

usage() {
    cat <<'EOF'
Usage: sudo ./install_service.sh [--reinstall]

Installs anan-client as a systemd service on Ubuntu.

Options:
  --reinstall   Rewrite service unit and environment file even if they exist.
EOF
}

REINSTALL="false"
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "${1:-}" == "--reinstall" ]]; then
    REINSTALL="true"
elif [[ -n "${1:-}" ]]; then
    echo "Unknown option: ${1}" >&2
    usage >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer as root: sudo ./install_service.sh" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required. Install it first (example: sudo apt install -y python3 python3-venv)." >&2
    exit 1
fi

if [[ ! -x "${START_SCRIPT}" ]]; then
    chmod +x "${START_SCRIPT}"
fi

create_venv() {
    local venv_dir="${PROJECT_DIR}/.venv"
    local tmp_log
    local py_mm
    local venv_retry_log
    tmp_log="$(mktemp)"
    venv_retry_log="$(mktemp)"

    echo "Creating Python virtual environment in ${venv_dir}"

    if python3 -m venv "${venv_dir}" >"${tmp_log}" 2>&1; then
        rm -f "${tmp_log}"
        return 0
    fi

    if grep -Eqi "ensurepip|No module named ensurepip|python[0-9.]*-venv" "${tmp_log}"; then
        # Debian/Ubuntu often split ensurepip into python3-venv packages.
        if command -v apt-get >/dev/null 2>&1; then
            py_mm="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
            echo "python3 venv support is missing. Installing required package(s) with apt-get..."

            if apt-get update; then
                apt-get install -y python3-venv || true
                apt-get install -y "python${py_mm}-venv" || true
                rm -rf "${venv_dir}"
                if python3 -m venv "${venv_dir}" >"${venv_retry_log}" 2>&1; then
                    rm -f "${tmp_log}"
                    rm -f "${venv_retry_log}"
                    return 0
                fi

                # Fallback for systems where stdlib venv is still unavailable.
                echo "venv creation still failing, trying python3-virtualenv fallback..."
                apt-get install -y python3-virtualenv || true
                rm -rf "${venv_dir}"
                if python3 -m virtualenv "${venv_dir}"; then
                    rm -f "${tmp_log}"
                    rm -f "${venv_retry_log}"
                    return 0
                fi
            fi
        fi

        echo "Failed to create virtual environment: ensurepip is not available." >&2
        echo "Install venv support and rerun installer:" >&2
        echo "  sudo apt-get update" >&2
        echo "  sudo apt-get install -y python3-venv" >&2
        echo "  sudo apt-get install -y python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')-venv" >&2
        echo "  sudo apt-get install -y python3-virtualenv" >&2
        echo "  python3 -m virtualenv .venv" >&2
        echo "Then run: sudo ./install_service.sh" >&2
        if [[ -s "${venv_retry_log}" ]]; then
            echo "Retry error output:" >&2
            cat "${venv_retry_log}" >&2
        fi
        rm -f "${tmp_log}"
        rm -f "${venv_retry_log}"
        exit 1
    fi

    cat "${tmp_log}" >&2
    rm -f "${tmp_log}"
    rm -f "${venv_retry_log}"
    exit 1
}

ensure_pip() {
    if "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
        return 0
    fi

    echo "Bootstrapping pip in the virtual environment"

    if "${PYTHON_BIN}" -m ensurepip --upgrade >/dev/null 2>&1; then
        return 0
    fi

    echo "pip is missing and ensurepip could not repair it; recreating the virtual environment"
    rm -rf "${PROJECT_DIR}/.venv"
    create_venv
}

if [[ ! -x "${PYTHON_BIN}" ]]; then
    create_venv
fi

ensure_pip

echo "Installing Python dependencies"
"${PYTHON_BIN}" -m pip install --upgrade pip >/dev/null
"${PYTHON_BIN}" -m pip install -r "${PROJECT_DIR}/requirements.txt"

if [[ ! -f "${SYSTEMD_UNIT_PATH}" || "${REINSTALL}" == "true" ]]; then
cat > "${SYSTEMD_UNIT_PATH}" <<EOF
[Unit]
Description=UFW Local Agent API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=-${ENV_FILE_PATH}
ExecStartPre=${PYTHON_BIN} ${PROJECT_DIR}/src/policy_preflight.py
ExecStart=${START_SCRIPT}
Restart=always
RestartSec=3
User=root
Group=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
fi

if [[ ! -f "${ENV_FILE_PATH}" || "${REINSTALL}" == "true" ]]; then
    cat > "${ENV_FILE_PATH}" <<'EOF'
ANAN_CLIENT_API_KEY=change-me
ANAN_CLIENT_HOST=0.0.0.0
ANAN_CLIENT_PORT=8443
ANAN_CLIENT_EXEC_POLICY_FILE=/etc/anan-client/command-policy.json
# Optional overrides:
# ANAN_CLIENT_HTTPS_CERT=/absolute/path/to/tls.crt
# ANAN_CLIENT_HTTPS_KEY=/absolute/path/to/tls.key
# ANAN_CLIENT_REQUEST_LOG_FILE=/absolute/path/to/logfile.log
# ANAN_CLIENT_LOG_RESPONSE_BODY=true
EOF
fi

mkdir -p "${POLICY_DIR}"
if [[ ! -f "${POLICY_FILE_PATH}" || "${REINSTALL}" == "true" ]]; then
        cat > "${POLICY_FILE_PATH}" <<'EOF'
{
    "allowlist": {
        "hostname": {
            "binary": "/usr/bin/hostname",
            "fixed_args": [],
            "allow_extra_args": false
        },
        "uptime": {
            "binary": "/usr/bin/uptime",
            "fixed_args": [],
            "allow_extra_args": false
        },
        "disk_usage": {
            "binary": "/usr/bin/df",
            "fixed_args": ["-h"],
            "allow_extra_args": false
        },
        "memory_usage": {
            "binary": "/usr/bin/free",
            "fixed_args": ["-h"],
            "allow_extra_args": false
        },
        "firewall_status": {
            "binary": "/usr/sbin/ufw",
            "fixed_args": ["status", "verbose"],
            "allow_extra_args": false
        }
    },
    "deny_binaries": [
        "rm",
        "mv",
        "chmod",
        "chown",
        "systemctl",
        "service",
        "reboot",
        "shutdown",
        "iptables",
        "nft",
        "ufw"
    ]
}
EOF
fi

chown root:root "${POLICY_FILE_PATH}"
chmod 600 "${POLICY_FILE_PATH}"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"
systemctl status "${SERVICE_NAME}.service" --no-pager

echo

echo "Installed ${SERVICE_NAME}.service"
echo "Environment file: ${ENV_FILE_PATH}"
echo "Policy file (root editable only): ${POLICY_FILE_PATH}"
echo "Edit ANAN_CLIENT_API_KEY in the environment file, then run:"
echo "  sudo systemctl restart ${SERVICE_NAME}.service"
echo "Follow logs with:"
echo "  sudo journalctl -u ${SERVICE_NAME}.service -f"
