#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="anan-client"
SYSTEMD_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SYSTEMD_WANT_PATH="/etc/systemd/system/multi-user.target.wants/${SERVICE_NAME}.service"
ENV_FILE_PATH="/etc/default/${SERVICE_NAME}"
POLICY_FILE_PATH="/etc/anan-client/command-policy.json"
POLICY_DIR="/etc/anan-client"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: sudo ./uninstall_service.sh [--purge]

Uninstalls anan-client systemd service from Ubuntu.

Options:
    --purge   Also remove /etc/default/anan-client and command policy file.
EOF
}

PURGE="false"
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "${1:-}" == "--purge" ]]; then
    PURGE="true"
elif [[ -n "${1:-}" ]]; then
    echo "Unknown option: ${1}" >&2
    usage >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this uninstaller as root: sudo ./uninstall_service.sh" >&2
    exit 1
fi

stop_service() {
    local unit="${1}"

    if systemctl list-unit-files --type=service 2>/dev/null | grep -qE "^${unit}\\s"; then
        echo "Stopping and disabling ${unit}"
        systemctl disable --now "${unit}" || true
    elif systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -qE "^${unit}\\s"; then
        echo "Stopping active unit ${unit}"
        systemctl stop "${unit}" || true
        systemctl disable "${unit}" || true
    fi

    local pids
    pids="$(ps -eo pid,cmd --no-headers | awk -v proj="${PROJECT_DIR}" '
        $0 ~ /anan_client\.py/ || $0 ~ /start_anan_client\.sh/ {
            if ($0 ~ proj) {
                print $1
            }
        }
    ' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"

    if [[ -n "${pids}" ]]; then
        echo "Stopping orphaned client processes: ${pids}"
        kill ${pids} 2>/dev/null || true
        sleep 2
        kill -9 ${pids} 2>/dev/null || true
    fi
}

stop_service "${SERVICE_NAME}.service"

if [[ -L "${SYSTEMD_WANT_PATH}" || -f "${SYSTEMD_WANT_PATH}" ]]; then
    rm -f "${SYSTEMD_WANT_PATH}"
fi

if [[ -f "${SYSTEMD_UNIT_PATH}" ]]; then
    rm -f "${SYSTEMD_UNIT_PATH}"
fi

if [[ "${PURGE}" == "true" ]]; then
    if [[ -f "${ENV_FILE_PATH}" ]]; then
        rm -f "${ENV_FILE_PATH}"
    fi
    if [[ -f "${POLICY_FILE_PATH}" ]]; then
        rm -f "${POLICY_FILE_PATH}"
    fi
    if [[ -d "${POLICY_DIR}" ]]; then
        rmdir "${POLICY_DIR}" 2>/dev/null || true
    fi
fi

systemctl daemon-reload
systemctl reset-failed || true

echo
if [[ "${PURGE}" == "true" ]]; then
    echo "Uninstalled ${SERVICE_NAME}.service and removed environment files if present."
else
    echo "Uninstalled ${SERVICE_NAME}.service."
    echo "Kept environment file: ${ENV_FILE_PATH}"
fi
