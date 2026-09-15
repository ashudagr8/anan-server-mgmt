from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

OUTPUT_LIMIT_BYTES = 256 * 1024
COMMAND_TIMEOUT_SECONDS = 15

ERROR_DENIED_COMMAND = "denied_command"
ERROR_INVALID_ARGS = "invalid_args"
ERROR_TIMEOUT = "timeout"
ERROR_OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"

DEFAULT_POLICY_FILE = "/etc/anan-client/command-policy.json"
DEFAULT_POLICY_TEMPLATE = {
    "allowlist": {},
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
        "ufw",
    ],
}


@dataclass(frozen=True)
class CommandSpec:
    binary: str
    fixed_args: tuple[str, ...] = ()
    allow_extra_args: bool = False


DEFAULT_DENY_BINARIES = {
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
    "ufw",
}

# Backward-compatible alias used by tests/importers.
ALLOWLIST: dict[str, CommandSpec] = {}


@dataclass
class CommandResult:
    command_name: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int | None
    duration_ms: float
    error_code: str | None = None


class CommandValidationError(ValueError):
    def __init__(self, error_code: str, message: str):
        super().__init__(message)
        self.error_code = error_code
        self.message = message


@dataclass(frozen=True)
class ExecutionPolicy:
    allowlist: dict[str, CommandSpec]
    deny_binaries: set[str]


def _policy_file_path() -> Path:
    return Path(os.getenv("ANAN_CLIENT_EXEC_POLICY_FILE", DEFAULT_POLICY_FILE))


def ensure_runtime_policy_file(policy_path: Path | None = None) -> Path:
    resolved_path = policy_path or _policy_file_path()
    if resolved_path.exists():
        return resolved_path

    if str(resolved_path) != DEFAULT_POLICY_FILE:
        raise CommandValidationError(
            ERROR_DENIED_COMMAND,
            f"Policy file '{resolved_path}' is required.",
        )

    try:
        if os.geteuid() != 0:
            raise CommandValidationError(
                ERROR_DENIED_COMMAND,
                f"Policy file '{resolved_path}' is required and must be created as root.",
            )
    except AttributeError:
        pass

    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_path.write_text(json.dumps(DEFAULT_POLICY_TEMPLATE, indent=2) + "\n", encoding="utf-8")

    try:
        os.chown(resolved_path, 0, 0)
    except (AttributeError, PermissionError):
        pass

    os.chmod(resolved_path, 0o600)
    return resolved_path


def _load_policy_data(policy_path: Path | None = None, validate_permissions: bool = True) -> dict[str, Any]:
    resolved_path = policy_path or _policy_file_path()
    if not resolved_path.exists():
        if str(resolved_path) == DEFAULT_POLICY_FILE:
            resolved_path = ensure_runtime_policy_file(resolved_path)
        else:
            raise CommandValidationError(
                ERROR_DENIED_COMMAND,
                f"Policy file '{resolved_path}' is required.",
            )

    if validate_permissions:
        _validate_policy_file_permissions(resolved_path)

    try:
        raw_data = json.loads(resolved_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CommandValidationError(
            ERROR_INVALID_ARGS,
            f"Policy file '{resolved_path}' contains invalid JSON: {exc.msg}.",
        )

    if not isinstance(raw_data, dict):
        raise CommandValidationError(ERROR_INVALID_ARGS, "Policy file root must be an object.")
    return raw_data


def _validate_policy_file_permissions(policy_path: Path) -> None:
    stat_result = policy_path.stat()

    if stat_result.st_uid != 0:
        raise CommandValidationError(
            ERROR_DENIED_COMMAND,
            f"Policy file '{policy_path}' must be owned by root.",
        )

    if stat_result.st_mode & 0o022:
        raise CommandValidationError(
            ERROR_DENIED_COMMAND,
            f"Policy file '{policy_path}' cannot be group/other writable.",
        )


def _command_spec_from_dict(command_name: str, raw_spec: object) -> CommandSpec:
    if not isinstance(raw_spec, dict):
        raise CommandValidationError(
            ERROR_INVALID_ARGS,
            f"Policy command '{command_name}' must be an object.",
        )

    binary = raw_spec.get("binary")
    if not isinstance(binary, str) or not binary.strip():
        raise CommandValidationError(
            ERROR_INVALID_ARGS,
            f"Policy command '{command_name}' requires a non-empty binary path.",
        )

    raw_fixed_args = raw_spec.get("fixed_args", [])
    if not isinstance(raw_fixed_args, list) or not all(isinstance(item, str) for item in raw_fixed_args):
        raise CommandValidationError(
            ERROR_INVALID_ARGS,
            f"Policy command '{command_name}' fixed_args must be a list of strings.",
        )

    allow_extra_args = raw_spec.get("allow_extra_args", False)
    if not isinstance(allow_extra_args, bool):
        raise CommandValidationError(
            ERROR_INVALID_ARGS,
            f"Policy command '{command_name}' allow_extra_args must be a boolean.",
        )

    return CommandSpec(
        binary=binary,
        fixed_args=tuple(raw_fixed_args),
        allow_extra_args=allow_extra_args,
    )


def load_execution_policy() -> ExecutionPolicy:
    raw_data = _load_policy_data(validate_permissions=True)

    raw_allowlist = raw_data.get("allowlist")
    if not isinstance(raw_allowlist, dict):
        raise CommandValidationError(ERROR_INVALID_ARGS, "Policy allowlist must be an object.")
    allowlist = {
        command_name: _command_spec_from_dict(command_name, raw_spec)
        for command_name, raw_spec in raw_allowlist.items()
        if isinstance(command_name, str) and command_name.strip()
    }

    raw_deny = raw_data.get("deny_binaries")
    if not isinstance(raw_deny, list) or not all(isinstance(item, str) and item.strip() for item in raw_deny):
        raise CommandValidationError(ERROR_INVALID_ARGS, "Policy deny_binaries must be a list of strings.")
    deny_binaries = {item.strip() for item in raw_deny}

    return ExecutionPolicy(allowlist=allowlist, deny_binaries=deny_binaries)


def list_allowed_commands() -> list[str]:
    raw_data = _load_policy_data(validate_permissions=False)
    raw_allowlist = raw_data.get("allowlist")
    if not isinstance(raw_allowlist, dict):
        return []

    return sorted(
        command_name
        for command_name in raw_allowlist.keys()
        if isinstance(command_name, str) and command_name.strip()
    )


def read_policy_file(policy_path: Path | None = None) -> dict[str, Any]:
    resolved_path = policy_path or _policy_file_path()
    return _load_policy_data(resolved_path, validate_permissions=False)


def write_policy_file(payload: dict[str, Any], policy_path: Path | None = None) -> None:
    resolved_path = policy_path or _policy_file_path()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def add_policy_command(command_name: str, binary: str, fixed_args: list[str] | None = None, allow_extra_args: bool = False) -> dict[str, Any]:
    normalized_name = command_name.strip()
    if not normalized_name:
        raise CommandValidationError(ERROR_INVALID_ARGS, "command_name cannot be empty.")

    policy_data = read_policy_file()
    allowlist = policy_data.get("allowlist")
    if not isinstance(allowlist, dict):
        raise CommandValidationError(ERROR_INVALID_ARGS, "Policy allowlist must be an object.")

    allowlist[normalized_name] = {
        "binary": binary.strip(),
        "fixed_args": list(fixed_args or []),
        "allow_extra_args": bool(allow_extra_args),
    }
    write_policy_file(policy_data)
    return {
        "command_name": normalized_name,
        "binary": binary.strip(),
        "fixed_args": list(fixed_args or []),
        "allow_extra_args": bool(allow_extra_args),
    }


def remove_policy_command(command_name: str) -> dict[str, Any]:
    normalized_name = command_name.strip()
    if not normalized_name:
        raise CommandValidationError(ERROR_INVALID_ARGS, "command_name cannot be empty.")

    policy_data = read_policy_file()
    allowlist = policy_data.get("allowlist")
    if not isinstance(allowlist, dict):
        raise CommandValidationError(ERROR_INVALID_ARGS, "Policy allowlist must be an object.")

    removed = allowlist.pop(normalized_name, None)
    write_policy_file(policy_data)
    return {
        "command_name": normalized_name,
        "removed": removed is not None,
    }


def _decode_bytes(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _truncate_bytes(raw: bytes, limit: int) -> str:
    if len(raw) <= limit:
        return _decode_bytes(raw)
    return _decode_bytes(raw[:limit]) + "\n<truncated>"


def _validate_command_name(command_name: str | None, allowlist: dict[str, CommandSpec]) -> str:
    if command_name is None:
        raise CommandValidationError(ERROR_INVALID_ARGS, "command_name is required.")
    normalized = command_name.strip()
    if not normalized:
        raise CommandValidationError(ERROR_INVALID_ARGS, "command_name cannot be empty.")
    if normalized not in allowlist:
        raise CommandValidationError(
            ERROR_DENIED_COMMAND,
            f"Command '{normalized}' is not allowed.",
        )
    return normalized


def _validate_state_guardrails(spec: CommandSpec, deny_binaries: set[str]) -> None:
    binary_name = Path(spec.binary).name
    if binary_name in deny_binaries:
        if binary_name == "ufw" and tuple(spec.fixed_args) == ("status", "verbose"):
            return
        raise CommandValidationError(
            ERROR_DENIED_COMMAND,
            f"Binary '{binary_name}' is denied by policy.",
        )


def _build_argv(command_name: str, extra_args: list[str] | None = None) -> list[str]:
    policy = load_execution_policy()
    normalized = _validate_command_name(command_name, policy.allowlist)
    spec = policy.allowlist[normalized]
    _validate_state_guardrails(spec, policy.deny_binaries)

    if extra_args and not spec.allow_extra_args:
        raise CommandValidationError(
            ERROR_INVALID_ARGS,
            "Extra arguments are not allowed for this command.",
        )

    if extra_args and spec.allow_extra_args:
        return [spec.binary, *spec.fixed_args, *extra_args]

    return [spec.binary, *spec.fixed_args]


def execute_allowed_command(command_name: str, extra_args: list[str] | None = None) -> CommandResult:
    argv = _build_argv(command_name=command_name, extra_args=extra_args)
    started = time.perf_counter()

    try:
        completed = subprocess.run(
            argv,
            shell=False,
            check=False,
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            text=False,
        )
    except FileNotFoundError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return CommandResult(
            command_name=command_name,
            success=False,
            stdout="",
            stderr=str(exc),
            exit_code=None,
            duration_ms=duration_ms,
            error_code=ERROR_DENIED_COMMAND,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return CommandResult(
            command_name=command_name,
            success=False,
            stdout=_decode_bytes(exc.stdout or b""),
            stderr=_decode_bytes(exc.stderr or b""),
            exit_code=None,
            duration_ms=duration_ms,
            error_code=ERROR_TIMEOUT,
        )

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    stdout_raw = completed.stdout or b""
    stderr_raw = completed.stderr or b""
    total_output_size = len(stdout_raw) + len(stderr_raw)

    if total_output_size > OUTPUT_LIMIT_BYTES:
        per_stream_limit = OUTPUT_LIMIT_BYTES // 2
        return CommandResult(
            command_name=command_name,
            success=False,
            stdout=_truncate_bytes(stdout_raw, per_stream_limit),
            stderr=_truncate_bytes(stderr_raw, per_stream_limit),
            exit_code=completed.returncode,
            duration_ms=duration_ms,
            error_code=ERROR_OUTPUT_LIMIT_EXCEEDED,
        )

    return CommandResult(
        command_name=command_name,
        success=completed.returncode == 0,
        stdout=_decode_bytes(stdout_raw),
        stderr=_decode_bytes(stderr_raw),
        exit_code=completed.returncode,
        duration_ms=duration_ms,
    )
