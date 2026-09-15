"""Audit logging module for command execution and policy enforcement.

This module provides audit logging functionality that captures all security-relevant
events including command execution, policy decisions, and access attempts. Audit logs
are retained for 30 days and persist across service restarts.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _env_var(*names: str, default: str | None = None) -> str | None:
    """Get environment variable, supporting multiple name aliases."""
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return default


def _get_audit_log_dir() -> Path:
    """Get the audit log directory, creating it if necessary."""
    log_dir = _env_var(
        "ANAN_CLIENT_AUDIT_LOG_DIR",
        default="logs/audit",
    )
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    return log_path


def get_audit_logger() -> logging.Logger:
    """Get or create the audit logger.
    
    The audit logger:
    - Persists audit events to disk with append mode (retains across restarts)
    - Uses a daily rotation strategy
    - Cleans up logs older than 30 days
    
    Returns:
        logging.Logger: Configured audit logger instance
    """
    logger = logging.getLogger("anan_client.audit")
    
    # Return existing logger if already configured
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    # Configure file handler with append mode (retains across restarts)
    audit_dir = _get_audit_log_dir()
    log_file = audit_dir / "audit.log"
    
    handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    
    # Clean up old logs on startup
    _cleanup_old_audit_logs(audit_dir)
    
    return logger


def _cleanup_old_audit_logs(audit_dir: Path, retention_days: int = 30) -> None:
    """Remove audit log files older than the retention period.
    
    Args:
        audit_dir: Directory containing audit log files
        retention_days: Number of days to retain logs (default: 30)
    """
    if not audit_dir.exists():
        return
    
    cutoff_time = datetime.now(tz=timezone.utc) - timedelta(days=retention_days)
    
    for log_file in audit_dir.glob("*.log*"):
        try:
            # Get file modification time
            mtime = log_file.stat().st_mtime
            mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            
            if mtime_dt < cutoff_time:
                log_file.unlink()
        except (OSError, ValueError):
            # Skip files that can't be accessed or have invalid timestamps
            pass


def log_command_execution(
    *,
    timestamp: datetime,
    username: str,
    ip_address: str,
    command_name: str,
    binary_path: str,
    command_args: list[str] | None = None,
    success: bool,
    exit_code: int | None = None,
    error_code: str | None = None,
    denial_reason: str | None = None,
    duration_ms: float = 0.0,
    hostname: str = "",
    source: str = "unknown",
) -> None:
    """Log a command execution audit event.
    
    This function logs all relevant details about command execution including
    the request details, execution result, and any denial reasons.
    
    Args:
        timestamp: UTC timestamp of the event
        username: Username of the requester
        ip_address: IP address of the requester
        command_name: Logical command name from policy
        binary_path: Actual binary path being executed
        command_args: List of command arguments (if any)
        success: Whether execution was successful
        exit_code: Process exit code (None if not applicable)
        error_code: Error code if execution failed (e.g., "denied_command")
        denial_reason: Detailed reason if command was denied
        duration_ms: Execution duration in milliseconds
        hostname: Target hostname
        source: Source identifier (e.g., API, agent name)
    """
    logger = get_audit_logger()
    
    event = {
        "event_type": "command_execution",
        "timestamp": timestamp.isoformat(),
        "username": username or "unknown",
        "ip_address": ip_address or "unknown",
        "source": source or "unknown",
        "hostname": hostname or "unknown",
        "command_name": command_name,
        "binary_path": binary_path,
        "command_args": command_args or [],
        "success": success,
        "exit_code": exit_code,
        "error_code": error_code,
        "denial_reason": denial_reason,
        "duration_ms": duration_ms,
    }
    
    logger.info(json.dumps(event))


def log_policy_decision(
    *,
    timestamp: datetime,
    username: str,
    ip_address: str,
    command_name: str,
    binary_path: str,
    decision: str,
    reason: str,
    hostname: str = "",
    source: str = "unknown",
) -> None:
    """Log a policy decision audit event.
    
    This function logs policy enforcement decisions such as whether a command
    is allowed or denied based on the execution policy.
    
    Args:
        timestamp: UTC timestamp of the event
        username: Username of the requester
        ip_address: IP address of the requester
        command_name: Logical command name from policy
        binary_path: Actual binary path being evaluated
        decision: Policy decision (e.g., "allowed", "denied")
        reason: Detailed reason for the decision
        hostname: Target hostname
        source: Source identifier (e.g., API, agent name)
    """
    logger = get_audit_logger()
    
    event = {
        "event_type": "policy_decision",
        "timestamp": timestamp.isoformat(),
        "username": username or "unknown",
        "ip_address": ip_address or "unknown",
        "source": source or "unknown",
        "hostname": hostname or "unknown",
        "command_name": command_name,
        "binary_path": binary_path,
        "decision": decision,
        "reason": reason,
    }
    
    logger.info(json.dumps(event))


def log_access_attempt(
    *,
    timestamp: datetime,
    username: str,
    ip_address: str,
    endpoint: str,
    method: str,
    status_code: int,
    result: str,
    hostname: str = "",
    source: str = "unknown",
) -> None:
    """Log an API access audit event.
    
    This function logs all API access attempts including successful and failed
    authentication/authorization attempts.
    
    Args:
        timestamp: UTC timestamp of the event
        username: Username attempting access (may be empty)
        ip_address: IP address of the requester
        endpoint: API endpoint accessed
        method: HTTP method (GET, POST, DELETE, etc.)
        status_code: HTTP response status code
        result: Result of access attempt (e.g., "allowed", "denied", "unauthorized")
        hostname: Target hostname
        source: Source identifier (e.g., API, agent name)
    """
    logger = get_audit_logger()
    
    event = {
        "event_type": "access_attempt",
        "timestamp": timestamp.isoformat(),
        "username": username or "unknown",
        "ip_address": ip_address or "unknown",
        "source": source or "unknown",
        "hostname": hostname or "unknown",
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "result": result,
    }
    
    logger.info(json.dumps(event))


def log_configuration_change(
    *,
    timestamp: datetime,
    username: str,
    ip_address: str,
    operation: str,
    command_name: str,
    details: dict[str, Any] | None = None,
    hostname: str = "",
    source: str = "unknown",
) -> None:
    """Log a configuration change audit event.
    
    This function logs changes to the command execution policy such as
    adding or removing allowed commands.
    
    Args:
        timestamp: UTC timestamp of the event
        username: Username making the change
        ip_address: IP address of the requester
        operation: Type of operation (e.g., "add_command", "remove_command")
        command_name: Logical command name being modified
        details: Additional details about the change
        hostname: Target hostname
        source: Source identifier (e.g., API, agent name)
    """
    logger = get_audit_logger()
    
    event = {
        "event_type": "configuration_change",
        "timestamp": timestamp.isoformat(),
        "username": username or "unknown",
        "ip_address": ip_address or "unknown",
        "source": source or "unknown",
        "hostname": hostname or "unknown",
        "operation": operation,
        "command_name": command_name,
        "details": details or {},
    }
    
    logger.info(json.dumps(event))


def get_audit_log_retention_info() -> dict[str, Any]:
    """Get information about audit log retention.
    
    Returns:
        dict: Information about audit log directory and retention policy
    """
    audit_dir = _get_audit_log_dir()
    
    log_files = []
    total_size = 0
    
    if audit_dir.exists():
        for log_file in sorted(audit_dir.glob("*.log*")):
            try:
                size = log_file.stat().st_size
                total_size += size
                log_files.append({
                    "filename": log_file.name,
                    "size_bytes": size,
                    "modified": datetime.fromtimestamp(
                        log_file.stat().st_mtime,
                        tz=timezone.utc
                    ).isoformat(),
                })
            except OSError:
                pass
    
    return {
        "log_directory": str(audit_dir),
        "retention_days": 30,
        "total_size_bytes": total_size,
        "log_files": log_files,
        "file_count": len(log_files),
    }
