import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.responses import Response

from audit import (
    get_audit_log_retention_info,
    log_command_execution,
    log_configuration_change,
    log_policy_decision,
)
from execution_policy import (
    ERROR_DENIED_COMMAND,
    ERROR_INVALID_ARGS,
    ERROR_OUTPUT_LIMIT_EXCEEDED,
    ERROR_TIMEOUT,
    CommandResult,
    CommandValidationError,
    add_policy_command,
    execute_allowed_command,
    list_allowed_commands,
    load_execution_policy,
    remove_policy_command,
)
from security import get_api_key


def _env_var(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return default


def get_request_logger() -> logging.Logger:
    logger = logging.getLogger("ufw_local_agent.requests")
    log_file = _env_var(
        "ANAN_CLIENT_REQUEST_LOG_FILE",
        default="logs/anan-client-requests.log",
    )
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            base_filename = getattr(handler, "baseFilename", "")
            if base_filename and Path(base_filename).resolve() == log_path.resolve():
                return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Start with a fresh request log on each service restart.
    handler = logging.FileHandler(log_path, mode="w")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    return logger


def _safe_text(data: bytes, limit: int = 4000) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > limit:
        return f"{text[:limit]}...<truncated>"
    return text


def _is_true(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


async def _capture_response_body(response) -> tuple[bytes, Response | None]:
    if hasattr(response, "body") and response.body is not None:
        return response.body, None

    if hasattr(response, "body_iterator") and response.body_iterator is not None:
        chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            if isinstance(chunk, bytes):
                chunks.append(chunk)
            else:
                chunks.append(str(chunk).encode("utf-8", errors="replace"))
        body = b"".join(chunks)
        rebuilt = Response(
            content=body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
            background=response.background,
        )
        return body, rebuilt

    return b"", None


class CallerIdentity(BaseModel):
    username: str | None = None
    agent_ip: str | None = None
    source: str | None = None


class RunCommandRequest(BaseModel):
    command_name: str = Field(min_length=1)
    args: list[str] | None = None
    caller_identity: CallerIdentity | None = None


class PolicyCommandRequest(BaseModel):
    command_name: str = Field(min_length=1)
    binary: str = Field(min_length=1)
    fixed_args: list[str] | None = None
    allow_extra_args: bool = False
    caller_identity: CallerIdentity | None = None


def _status_code_for_error(error_code: str | None) -> int:
    if error_code == ERROR_DENIED_COMMAND:
        return 403
    if error_code == ERROR_INVALID_ARGS:
        return 400
    if error_code == ERROR_TIMEOUT:
        return 408
    if error_code == ERROR_OUTPUT_LIMIT_EXCEEDED:
        return 413
    return 500


def _result_payload(result: CommandResult) -> dict[str, object]:
    payload: dict[str, object] = {
        "command_name": result.command_name,
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
    }
    if result.error_code:
        payload["error_code"] = result.error_code
    return payload


def _sanitize_identity_token(value: str | None, default: str = "") -> str:
    text = (value or "").strip()
    if not text:
        return default
    text = re.sub(r"\s+", "_", text)
    text = "".join(ch for ch in text if ch.isprintable() and ch not in {"\n", "\r", "\t"})
    if not text:
        return default
    if len(text) > 128:
        return text[:125] + "..."
    return text


def _caller_identity_from_headers(request: Request) -> CallerIdentity:
    username = ""
    for header_name in (
        "X-Caller-Username",
        "X-User",
        "X-Forwarded-User",
        "X-Authenticated-User",
    ):
        candidate = _sanitize_identity_token(request.headers.get(header_name), default="")
        if candidate:
            username = candidate
            break

    source = _sanitize_identity_token(request.headers.get("X-Caller-Source"), default="")
    agent_ip = _sanitize_identity_token(request.headers.get("X-Agent-IP"), default="")
    return CallerIdentity(username=username or None, source=source or None, agent_ip=agent_ip or None)


def _normalize_caller_identity(request: Request, payload_identity: CallerIdentity | None = None) -> CallerIdentity:
    header_identity = _caller_identity_from_headers(request)

    username = _sanitize_identity_token(
        (payload_identity.username if payload_identity else "") or (header_identity.username or ""),
        default="anonymous",
    )
    source = _sanitize_identity_token(
        (payload_identity.source if payload_identity else "") or (header_identity.source or ""),
        default="unknown",
    )
    agent_ip = _sanitize_identity_token(
        (payload_identity.agent_ip if payload_identity else "") or (header_identity.agent_ip or ""),
        default="unknown",
    )

    return CallerIdentity(username=username, source=source, agent_ip=agent_ip)


def _caller_identity_payload(caller_identity: CallerIdentity) -> dict[str, str]:
    return {
        "username": _sanitize_identity_token(caller_identity.username, default="anonymous"),
        "source": _sanitize_identity_token(caller_identity.source, default="unknown"),
        "agent_ip": _sanitize_identity_token(caller_identity.agent_ip, default="unknown"),
    }


def _get_command_binary_path(command_name: str) -> str | None:
    """Get the binary path for a command from the execution policy.
    
    Args:
        command_name: The logical command name
        
    Returns:
        The binary path if command exists, None otherwise
    """
    try:
        policy = load_execution_policy()
        if command_name in policy.allowlist:
            return policy.allowlist[command_name].binary
    except (CommandValidationError, PermissionError, OSError):
        pass
    return None


def _log_command_execution(
    request: Request,
    command_name: str,
    result: CommandResult,
    caller_identity: CallerIdentity,
    timestamp: datetime | None = None,
    hostname: str | None = None,
    command_args: list[str] | None = None,
) -> None:
    """Log command execution to both request log and audit log.
    
    Args:
        request: The HTTP request
        command_name: The logical command name from policy
        result: The command execution result
        caller_identity: The caller's identity information
        timestamp: UTC timestamp for the event (defaults to now)
        hostname: Target hostname (defaults to socket.gethostname())
        command_args: Command arguments that were provided (if any)
    """
    timestamp = timestamp or datetime.now(tz=timezone.utc)
    hostname = hostname or socket.gethostname()
    
    # Log to request logger (existing behavior)
    get_request_logger().info(
        json.dumps(
            {
                "event": "command_execution",
                "timestamp": timestamp.isoformat(),
                "requested_by": _sanitize_identity_token(caller_identity.username, default="anonymous"),
                "caller_identity_source": _sanitize_identity_token(caller_identity.source, default="unknown"),
                "caller_agent_ip": _sanitize_identity_token(caller_identity.agent_ip, default="unknown"),
                "command_name": command_name,
                "target_host": hostname,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "success": result.success,
                "error_code": result.error_code,
            }
        )
    )
    
    # Log to audit logger with comprehensive information
    username = _sanitize_identity_token(caller_identity.username, default="anonymous")
    ip_address = _sanitize_identity_token(caller_identity.agent_ip, default="unknown")
    source = _sanitize_identity_token(caller_identity.source, default="unknown")
    
    binary_path = _get_command_binary_path(command_name) or "unknown"
    
    # Determine denial reason if applicable
    denial_reason = None
    if not result.success and result.error_code:
        if result.error_code == ERROR_DENIED_COMMAND:
            denial_reason = result.stderr or "Command denied by policy"
        elif result.error_code == ERROR_INVALID_ARGS:
            denial_reason = result.stderr or "Invalid arguments"
        elif result.error_code == ERROR_TIMEOUT:
            denial_reason = "Command execution timeout"
        elif result.error_code == ERROR_OUTPUT_LIMIT_EXCEEDED:
            denial_reason = "Output limit exceeded"
    
    log_command_execution(
        timestamp=timestamp,
        username=username,
        ip_address=ip_address,
        command_name=command_name,
        binary_path=binary_path,
        command_args=command_args,
        success=result.success,
        exit_code=result.exit_code,
        error_code=result.error_code,
        denial_reason=denial_reason,
        duration_ms=result.duration_ms,
        hostname=hostname,
        source=source,
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="anan-client",
        description="Policy-controlled Linux command execution API.",
        version="1.0.0",
    )
    log_response_body = _is_true(
        _env_var("ANAN_CLIENT_LOG_RESPONSE_BODY"),
        default=True,
    )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(_request: Request, _exc: RequestValidationError):
        return JSONResponse(
            status_code=400,
            content={
                "command_name": "",
                "success": False,
                "stdout": "",
                "stderr": "Malformed or invalid request payload.",
                "exit_code": None,
                "duration_ms": 0.0,
                "error_code": ERROR_INVALID_ARGS,
            },
        )

    @app.middleware("http")
    async def log_request_response(request: Request, call_next):
        request_logger = get_request_logger()
        started = time.perf_counter()
        request_body = _safe_text(await request.body())
        request_caller_identity = _caller_identity_payload(_normalize_caller_identity(request=request))

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            request_logger.exception(
                json.dumps(
                    {
                        "method": request.method,
                        "path": request.url.path,
                        "query": str(request.url.query),
                        "request_body": request_body,
                        "caller_identity": request_caller_identity,
                        "status_code": 500,
                        "response_body": "<unhandled exception>",
                        "duration_ms": duration_ms,
                        "error": str(exc),
                    }
                )
            )
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response_body = "<disabled>"
        replacement_response = None
        if log_response_body:
            body_bytes, replacement_response = await _capture_response_body(response)
            response_body = _safe_text(body_bytes) if body_bytes else ""

        request_logger.info(
            json.dumps(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "query": str(request.url.query),
                    "request_body": request_body,
                    "caller_identity": request_caller_identity,
                    "status_code": response.status_code,
                    "response_body": response_body,
                    "duration_ms": duration_ms,
                }
            )
        )
        return replacement_response or response

    @app.get("/", dependencies=[Depends(get_api_key)])
    def root() -> dict[str, str]:
        try:
            allowed_commands = ",".join(list_allowed_commands())
        except (CommandValidationError, PermissionError, OSError):
            allowed_commands = ""

        return {
            "message": "read-only command API",
            "run": "/commands/run",
            "allowed_commands": allowed_commands,
            "hostname": "/system/hostname",
        }

    @app.get("/cli/list", dependencies=[Depends(get_api_key)])
    def cli_list(request: Request) -> dict[str, object]:
        caller_identity = _normalize_caller_identity(request=request)
        commands = []
        for command_name in list_allowed_commands():
            commands.append({"name": command_name, "read_only": True})
        return {
            "commands": commands,
            "count": len(commands),
            "caller_identity": _caller_identity_payload(caller_identity),
        }

    @app.post("/policy/commands", dependencies=[Depends(get_api_key)])
    def add_policy_command_endpoint(request: Request, payload: PolicyCommandRequest) -> dict[str, object]:
        caller_identity = _normalize_caller_identity(request=request, payload_identity=payload.caller_identity)
        timestamp = datetime.now(tz=timezone.utc)
        
        try:
            result = add_policy_command(
                command_name=payload.command_name,
                binary=payload.binary,
                fixed_args=payload.fixed_args,
                allow_extra_args=payload.allow_extra_args,
            )
        except CommandValidationError as exc:
            raise HTTPException(status_code=400, detail=exc.message) from exc
        
        # Log configuration change to audit log
        log_configuration_change(
            timestamp=timestamp,
            username=_sanitize_identity_token(caller_identity.username, default="anonymous"),
            ip_address=_sanitize_identity_token(caller_identity.agent_ip, default="unknown"),
            operation="add_command",
            command_name=payload.command_name,
            details={
                "binary": payload.binary,
                "fixed_args": payload.fixed_args or [],
                "allow_extra_args": payload.allow_extra_args,
            },
            hostname=socket.gethostname(),
            source=_sanitize_identity_token(caller_identity.source, default="unknown"),
        )
        
        return {
            "status": "updated",
            **result,
            "caller_identity": _caller_identity_payload(caller_identity),
        }

    @app.delete("/policy/commands/{command_name}", dependencies=[Depends(get_api_key)])
    def remove_policy_command_endpoint(request: Request, command_name: str) -> dict[str, object]:
        caller_identity = _normalize_caller_identity(request=request)
        timestamp = datetime.now(tz=timezone.utc)
        
        try:
            result = remove_policy_command(command_name)
        except CommandValidationError as exc:
            raise HTTPException(status_code=400, detail=exc.message) from exc
        
        # Log configuration change to audit log
        log_configuration_change(
            timestamp=timestamp,
            username=_sanitize_identity_token(caller_identity.username, default="anonymous"),
            ip_address=_sanitize_identity_token(caller_identity.agent_ip, default="unknown"),
            operation="remove_command",
            command_name=command_name,
            details={"removed": result.get("removed")},
            hostname=socket.gethostname(),
            source=_sanitize_identity_token(caller_identity.source, default="unknown"),
        )
        
        return {
            "status": "updated",
            **result,
            "caller_identity": _caller_identity_payload(caller_identity),
        }

    @app.get("/system/hostname", dependencies=[Depends(get_api_key)])
    def system_hostname(request: Request) -> dict[str, object]:
        caller_identity = _normalize_caller_identity(request=request)
        timestamp = datetime.now(tz=timezone.utc)
        hostname = socket.gethostname()
        started = time.perf_counter()
        result = CommandResult(
            command_name="hostname",
            success=True,
            stdout=f"{hostname}\n",
            stderr="",
            exit_code=0,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )

        _log_command_execution(
            request=request,
            command_name="hostname",
            result=result,
            caller_identity=caller_identity,
            timestamp=timestamp,
            hostname=hostname,
        )
        return {
            "hostname": hostname,
            "caller_identity": _caller_identity_payload(caller_identity),
        }

    @app.post("/commands/run", dependencies=[Depends(get_api_key)])
    def run_command(request: Request, payload: RunCommandRequest) -> dict[str, object]:
        caller_identity = _normalize_caller_identity(request=request, payload_identity=payload.caller_identity)
        timestamp = datetime.now(tz=timezone.utc)
        hostname = socket.gethostname()
        
        try:
            result = execute_allowed_command(
                command_name=payload.command_name,
                extra_args=payload.args,
            )
        except CommandValidationError as exc:
            result = CommandResult(
                command_name=payload.command_name,
                success=False,
                stdout="",
                stderr=exc.message,
                exit_code=None,
                duration_ms=0.0,
                error_code=exc.error_code,
            )
            
            # Log policy decision for denied commands
            binary_path = _get_command_binary_path(payload.command_name) or "unknown"
            log_policy_decision(
                timestamp=timestamp,
                username=_sanitize_identity_token(caller_identity.username, default="anonymous"),
                ip_address=_sanitize_identity_token(caller_identity.agent_ip, default="unknown"),
                command_name=payload.command_name,
                binary_path=binary_path,
                decision="denied",
                reason=exc.message,
                hostname=hostname,
                source=_sanitize_identity_token(caller_identity.source, default="unknown"),
            )

        _log_command_execution(
            request=request,
            command_name=payload.command_name,
            result=result,
            caller_identity=caller_identity,
            timestamp=timestamp,
            hostname=hostname,
            command_args=payload.args,
        )
        status_code = 200 if result.success else _status_code_for_error(result.error_code)
        return JSONResponse(
            status_code=status_code,
            content={
                **_result_payload(result),
                "caller_identity": _caller_identity_payload(caller_identity),
            },
        )

    @app.get("/audit/info", dependencies=[Depends(get_api_key)])
    def audit_info(request: Request) -> dict[str, object]:
        """Get information about audit log retention and status."""
        caller_identity = _normalize_caller_identity(request=request)
        retention_info = get_audit_log_retention_info()
        
        return {
            "audit_logs": retention_info,
            "caller_identity": _caller_identity_payload(caller_identity),
        }

    return app


app = create_app()
