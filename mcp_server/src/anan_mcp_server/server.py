import json
import os
import shutil
import ssl
import stat
import subprocess
import ipaddress
import urllib.error
import urllib.request
import tempfile
import re
import sys
from contextvars import ContextVar
from urllib.parse import quote, urlparse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from starlette.datastructures import Headers
import jwt
from jwt import PyJWKClient
from jwt import exceptions as jwt_exceptions

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

mcp = FastMCP(
    "ufw_mcp_server",
    instructions=(
        "MCP server exposing server firewall management, "
        "and routing to named servers."
    ),
)


@dataclass(frozen=True)
class AnanClientConfig:
    """Connection settings for a server."""

    name: str
    agent_url: str
    api_key: str | None
    ssl_verify: bool = True
    commands: tuple[str, ...] | None = None


@dataclass(frozen=True)
class OAuthServerConfig:
    """Configuration for a trusted OAuth/OIDC server."""

    name: str
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256",)


@dataclass(frozen=True)
class AuthSettings:
    """Server authentication mode loaded once at startup."""

    mode: Literal["no_auth", "oauth"]
    oauth_servers: dict[str, OAuthServerConfig]
    oauth_source: str | None = None


@dataclass(frozen=True)
class RegisteredCommand:
    """Canonical command definition owned by the MCP server."""

    name: str
    description: str
    binary: str
    fixed_args: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    allow_extra_args: bool = False
    examples: tuple[str, ...] = ()


DEFAULT_ANAN_CLIENT_NAME = "default"
MCP_SERVER_CONFIG_ENV = "MCP_SERVER_CONFIG"
ANAN_CLIENTS_ENV = "ANAN_CLIENTS"
ANAN_CLIENTS_FILE_ENV = "ANAN_CLIENTS_FILE"
AUTH_MODE_ENV = "AUTH_MODE"
OAUTH_SERVERS_ENV = "OAUTH_SERVERS"
OAUTH_SERVERS_FILE_ENV = "OAUTH_SERVERS_FILE"
MVP_NON_ADMIN_MODE_ENV = "MVP_NON_ADMIN_MODE"
MVP_NON_ADMIN_TOOL_NAMES = frozenset({"list_servers", "readonly_cli_list", "readonly_cli_run"})
INBOUND_AGENT_USERNAME_HEADER = "x-agent-username"
INBOUND_CALLER_USERNAME_HEADER = "x-caller-username"
INBOUND_AGENT_IP_HEADER = "x-agent-ip"
INBOUND_FORWARDED_FOR_HEADER = "x-forwarded-for"
DEFAULT_MCP_SERVER_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "mcp_server_config.json",
)

DEFAULT_REGISTERED_COMMANDS_RAW: dict[str, dict[str, Any]] = {
    "hostname": {
        "description": "Print system hostname.",
        "aliases": ["hostname"],
        "binary": "/usr/bin/hostname",
        "fixed_args": [],
        "allow_extra_args": False,
        "examples": ["show the hostname"],
    },
    "date_now": {
        "description": "Print the current system date and time.",
        "aliases": ["date", "current date", "current time"],
        "binary": "/usr/bin/date",
        "fixed_args": [],
        "allow_extra_args": False,
        "examples": ["what time is it on the server"],
    },
    "uptime": {
        "description": "Tell how long the system has been running.",
        "aliases": ["uptime", "system uptime"],
        "binary": "/usr/bin/uptime",
        "fixed_args": [],
        "allow_extra_args": False,
        "examples": ["show uptime"],
    },
    "disk_usage": {
        "description": "Report file system disk space usage.",
        "aliases": ["df", "disk usage", "filesystem usage"],
        "binary": "/usr/bin/df",
        "fixed_args": ["-h"],
        "allow_extra_args": False,
        "examples": ["show disk usage"],
    },
    "memory_usage": {
        "description": "Display the amount of free and used memory.",
        "aliases": ["free", "memory usage", "ram usage"],
        "binary": "/usr/bin/free",
        "fixed_args": ["-h"],
        "allow_extra_args": False,
        "examples": ["show memory usage"],
    },
    "process_list": {
        "description": "Report a snapshot of current processes.",
        "aliases": ["ps", "processes", "running processes"],
        "binary": "/usr/bin/ps",
        "fixed_args": ["aux"],
        "allow_extra_args": False,
        "examples": ["list running processes"],
    },
}

def get_mcp_server_config_path() -> str:
    configured = os.getenv(MCP_SERVER_CONFIG_ENV, "").strip()
    return configured or DEFAULT_MCP_SERVER_CONFIG_PATH


def load_mcp_server_config() -> dict[str, Any]:
    config_path = get_mcp_server_config_path()
    if not config_path or not os.path.exists(config_path):
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}

    return payload if isinstance(payload, dict) else {}


def get_config_value(env_name: str, config_path: tuple[str, ...], default: Any = None, *, parser: Any = None) -> Any:
    if env_name in os.environ:
        env_value = os.environ[env_name]
        if env_value != "":
            return parser(env_value) if parser is not None else env_value
        if default is not None:
            return parser(default) if parser is not None else default
        return ""

    config = load_mcp_server_config()
    current: Any = config
    for key in config_path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)

    if current is None:
        return default
    return parser(current) if parser is not None else current


# Default connection details for the local UFW helper agent.
UFW_AGENT_URL = get_config_value("UFW_AGENT_URL", ("agent", "ufw_agent_url"), "https://127.0.0.1:8443")
ANAN_CLIENT_API_KEY = get_config_value("ANAN_CLIENT_API_KEY", ("agent", "anan_client_api_key"), None)


RequestIdentityContext = dict[str, Any]
REQUEST_IDENTITY_CONTEXT: ContextVar[RequestIdentityContext | None] = ContextVar(
    "request_identity_context",
    default=None,
)


def get_ufw_agent_url() -> str:
    value = get_config_value("UFW_AGENT_URL", ("agent", "ufw_agent_url"), "https://127.0.0.1:8443")
    return str(value or "https://127.0.0.1:8443")


def get_anan_client_api_key() -> str | None:
    value = get_config_value("ANAN_CLIENT_API_KEY", ("agent", "anan_client_api_key"), None)
    return str(value) if value is not None else None


def _parse_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _normalize_command_names(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        raw_items = _parse_csv(value)
    elif isinstance(value, (list, tuple)):
        raw_items = tuple(str(item).strip() for item in value if str(item).strip())
    else:
        raw_items = (str(value).strip(),) if str(value).strip() else ()

    seen: set[str] = set()
    normalized: list[str] = []
    for item in raw_items:
        if item and item not in seen:
            seen.add(item)
            normalized.append(item)
    return tuple(normalized)


def is_mvp_non_admin_mode() -> bool:
    """Return whether MVP non-admin mode is enabled."""
    value = get_config_value(MVP_NON_ADMIN_MODE_ENV, ("auth", "mvp_non_admin_mode"), "false")
    return _parse_bool(value, default=False)


MVP_NON_ADMIN_MODE = is_mvp_non_admin_mode()


def is_tool_enabled(tool_name: str) -> bool:
    """Return whether a tool should be registered for the current runtime mode."""
    if not MVP_NON_ADMIN_MODE:
        return True
    return tool_name in MVP_NON_ADMIN_TOOL_NAMES


def mcp_tool(tool_name: str):
    """Register the tool only when enabled for the current runtime mode."""
    def decorator(func):
        if is_tool_enabled(tool_name):
            return mcp.tool(name=tool_name)(func)
        return func

    return decorator


def _normalize_oauth_server(name: str, raw_config: dict[str, Any]) -> OAuthServerConfig:
    issuer = raw_config.get("issuer")
    audience = raw_config.get("audience")
    jwks_url = raw_config.get("jwks_url") or raw_config.get("jwksUri") or raw_config.get("jwks")
    algorithms_raw = raw_config.get("algorithms")

    if isinstance(algorithms_raw, str):
        algorithms = _parse_csv(algorithms_raw)
    elif isinstance(algorithms_raw, list):
        algorithms = tuple(str(item).strip() for item in algorithms_raw if str(item).strip())
    else:
        algorithms = ("RS256",)

    if not issuer or not str(issuer).strip():
        raise RuntimeError(f"OAuth server '{name}' is missing issuer.")
    if not audience or not str(audience).strip():
        raise RuntimeError(f"OAuth server '{name}' is missing audience.")
    if not jwks_url or not str(jwks_url).strip():
        raise RuntimeError(f"OAuth server '{name}' is missing jwks_url.")
    if not algorithms:
        raise RuntimeError(f"OAuth server '{name}' must define at least one signing algorithm.")

    return OAuthServerConfig(
        name=name,
        issuer=str(issuer).strip(),
        audience=str(audience).strip(),
        jwks_url=str(jwks_url).strip(),
        algorithms=algorithms,
    )


def load_oauth_servers_payload() -> tuple[str, str]:
    """Load OAuth server JSON payload from file or environment."""
    file_path = os.getenv(OAUTH_SERVERS_FILE_ENV)
    if file_path is not None:
        file_path = file_path.strip()
        if file_path:
            try:
                with open(file_path, encoding="utf-8") as handle:
                    return handle.read(), f"file:{file_path}"
            except FileNotFoundError as exc:
                raise RuntimeError(f"OAuth servers file not found: {file_path}") from exc
            except OSError as exc:
                raise RuntimeError(f"Unable to read OAuth servers file: {file_path}") from exc
        if file_path == "":
            # An explicit empty environment override should suppress config-file fallback.
            pass
    elif not file_path:
        file_path = str(get_config_value(OAUTH_SERVERS_FILE_ENV, ("auth", "oauth_servers_file"), "") or "")
        if file_path:
            try:
                with open(file_path, encoding="utf-8") as handle:
                    return handle.read(), f"file:{file_path}"
            except FileNotFoundError as exc:
                raise RuntimeError(f"OAuth servers file not found: {file_path}") from exc
            except OSError as exc:
                raise RuntimeError(f"Unable to read OAuth servers file: {file_path}") from exc

    raw_payload = os.getenv(OAUTH_SERVERS_ENV)
    if raw_payload is not None:
        raw_payload = raw_payload.strip()
        if not raw_payload:
            raw_payload = ""
    else:
        raw_payload = ""
        oauth_servers_cfg = get_config_value(OAUTH_SERVERS_ENV, ("auth", "oauth_servers"), None)
        if isinstance(oauth_servers_cfg, str):
            raw_payload = oauth_servers_cfg.strip()
        elif oauth_servers_cfg is not None:
            raw_payload = json.dumps(oauth_servers_cfg)

    if not raw_payload:
        raise RuntimeError(
            f"Set {OAUTH_SERVERS_FILE_ENV} or {OAUTH_SERVERS_ENV} when {AUTH_MODE_ENV}=oauth."
        )
    if OAUTH_SERVERS_ENV in os.environ:
        return raw_payload, f"env:{OAUTH_SERVERS_ENV}"
    return raw_payload, "config:auth.oauth_servers"


def _extract_auth_mode_from_oauth_payload(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None

    raw_mode = payload.get("auth_mode")
    if raw_mode is None:
        raw_mode = payload.get("AUTH_MODE")
    if raw_mode is None:
        return None

    mode = str(raw_mode).strip().lower()
    if mode not in {"no_auth", "oauth"}:
        raise RuntimeError("oauth server payload auth_mode must be one of: no_auth, oauth.")
    return mode


def _load_oauth_servers_payload_json() -> tuple[Any, str]:
    raw_payload, source = load_oauth_servers_payload()

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid OAuth server JSON from {source}.") from exc

    return payload, source


def detect_auth_mode_from_oauth_payload() -> str | None:
    """Read auth_mode from oauth payload metadata when present."""
    try:
        payload, _ = _load_oauth_servers_payload_json()
    except RuntimeError:
        return None
    return _extract_auth_mode_from_oauth_payload(payload)


def load_oauth_server_registry() -> tuple[dict[str, OAuthServerConfig], str]:
    payload, source = _load_oauth_servers_payload_json()

    registry: dict[str, OAuthServerConfig] = {}
    if isinstance(payload, dict):
        for name, server_config in payload.items():
            normalized_name = str(name).strip()
            if normalized_name.lower() == "auth_mode":
                continue
            if not isinstance(name, str) or not isinstance(server_config, dict):
                raise RuntimeError(f"OAuth server object entries must map names to OAuth server objects ({source}).")
            normalized_name = name.strip()
            if not normalized_name:
                raise RuntimeError("OAuth server names must not be empty.")
            registry[normalized_name] = _normalize_oauth_server(normalized_name, server_config)
    elif isinstance(payload, list):
        for index, server_config in enumerate(payload):
            if not isinstance(server_config, dict):
                raise RuntimeError(f"OAuth server list entry at index {index} must be an object ({source}).")
            name = str(server_config.get("name") or server_config.get("id") or "").strip()
            if not name:
                raise RuntimeError(f"OAuth server list entry at index {index} is missing name ({source}).")
            registry[name] = _normalize_oauth_server(name, server_config)
    else:
        raise RuntimeError(f"OAuth server configuration must be a JSON object or JSON list ({source}).")

    if not registry:
        raise RuntimeError(f"OAuth server configuration must define at least one provider ({source}).")
    return registry, source


def load_auth_settings() -> AuthSettings:
    env_mode = os.getenv(AUTH_MODE_ENV)
    if env_mode is not None:
        mode_raw = env_mode.strip().lower()
    else:
        mode_raw = str(get_config_value(AUTH_MODE_ENV, ("auth", "mode"), "") or "").strip().lower()
    if not mode_raw:
        mode_raw = detect_auth_mode_from_oauth_payload() or "no_auth"

    if mode_raw not in {"no_auth", "oauth"}:
        raise RuntimeError(f"{AUTH_MODE_ENV} must be one of: no_auth, oauth.")

    if mode_raw == "no_auth":
        return AuthSettings(mode="no_auth", oauth_servers={}, oauth_source=None)

    oauth_servers, oauth_source = load_oauth_server_registry()
    return AuthSettings(mode="oauth", oauth_servers=oauth_servers, oauth_source=oauth_source)


AUTH_SETTINGS = load_auth_settings()
OAUTH_JWK_CLIENTS = {
    name: PyJWKClient(server_config.jwks_url)
    for name, server_config in AUTH_SETTINGS.oauth_servers.items()
}


def is_auth_enforced_path(path: str) -> bool:
    """Return whether inbound auth should be applied for a route."""
    if path == "/mcp/health":
        return False
    return path.startswith("/mcp") or path.startswith("/ufw")


def get_bearer_token_from_headers(headers: Headers) -> str:
    """Extract a Bearer token from Authorization header."""
    auth_header = headers.get("authorization", "")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header.")

    prefix = "bearer "
    if not auth_header.lower().startswith(prefix):
        raise HTTPException(status_code=401, detail="Authorization header must use Bearer token.")

    token = auth_header[len(prefix):].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token is empty.")
    return token


def _candidate_oauth_servers(token: str) -> list[OAuthServerConfig]:
    """Select candidate providers, preferring issuer-matched servers."""
    try:
        unverified_claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
        )
    except jwt_exceptions.PyJWTError:
        return list(AUTH_SETTINGS.oauth_servers.values())

    issuer = str(unverified_claims.get("iss") or "").strip()
    if not issuer:
        return list(AUTH_SETTINGS.oauth_servers.values())

    matched = [server for server in AUTH_SETTINGS.oauth_servers.values() if server.issuer == issuer]
    return matched or list(AUTH_SETTINGS.oauth_servers.values())


def validate_oauth_bearer_token(token: str) -> dict[str, Any]:
    """Validate an OAuth access token against configured OAuth servers."""
    if AUTH_SETTINGS.mode != "oauth":
        raise HTTPException(status_code=500, detail="OAuth validation called while auth mode is not oauth.")

    errors: list[str] = []
    for server in _candidate_oauth_servers(token):
        jwk_client = OAUTH_JWK_CLIENTS[server.name]
        try:
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(server.algorithms),
                audience=server.audience,
                issuer=server.issuer,
            )
            if not isinstance(claims, dict):
                raise jwt_exceptions.InvalidTokenError("Claims payload is not a JSON object.")
            return claims
        except jwt_exceptions.PyJWTError as exc:
            errors.append(f"{server.name}: {exc}")

    details = "; ".join(errors) if errors else "Token did not match any configured OAuth server."
    raise HTTPException(status_code=401, detail=f"Invalid OAuth bearer token. {details}")


def sanitize_username(value: Any, default: str = "unknown") -> str:
    """Return a log-safe username token."""
    text = str(value or "").strip()
    if not text:
        return default
    # Keep the log line single-token and remove control characters.
    text = re.sub(r"\s+", "_", text)
    text = "".join(ch for ch in text if ch.isprintable() and ch not in {"\n", "\r", "\t"})
    if not text:
        return default
    if len(text) > 128:
        return text[:125] + "..."
    return text


def get_username_from_oauth_claims(claims: dict[str, Any] | None) -> str:
    """Extract a preferred username from OAuth claims."""
    if not claims:
        return ""
    for key in ("preferred_username", "name", "email", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return sanitize_username(value)
    return ""


def get_agent_identity_from_response(payload: dict[str, Any]) -> tuple[str, str]:
    """Return fallback username/source provided by downstream agent response."""
    raw_identity = payload.get("caller_identity")
    if not isinstance(raw_identity, dict):
        return "", ""

    username = sanitize_username(raw_identity.get("username"), default="")
    if not username:
        return "", ""
    source = sanitize_username(raw_identity.get("source"), default="agent_response")
    return username, source


def get_agent_ip_from_client_config(client_config: AnanClientConfig) -> str:
    """Extract host/IP from selected downstream client URL."""
    try:
        hostname = urlparse(client_config.agent_url).hostname
    except ValueError:
        return "unknown"
    return sanitize_username(hostname or "unknown")


def resolve_username_from_headers(headers: Headers) -> str:
    """Resolve caller username from trusted inbound headers when auth is disabled."""
    return sanitize_username(
        headers.get(INBOUND_AGENT_USERNAME_HEADER) or headers.get(INBOUND_CALLER_USERNAME_HEADER),
        default="",
    )


def resolve_agent_ip_from_request(request: Request) -> str:
    """Resolve caller agent IP from trusted headers, then socket address."""
    direct_header_ip = sanitize_username(request.headers.get(INBOUND_AGENT_IP_HEADER), default="")
    if direct_header_ip:
        return direct_header_ip

    forwarded_for = str(request.headers.get(INBOUND_FORWARDED_FOR_HEADER, "") or "")
    if forwarded_for:
        first_hop = forwarded_for.split(",", 1)[0].strip()
        resolved = sanitize_username(first_hop, default="")
        if resolved:
            return resolved

    if request.client and request.client.host:
        return sanitize_username(request.client.host, default="unknown")

    return "unknown"


def ensure_request_identity_context() -> RequestIdentityContext:
    """Return an initialized per-request identity context."""
    context = REQUEST_IDENTITY_CONTEXT.get()
    if context is None:
        context = {}
        REQUEST_IDENTITY_CONTEXT.set(context)
    return context


def get_resolved_request_identity(request: Request) -> tuple[str, str, str]:
    """Resolve final username/source/agent_ip for logging and propagation."""
    username = sanitize_username(getattr(request.state, "caller_username", ""), default="")
    source = sanitize_username(getattr(request.state, "caller_identity_source", ""), default="")
    agent_ip = sanitize_username(getattr(request.state, "agent_ip", ""), default="")

    if not username:
        username = "anonymous" if AUTH_SETTINGS.mode == "no_auth" else "unknown"
    if not source:
        source = "unknown"
    if not agent_ip:
        agent_ip = "unknown"
    return username, source, agent_ip


def get_outbound_caller_identity_payload(request: Request, client_config: AnanClientConfig) -> dict[str, str]:
    """Build caller identity payload to propagate to downstream clients."""
    username = sanitize_username(getattr(request.state, "caller_username", ""), default="")
    source = sanitize_username(getattr(request.state, "caller_identity_source", ""), default="")

    if not username and AUTH_SETTINGS.mode == "no_auth":
        username = resolve_username_from_headers(request.headers)
        if username and not source:
            source = "agent_request"

    if not username:
        username = "unknown"
    if not source:
        source = "unknown"

    request_agent_ip = resolve_agent_ip_from_request(request)
    client_agent_ip = get_agent_ip_from_client_config(client_config)
    if client_agent_ip and client_agent_ip != "unknown":
        request_agent_ip = client_agent_ip

    return {
        "username": username,
        "agent_ip": request_agent_ip,
        "source": source,
    }


def _normalize_client_config(name: str, raw_config: dict[str, Any]) -> AnanClientConfig:
    agent_url = raw_config.get("agent_url") or raw_config.get("UFW_AGENT_URL") or raw_config.get("url") or raw_config.get("base_url")
    api_key = raw_config.get("api_key") or raw_config.get("ANAN_CLIENT_API_KEY") or raw_config.get("client_api_key")
    ssl_verify = raw_config.get("ssl_verify")
    if ssl_verify is None:
        ssl_verify = raw_config.get("UFW_CLIENT_SSL_VERIFY")
    if agent_url is None:
        agent_url = UFW_AGENT_URL if name == DEFAULT_ANAN_CLIENT_NAME else None
    if api_key is None and name == DEFAULT_ANAN_CLIENT_NAME:
        api_key = get_anan_client_api_key()
    return AnanClientConfig(
        name=name,
        agent_url=str(agent_url) if agent_url is not None else "",
        api_key=api_key,
        ssl_verify=_parse_bool(ssl_verify, default=True),
        commands=None,
    )


def _normalize_string_list(value: Any) -> tuple[str, ...]:
    normalized = _normalize_command_names(value)
    if normalized is None:
        return ()
    return normalized


def _normalize_registered_command(name: str, raw_config: dict[str, Any]) -> RegisteredCommand:
    normalized_name = name.strip()
    if not normalized_name:
        raise HTTPException(status_code=500, detail="Registered command names must not be empty.")

    description = str(raw_config.get("description") or "").strip()
    if not description:
        raise HTTPException(status_code=500, detail=f"Registered command '{normalized_name}' is missing description.")

    binary = str(raw_config.get("binary") or "").strip()
    if not binary or not binary.startswith("/"):
        raise HTTPException(status_code=500, detail=f"Registered command '{normalized_name}' must define an absolute binary path.")

    fixed_args = _normalize_fixed_args(raw_config.get("fixed_args"))
    aliases = _normalize_string_list(raw_config.get("aliases"))
    examples = _normalize_string_list(raw_config.get("examples"))
    allow_extra_args = raw_config.get("allow_extra_args", False)
    if not isinstance(allow_extra_args, bool):
        raise HTTPException(status_code=500, detail=f"Registered command '{normalized_name}' allow_extra_args must be boolean.")

    return RegisteredCommand(
        name=normalized_name,
        description=description,
        binary=binary,
        fixed_args=tuple(fixed_args),
        aliases=aliases,
        allow_extra_args=allow_extra_args,
        examples=examples,
    )


def _serialize_registered_command(command: RegisteredCommand) -> dict[str, Any]:
    return {
        "description": command.description,
        "aliases": list(command.aliases),
        "binary": command.binary,
        "fixed_args": list(command.fixed_args),
        "allow_extra_args": command.allow_extra_args,
        "examples": list(command.examples),
    }


def _default_registered_commands_payload() -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for command_name, raw_config in DEFAULT_REGISTERED_COMMANDS_RAW.items():
        command = _normalize_registered_command(command_name, raw_config)
        payload[command.name] = _serialize_registered_command(command)
    return payload


def _default_server_state_payload() -> dict[str, Any]:
    return {
        "clients": {},
        "registered_commands": _default_registered_commands_payload(),
    }


def _coerce_server_state_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Server state file must contain a JSON object.")

    if not payload:
        return _default_server_state_payload()

    if "clients" not in payload and "registered_commands" not in payload:
        return {
            "clients": payload,
            "registered_commands": _default_registered_commands_payload(),
        }

    clients_payload = payload.get("clients", {})
    if not isinstance(clients_payload, dict):
        raise HTTPException(status_code=500, detail="Server state 'clients' must be a JSON object.")

    registered_payload = payload.get("registered_commands")
    if registered_payload is None:
        normalized_registered_payload = _default_registered_commands_payload()
    else:
        if not isinstance(registered_payload, dict):
            raise HTTPException(status_code=500, detail="Server state 'registered_commands' must be a JSON object.")
        normalized_registered_payload: dict[str, Any] = {}
        for command_name, raw_config in registered_payload.items():
            if not isinstance(command_name, str) or not isinstance(raw_config, dict):
                raise HTTPException(status_code=500, detail="Registered commands must map names to command objects.")
            command = _normalize_registered_command(command_name, raw_config)
            normalized_registered_payload[command.name] = _serialize_registered_command(command)

    return {
        "clients": clients_payload,
        "registered_commands": normalized_registered_payload,
    }


def get_anan_clients_file_path() -> str:
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "anan_clients.json",
    )
    return str(get_config_value(ANAN_CLIENTS_FILE_ENV, ("clients", "file"), default_path) or default_path)


def _load_server_state_payload_for_update(file_path: str) -> dict[str, Any]:
    """Load raw server state for updates, creating defaults when the file is missing."""
    if not os.path.exists(file_path):
        return _default_server_state_payload()

    try:
        with open(file_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid JSON in {file_path}.",
        ) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to read server state: {file_path}",
        ) from exc

    return _coerce_server_state_payload(payload)


def _write_server_state_payload(file_path: str, payload: dict[str, Any]) -> None:
    """Persist server state atomically to avoid partial writes."""
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    existing_stat: os.stat_result | None = None
    if os.path.exists(file_path):
        try:
            existing_stat = os.stat(file_path)
        except OSError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Unable to read server list metadata: {file_path}",
            ) from exc

    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory or None, delete=False) as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            temp_path = handle.name

        if existing_stat is not None:
            # Keep ownership/mode stable across atomic replace.
            os.chmod(temp_path, stat.S_IMODE(existing_stat.st_mode))
            os.chown(temp_path, existing_stat.st_uid, existing_stat.st_gid)

        os.replace(temp_path, file_path)
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to update server state: {file_path}",
        ) from exc


def _load_anan_clients_from_file(file_path: str) -> dict[str, AnanClientConfig]:
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid JSON in {file_path}.",
        ) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to read server state: {file_path}",
        ) from exc

    state_payload = _coerce_server_state_payload(payload)
    clients_payload = state_payload.get("clients", {})
    if not clients_payload:
        return {}

    registry: dict[str, AnanClientConfig] = {}
    for name, client_config in clients_payload.items():
        if not isinstance(name, str) or not isinstance(client_config, dict):
            raise HTTPException(
                status_code=500,
                detail=f"{file_path} clients must map names to configuration objects.",
            )
        registry[name] = _normalize_client_config(name, client_config)
    return registry


def get_registered_command_registry() -> dict[str, RegisteredCommand]:
    file_path = get_anan_clients_file_path()
    state_payload = _load_server_state_payload_for_update(file_path)
    registered_payload = state_payload.get("registered_commands", {})

    registry: dict[str, RegisteredCommand] = {}
    for command_name, raw_config in registered_payload.items():
        if not isinstance(command_name, str) or not isinstance(raw_config, dict):
            raise HTTPException(status_code=500, detail="Registered commands must map names to command objects.")
        command = _normalize_registered_command(command_name, raw_config)
        registry[command.name] = command
    return registry


def get_registered_command(command_name: str) -> RegisteredCommand:
    registry = get_registered_command_registry()
    try:
        return registry[command_name]
    except KeyError as exc:
        available = ", ".join(sorted(registry))
        raise HTTPException(status_code=400, detail=f"Unknown command '{command_name}'. Registered commands: {available}") from exc


def _registered_command_names() -> tuple[str, ...]:
    return tuple(get_registered_command_registry().keys())


def get_anan_client_registry() -> dict[str, AnanClientConfig]:
    configured_clients_file = os.getenv(ANAN_CLIENTS_FILE_ENV)
    if configured_clients_file and configured_clients_file.strip():
        return _load_anan_clients_from_file(configured_clients_file)

    raw_clients = os.getenv(ANAN_CLIENTS_ENV)
    if raw_clients and raw_clients.strip():
        try:
            payload = json.loads(raw_clients)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail=f"Invalid {ANAN_CLIENTS_ENV} configuration.") from exc

        if not isinstance(payload, dict) or not payload:
            raise HTTPException(status_code=500, detail=f"{ANAN_CLIENTS_ENV} must be a JSON object with at least one client.")

        registry: dict[str, AnanClientConfig] = {}
        for name, client_config in payload.items():
            if not isinstance(name, str) or not isinstance(client_config, dict):
                raise HTTPException(status_code=500, detail=f"{ANAN_CLIENTS_ENV} must map client names to configuration objects.")
            registry[name] = _normalize_client_config(name, client_config)
        return registry

    configured_clients_file = get_config_value(ANAN_CLIENTS_FILE_ENV, ("clients", "file"), "")
    if configured_clients_file:
        return _load_anan_clients_from_file(str(configured_clients_file))

    raw_clients = get_config_value(ANAN_CLIENTS_ENV, ("clients", "anan_clients"), None)
    if raw_clients is not None:
        payload = raw_clients if isinstance(raw_clients, dict) else json.loads(str(raw_clients))
        if not isinstance(payload, dict) or not payload:
            raise HTTPException(status_code=500, detail=f"{ANAN_CLIENTS_ENV} must be a JSON object with at least one client.")

        registry: dict[str, AnanClientConfig] = {}
        for name, client_config in payload.items():
            if not isinstance(name, str) or not isinstance(client_config, dict):
                raise HTTPException(status_code=500, detail=f"{ANAN_CLIENTS_ENV} must map client names to configuration objects.")
            registry[name] = _normalize_client_config(name, client_config)
        return registry

    default_file_path = get_anan_clients_file_path()
    file_registry = _load_anan_clients_from_file(default_file_path)
    if file_registry:
        return file_registry

    return {
        DEFAULT_ANAN_CLIENT_NAME: _normalize_client_config(
            DEFAULT_ANAN_CLIENT_NAME,
            {
                    "agent_url": UFW_AGENT_URL,
                    "api_key": get_anan_client_api_key(),
                    "ssl_verify": os.getenv("UFW_CLIENT_SSL_VERIFY", "true"),
                },
        )
    }


def get_available_anan_client_names() -> list[str]:
    return sorted(get_anan_client_registry().keys())


def get_anan_client_config(client_name: str | None = None) -> AnanClientConfig:
    registry = get_anan_client_registry()
    if client_name is None:
        if len(registry) == 1:
            return next(iter(registry.values()))
        if DEFAULT_ANAN_CLIENT_NAME in registry:
            return registry[DEFAULT_ANAN_CLIENT_NAME]
        raise HTTPException(
            status_code=400,
            detail="server name is required when multiple servers are registered.",
        )

    try:
        return registry[client_name]
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown server '{client_name}'. Available servers: {', '.join(sorted(registry))}",
        ) from exc


def get_server_config() -> tuple[str, int]:
    """Return the configured host and port for the HTTP server."""
    host = str(get_config_value("HOST", ("server", "host"), "0.0.0.0") or "0.0.0.0")
    port = int(get_config_value("PORT", ("server", "port"), "8000"))
    return host, port


def get_request_log_file() -> str:
    """Return the file path used for request logging."""
    default_log_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "logs",
        "request.log",
    )
    return str(get_config_value("REQUEST_LOG_FILE", ("server", "request_log_file"), default_log_file) or default_log_file)


def get_request_log_include_response_body() -> bool:
    """Return whether response body previews should be included in request logs."""
    value = get_config_value("REQUEST_LOG_INCLUDE_RESPONSE_BODY", ("server", "request_log_include_response_body"), "false")
    return _parse_bool(value, default=False)


def get_server_https_config() -> tuple[bool, str | None, str | None]:
    """Return whether HTTPS should be enabled and the configured certificate paths."""
    enabled = _parse_bool(get_config_value("HTTPS_ENABLED", ("server", "https_enabled"), "true"), default=True)
    certfile = get_config_value("SSL_CERTFILE", ("server", "ssl_certfile"), None)
    keyfile = get_config_value("SSL_KEYFILE", ("server", "ssl_keyfile"), None)
    return enabled, str(certfile) if certfile else None, str(keyfile) if keyfile else None


def install_openssl_if_missing() -> None:
    """Install OpenSSL automatically when the system package is missing."""
    if shutil.which("openssl"):
        return

    package_cmds: list[list[str]] = []

    if shutil.which("apt-get"):
        apt_prefix = ["sudo"] if shutil.which("sudo") and os.geteuid() != 0 else []
        package_cmds = [
            apt_prefix + ["apt-get", "update"],
            apt_prefix + ["apt-get", "install", "-y", "openssl"],
        ]
    elif shutil.which("dnf"):
        dnf_prefix = ["sudo"] if shutil.which("sudo") and os.geteuid() != 0 else []
        package_cmds = [
            dnf_prefix + ["dnf", "install", "-y", "openssl"],
        ]
    elif shutil.which("yum"):
        yum_prefix = ["sudo"] if shutil.which("sudo") and os.geteuid() != 0 else []
        package_cmds = [
            yum_prefix + ["yum", "install", "-y", "openssl"],
        ]
    elif shutil.which("apk"):
        apk_prefix = ["sudo"] if shutil.which("sudo") and os.geteuid() != 0 else []
        package_cmds = [
            apk_prefix + ["apk", "add", "--no-cache", "openssl"],
        ]
    elif shutil.which("brew"):
        brew_prefix = ["sudo"] if shutil.which("sudo") and os.geteuid() != 0 else []
        package_cmds = [
            brew_prefix + ["brew", "install", "openssl"],
        ]

    if not package_cmds:
        raise RuntimeError("OpenSSL is required to generate HTTPS certificates and could not be installed automatically on this system.")

    for command in package_cmds:
        subprocess.run(command, check=True, capture_output=True, text=True)

    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL installation was attempted but the binary is still unavailable.")


def ensure_https_certificates() -> tuple[str, str]:
    """Ensure SSL certificate and key files exist for HTTPS startup."""
    enabled, certfile, keyfile = get_server_https_config()
    if not enabled:
        raise RuntimeError("HTTPS is disabled.")

    cert_dir = str(get_config_value("SSL_DIR", ("server", "ssl_dir"), os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs")) or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs"))
    os.makedirs(cert_dir, exist_ok=True)
    certfile = certfile or get_config_value("SSL_CERTFILE", ("server", "ssl_certfile"), os.path.join(cert_dir, "server.crt"))
    keyfile = keyfile or get_config_value("SSL_KEYFILE", ("server", "ssl_keyfile"), os.path.join(cert_dir, "server.key"))
    certfile = str(certfile or os.path.join(cert_dir, "server.crt"))
    keyfile = str(keyfile or os.path.join(cert_dir, "server.key"))

    if os.path.exists(certfile) and os.path.exists(keyfile):
        return certfile, keyfile

    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        install_openssl_if_missing()
        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            raise RuntimeError("OpenSSL is required to generate HTTPS certificates.")

    subprocess.run(
        [
            openssl_bin,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "365",
            "-subj",
            "/CN=localhost",
            "-keyout",
            keyfile,
            "-out",
            certfile,
        ],
        check=True,
        capture_output=True,
    )
    return certfile, keyfile


def get_uvicorn_run_kwargs() -> dict[str, Any]:
    """Return the keyword arguments used to launch Uvicorn."""
    host, port = get_server_config()
    kwargs: dict[str, Any] = {"host": host, "port": port}
    enabled, _, _ = get_server_https_config()
    if enabled:
        certfile, keyfile = ensure_https_certificates()
        kwargs["ssl_certfile"] = certfile
        kwargs["ssl_keyfile"] = keyfile
    return kwargs


def get_headers_summary(headers: Headers) -> str:
    """Return a compact representation of selected request headers."""
    selected = {name: headers.get(name) for name in ["user-agent", "host", "x-forwarded-for"] if headers.get(name)}
    if not selected:
        return "headers=none"
    return "headers=" + ",".join(f"{key}={value}" for key, value in selected.items())


def get_ssl_context(verify_ssl: bool | None = None) -> ssl.SSLContext:
    """Create an SSL context that can optionally skip certificate verification."""
    if verify_ssl is None:
        # Prefer the new `clients.ufw_client_ssl_verify` config, fall back to the old
        # `agent.ufw_agent_ssl_verify` for backwards compatibility, then default to true.
        raw = get_config_value("UFW_CLIENT_SSL_VERIFY", ("clients", "ufw_client_ssl_verify"), None)
        if raw is None:
            raw = get_config_value("UFW_CLIENT_SSL_VERIFY", ("agent", "ufw_agent_ssl_verify"), "true")
        verify_ssl = _parse_bool(raw, default=True)

    if not verify_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    return ssl.create_default_context()


def get_body_preview(request: Request) -> str:
    """Return a short preview of the request body when available."""
    if request.method not in {"POST", "PUT", "PATCH"}:
        return "body=none"

    try:
        body = request._body
    except AttributeError:
        return "body=none"

    if not body:
        return "body=empty"

    preview = body.decode("utf-8", errors="replace").strip()
    if len(preview) > 120:
        preview = preview[:117] + "..."
    return f"body={preview}"


def get_response_body_preview(response: Any) -> str:
    """Return a short preview of the response body when logging is enabled."""
    if not get_request_log_include_response_body():
        return "response_body=disabled"

    if response is None:
        return "response_body=none"

    body = getattr(response, "body", None)
    if body is None:
        return "response_body=streaming_or_unavailable"

    if isinstance(body, bytes):
        preview = body.decode("utf-8", errors="replace").strip()
    else:
        preview = str(body).strip()

    if not preview:
        return "response_body=empty"

    if len(preview) > 120:
        preview = preview[:117] + "..."
    return f"response_body={preview}"


def classify_auth_failure_detail(detail: str) -> str:
    """Map auth error detail text to a stable machine-readable reason."""
    normalized = (detail or "").strip()
    if normalized == "Missing Authorization header.":
        return "missing_authorization_header"
    if normalized == "Authorization header must use Bearer token.":
        return "invalid_authorization_scheme"
    if normalized == "Bearer token is empty.":
        return "empty_bearer_token"
    if normalized.startswith("Invalid OAuth bearer token."):
        return "invalid_oauth_bearer_token"
    return "auth_failed"


def extract_auth_failure_summary(detail: str) -> str:
    """Extract a concise auth failure summary suitable for request logs."""
    normalized = (detail or "").strip()
    if not normalized:
        return ""

    prefix = "Invalid OAuth bearer token."
    if normalized.startswith(prefix):
        summary = normalized[len(prefix):].strip()
    else:
        summary = normalized

    if not summary:
        return ""
    summary = "_".join(summary.split())
    if len(summary) > 180:
        summary = summary[:177] + "..."
    return summary


def get_auth_failure_reason(status_code: int, response: Any) -> str:
    """Return a normalized auth failure reason for 401 responses."""
    if status_code != 401 or response is None:
        return ""

    body = getattr(response, "body", None)
    if not body:
        return ""

    if isinstance(body, bytes):
        payload_text = body.decode("utf-8", errors="replace")
    else:
        payload_text = str(body)

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return ""

    detail = str(payload.get("detail") or "").strip()
    if not detail:
        return ""
    return classify_auth_failure_detail(detail)


def initialize_request_log() -> None:
    """Reset the request log file at server startup so it doesn't grow indefinitely."""
    log_file = get_request_log_file()
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    try:
        with open(log_file, "w", encoding="utf-8"):
            pass
    except OSError:
        pass


def append_request_log(request: Request, status_code: int, response: Any = None, elapsed_ms: float | None = None) -> None:
    """Append an incoming request entry to the configured log file."""
    log_file = get_request_log_file()
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    client_ip = request.client.host if request.client else "unknown"
    query_string = request.url.query or ""
    request_path = request.url.path
    response_size = "unknown"
    if response is not None:
        response_size = getattr(response, "headers", {}).get("content-length", "unknown")
    auth_failure_reason = str(getattr(request.state, "auth_failure_reason", "") or "")
    if not auth_failure_reason:
        auth_failure_reason = get_auth_failure_reason(status_code, response)
    auth_failure_text = f" auth_failure={auth_failure_reason}" if auth_failure_reason else ""
    auth_failure_detail = str(getattr(request.state, "auth_failure_detail", "") or "")
    auth_failure_detail_text = f" auth_failure_detail={auth_failure_detail}" if auth_failure_detail else ""
    resolved_username, resolved_source, resolved_agent_ip = get_resolved_request_identity(request)
    identity_text = (
        f" user={resolved_username}"
        f" user_source={resolved_source}"
        f" agent_ip={resolved_agent_ip}"
    )

    try:
        with open(log_file, "a", encoding="utf-8") as handle:
            timestamp = datetime.now(timezone.utc).isoformat()
            elapsed_text = f" elapsed_ms={elapsed_ms:.2f}" if elapsed_ms is not None else ""
            handle.write(
                f"{timestamp} ip={client_ip} method={request.method} path={request_path}"
                f" query={query_string} status={status_code} size={response_size}"
                f"{elapsed_text} {get_headers_summary(request.headers)}"
                f" {get_body_preview(request)} {get_response_body_preview(response)}"
                f"{identity_text}{auth_failure_text}{auth_failure_detail_text}\n"
            )
    except OSError:
        pass


def _normalize_fixed_args(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise HTTPException(status_code=400, detail="fixed_args must be a list of strings.")
    return [item.strip() for item in value]


def _policy_command_payload(command: RegisteredCommand) -> dict[str, Any]:
    return {
        "command_name": command.name,
        "binary": command.binary,
        "fixed_args": list(command.fixed_args),
        "allow_extra_args": command.allow_extra_args,
    }


def _registered_command_response(command: RegisteredCommand, available_on_client: bool = True) -> dict[str, Any]:
    return {
        "name": command.name,
        "description": command.description,
        "aliases": list(command.aliases),
        "examples": list(command.examples),
        "read_only": True,
        "supports_args": command.allow_extra_args,
        "available_on_client": available_on_client,
    }


def _list_client_command_metadata(client_config: AnanClientConfig) -> dict[str, dict[str, Any]]:
    endpoint = f"{client_config.agent_url.rstrip('/')}/cli/list"
    payload = call_client_api(
        client_config=client_config,
        endpoint=endpoint,
        method="GET",
        timeout=30,
    )

    metadata_by_name: dict[str, dict[str, Any]] = {}
    raw_commands = payload.get("commands")
    if isinstance(raw_commands, list):
        for item in raw_commands:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                metadata_by_name[name.strip()] = item
    return metadata_by_name


def _push_registered_command_to_client(client_config: AnanClientConfig, command: RegisteredCommand) -> dict[str, Any]:
    endpoint = f"{client_config.agent_url.rstrip('/')}/policy/commands"
    return call_client_api(
        client_config=client_config,
        endpoint=endpoint,
        method="POST",
        data=_policy_command_payload(command),
        timeout=30,
    )


def _remove_registered_command_from_client(client_config: AnanClientConfig, command_name: str) -> dict[str, Any]:
    endpoint = f"{client_config.agent_url.rstrip('/')}/policy/commands/{quote(command_name, safe='')}"
    return call_client_api(
        client_config=client_config,
        endpoint=endpoint,
        method="DELETE",
        timeout=30,
    )


def _sync_registered_commands_to_client(client_config: AnanClientConfig) -> dict[str, Any]:
    registry = get_registered_command_registry()
    pushed: list[str] = []
    push_failures: list[dict[str, Any]] = []

    for command in registry.values():
        try:
            _push_registered_command_to_client(client_config, command)
            pushed.append(command.name)
        except HTTPException as exc:
            push_failures.append(
                {
                    "command_name": command.name,
                    "status_code": exc.status_code,
                    "detail": str(exc.detail),
                }
            )

    metadata_before_cleanup = _list_client_command_metadata(client_config)
    extra_client_commands = sorted(name for name in metadata_before_cleanup if name not in registry)
    removed: list[str] = []
    remove_failures: list[dict[str, Any]] = []
    for command_name in extra_client_commands:
        try:
            _remove_registered_command_from_client(client_config, command_name)
            removed.append(command_name)
        except HTTPException as exc:
            remove_failures.append(
                {
                    "command_name": command_name,
                    "status_code": exc.status_code,
                    "detail": str(exc.detail),
                }
            )

    metadata_after_sync = _list_client_command_metadata(client_config)
    available_commands = tuple(name for name in registry if name in metadata_after_sync)
    unavailable_commands = tuple(name for name in registry if name not in metadata_after_sync)

    return {
        "available_commands": available_commands,
        "unavailable_commands": unavailable_commands,
        "metadata_by_name": metadata_after_sync,
        "pushed_commands": tuple(pushed),
        "removed_commands": tuple(removed),
        "push_failures": push_failures,
        "remove_failures": remove_failures,
    }


def list_readonly_cli_commands(client_name: str | None = None) -> dict[str, Any]:
    """Return registered readonly commands available on the selected client after sync."""
    client_config = get_anan_client_config(client_name)
    registry = get_registered_command_registry()
    sync_result = _sync_registered_commands_to_client(client_config)

    commands: list[dict[str, Any]] = []
    for command_name in sync_result["available_commands"]:
        commands.append(_registered_command_response(registry[command_name], available_on_client=True))

    return {
        "commands": commands,
        "count": len(commands),
        "mode": "mvp_non_admin" if MVP_NON_ADMIN_MODE else "standard",
        "synchronized": True,
        "unavailable_on_client": list(sync_result["unavailable_commands"]),
        "push_failures": sync_result["push_failures"],
        "remove_failures": sync_result["remove_failures"],
    }


def run_readonly_cli_command(command_name: str, client_name: str | None = None) -> dict[str, Any]:
    """Execute one readonly command registered on the MCP server and synchronized to the client."""
    normalized_name = command_name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="command_name must not be empty.")

    get_registered_command(normalized_name)

    client_config = get_anan_client_config(client_name)
    sync_result = _sync_registered_commands_to_client(client_config)
    if normalized_name not in sync_result["available_commands"]:
        failure_details = [
            item["detail"]
            for item in sync_result["push_failures"]
            if item.get("command_name") == normalized_name
        ]
        detail = failure_details[0] if failure_details else f"Command '{normalized_name}' is not available on client '{client_config.name}' after sync."
        raise HTTPException(status_code=409, detail=detail)

    endpoint = f"{client_config.agent_url.rstrip('/')}/commands/run"
    return call_client_api(
        client_config=client_config,
        endpoint=endpoint,
        method="POST",
        data={"command_name": normalized_name},
        timeout=30,
    )


def call_client_api(
    client_config: AnanClientConfig,
    endpoint: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Call a client API endpoint and return a JSON object response."""
    if not client_config.api_key:
        raise HTTPException(status_code=500, detail=f"Server API key is not configured for '{client_config.name}'.")

    identity_context = REQUEST_IDENTITY_CONTEXT.get()
    caller_identity: dict[str, str] | None = None
    request_data_payload = data
    if identity_context is not None and isinstance(identity_context.get("request"), Request):
        request = identity_context["request"]
        caller_identity = get_outbound_caller_identity_payload(request, client_config)

        if isinstance(request_data_payload, dict):
            request_data_payload = dict(request_data_payload)
            request_data_payload.setdefault("caller_identity", caller_identity)

        if not getattr(request.state, "agent_ip", "") or getattr(request.state, "agent_ip", "") == "unknown":
            request.state.agent_ip = caller_identity.get("agent_ip", "unknown")

    request_data = json.dumps(request_data_payload).encode("utf-8") if request_data_payload is not None else None
    headers = {"X-API-Key": client_config.api_key}
    if caller_identity is not None:
        headers["X-Caller-Username"] = caller_identity["username"]
        headers["X-Caller-Source"] = caller_identity["source"]
        headers["X-Agent-IP"] = caller_identity["agent_ip"]
    if request_data is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        endpoint,
        data=request_data,
        headers=headers,
        method=method,
    )

    try:
        context = get_ssl_context(client_config.ssl_verify)
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to reach server '{client_config.name}': {exc}") from exc
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=exc.code, detail=detail) from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail="Client agent returned invalid JSON.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Client agent returned an invalid response.")

    if identity_context is not None and isinstance(identity_context.get("request"), Request):
        request = identity_context["request"]
        oauth_username = sanitize_username(getattr(request.state, "caller_username", ""), default="")
        oauth_source = sanitize_username(getattr(request.state, "caller_identity_source", ""), default="")
        raw_agent_identity = payload.get("caller_identity") if isinstance(payload, dict) else None
        if isinstance(raw_agent_identity, dict):
            agent_ip = sanitize_username(raw_agent_identity.get("agent_ip"), default="")
            if agent_ip:
                request.state.agent_ip = agent_ip
        fallback_username, fallback_source = get_agent_identity_from_response(payload)
        if not oauth_username and fallback_username:
            request.state.caller_username = fallback_username
            request.state.caller_identity_source = fallback_source or "agent_response"
        elif oauth_username:
            request.state.caller_username = oauth_username
            request.state.caller_identity_source = oauth_source or "oauth_claim"

    return payload


def get_ip_address_from_url(url: str) -> str | None:
    """Extract IP address from URL when host is already an IP literal."""
    try:
        hostname = urlparse(url).hostname
    except ValueError:
        return None

    if not hostname:
        return None

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return None

@mcp_tool("list_servers")
def list_servers() -> dict[str, Any]:
    """List all registered servers with their names and IP addresses."""
    registry = get_anan_client_registry()
    default_name = None
    if DEFAULT_ANAN_CLIENT_NAME in registry:
        default_name = DEFAULT_ANAN_CLIENT_NAME

    return {
        "default": default_name,
        "clients": [
            {
                "name": client.name,
                "agent_ip": get_ip_address_from_url(client.agent_url),
            }
            for client in registry.values()
        ],
    }

# Discovery-first tool: call this before readonly_cli_run to fetch the exact command names 
# currently available on the selected client after sync.
@mcp_tool("readonly_cli_list")
def readonly_cli_list(client_name: str | None = None) -> dict[str, Any]:
    """
    1. List readonly commands available in server.
    2.  Use this tool to find out possible commands that are not exposed as tools but can be executed on registered servers
    3. This maps to: GET /cli/list (filtered by server allowlist)
    """
    return list_readonly_cli_commands(client_name=client_name)


@mcp_tool("readonly_cli_run")
def readonly_cli_run(command_name: str, client_name: str | None = None) -> dict[str, Any]:
    """Execute one readonly command discovered from readonly_cli_list.

When to call:
- Call this only after readonly_cli_list and only with an exact command name from that response.
- If execution fails because command availability changed, call readonly_cli_list again and retry with a listed name.

Input rules:
- command_name must exactly match one item from readonly_cli_list()["commands"][].name.
- client_name should match the client used for discovery to avoid mismatched availability.

What this does:
- Re-syncs server-registered commands to the selected client before execution.
- Runs: POST /commands/run with {"command_name": "<exact_name>"}.

Notes:
- Unknown command_name values are rejected by the MCP server.
- Commands not available on the client after sync return a conflict error with failure detail.
"""
    return run_readonly_cli_command(command_name=command_name, client_name=client_name)


@mcp_tool("register_server")
@mcp_tool("register_client")
def register_server(
    server_name: str | None = None,
    server_host: str = "",
    server_port: int = 443,
    api_key: str = "",
    verify_ssl_certificate: bool | None = None,
) -> dict[str, Any]:
    """Register a new server and push the global command registry to it.

    Expected parameters:
    - server_name: Unique name used to reference the server in MCP tools.
    - server_host: Server IP address or DNS hostname (without protocol or port).
    - server_port: HTTPS port exposed by the client API (1-65535).
    - api_key: API key sent as X-API-Key to authenticate requests.
    - verify_ssl_certificate: Optional explicit override. If omitted, the server's
      `clients.ufw_client_ssl_verify` / `UFW_CLIENT_SSL_VERIFY` setting is used.

    Behavior:
    - Builds the client URL as https://{agent_host}:{agent_port}.
    - Calls GET /system/hostname to confirm the client is reachable.
    - Persists the client inventory entry.
    - Pushes the current global registered command set to the new client.
    """
    normalized_host = server_host.strip()
    normalized_key = api_key.strip()
    requested_name = server_name.strip() if isinstance(server_name, str) else ""
    normalized_name = requested_name or normalized_host

    if not normalized_name:
        raise HTTPException(status_code=400, detail="client_name must not be empty.")
    if not normalized_host:
        raise HTTPException(status_code=400, detail="server_host must not be empty.")
    if not isinstance(server_port, int) or not (1 <= server_port <= 65535):
        raise HTTPException(status_code=400, detail="server_port must be between 1 and 65535.")
    if not normalized_key:
        raise HTTPException(status_code=400, detail="api_key must not be empty.")

    configured_verify_ssl = get_config_value("UFW_CLIENT_SSL_VERIFY", ("clients", "ufw_client_ssl_verify"), None)
    if configured_verify_ssl is None:
        configured_verify_ssl = get_config_value("UFW_CLIENT_SSL_VERIFY", ("agent", "ufw_agent_ssl_verify"), "true")
    effective_verify_ssl = _parse_bool(configured_verify_ssl, default=True) if verify_ssl_certificate is None else bool(verify_ssl_certificate)

    normalized_url = f"https://{normalized_host}:{server_port}"

    file_path = get_anan_clients_file_path()
    state_payload = _load_server_state_payload_for_update(file_path)
    clients_payload = state_payload.get("clients", {})
    if normalized_name in clients_payload:
        raise HTTPException(status_code=409, detail=f"Server '{normalized_name}' is already registered.")

    client_config = AnanClientConfig(
        name=normalized_name,
        agent_url=normalized_url,
        api_key=normalized_key,
        ssl_verify=effective_verify_ssl,
    )
    hostname_response = call_client_api(
        client_config=client_config,
        endpoint=f"{normalized_url.rstrip('/')}/system/hostname",
        method="GET",
        timeout=15,
    )

    hostname = hostname_response.get("hostname")
    if not isinstance(hostname, str) or not hostname.strip():
        raise HTTPException(status_code=502, detail="Client did not return a valid hostname.")

    clients_payload[normalized_name] = {
        "agent_url": normalized_url,
        "api_key": normalized_key,
        "ssl_verify": bool(effective_verify_ssl),
    }

    state_payload["clients"] = clients_payload
    _write_server_state_payload(file_path, state_payload)

    sync_summary: dict[str, Any]
    try:
        sync_summary = _sync_registered_commands_to_client(client_config)
    except HTTPException as exc:
        sync_summary = {
            "available_commands": (),
            "unavailable_commands": tuple(_registered_command_names()),
            "push_failures": [{"command_name": "*", "status_code": exc.status_code, "detail": str(exc.detail)}],
            "remove_failures": [],
        }

    return {
        "status": "registered",
        "client": {
            "name": normalized_name,
            "agent_host": normalized_host,
            "agent_port": server_port,
            "agent_url": normalized_url,
            "ssl_verify": bool(effective_verify_ssl),
            "hostname": hostname,
        },
        "sync": {
            "available_commands": list(sync_summary["available_commands"]),
            "unavailable_commands": list(sync_summary["unavailable_commands"]),
            "push_failures": sync_summary["push_failures"],
            "remove_failures": sync_summary["remove_failures"],
        },
        "clients_file": file_path,
    }


register_client = register_server


@mcp_tool("remove_server")
def remove_server(client_name: str) -> dict[str, Any]:
    """Remove an existing server entry from anan_clients.json.

    Expected parameters:
    - client_name: Registered server name to delete.
    """
    normalized_name = client_name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="client_name must not be empty.")

    file_path = get_anan_clients_file_path()
    state_payload = _load_server_state_payload_for_update(file_path)
    clients_payload = state_payload.get("clients", {})

    removed = clients_payload.pop(normalized_name, None)
    if removed is None:
        raise HTTPException(status_code=404, detail=f"Server '{normalized_name}' is not registered.")

    state_payload["clients"] = clients_payload
    _write_server_state_payload(file_path, state_payload)

    return {
        "status": "removed",
        "client_name": normalized_name,
        "clients_file": file_path,
    }


@mcp_tool("add_cli_or_command")
def add_command_or_cli(
    command_name: str,
    binary: str,
    description: str | None = None,
    aliases: list[str] | None = None,
    fixed_args: list[str] | None = None,
    allow_extra_args: bool = False,
    sync_with_clients: bool = True,
) -> dict[str, Any]:
    """Add or update a global registered command and push it to all registered clients.

    This function can be used to add a new command or CLI to all registered clients,
    and does not require the name of a specific client or server. 
    Always present tool schema and then ask user for parameters

    Required schema:
    - command_name: str (non-empty semantic id)
    - binary: str (absolute path, must start with "/")

    Optional schema:
    - description: str (defaults to command_name with underscores replaced by spaces)
    - aliases: list[str]
    - fixed_args: list[str]
    - allow_extra_args: bool (default: false)
    - sync_with_clients: bool (default: true)

    Important:
    - Send arrays as native JSON arrays, not JSON-encoded strings.
    - Invalid: aliases='["a", "b"]', fixed_args='["-h"]'
    - Valid: aliases=["a", "b"], fixed_args=["-h"]

    Valid example payload:
    {
        "command_name": "check_pending_upgrades",
        "binary": "/usr/bin/apt",
        "description": "Check for pending package upgrades",
        "aliases": ["pending-upgrades", "check-upgrades"],
        "fixed_args": ["list", "-u"],
        "allow_extra_args": false,
        "sync_with_clients": true
    }
    """
    normalized_command_name = command_name.strip()
    normalized_binary = binary.strip()
    normalized_description = str(description or normalized_command_name.replace("_", " ")).strip()
    normalized_aliases = list(_normalize_string_list(aliases))
    normalized_fixed_args = _normalize_fixed_args(fixed_args)
    if not normalized_command_name:
        raise HTTPException(status_code=400, detail="command_name must not be empty.")
    if not normalized_binary.startswith("/"):
        raise HTTPException(status_code=400, detail="binary must be an absolute path.")
    if not normalized_description:
        raise HTTPException(status_code=400, detail="description must not be empty.")

    file_path = get_anan_clients_file_path()
    state_payload = _load_server_state_payload_for_update(file_path)
    registered_payload = state_payload.get("registered_commands", {})

    command = _normalize_registered_command(
        normalized_command_name,
        {
            "description": normalized_description,
            "aliases": normalized_aliases,
            "binary": normalized_binary,
            "fixed_args": normalized_fixed_args,
            "allow_extra_args": bool(allow_extra_args),
        },
    )
    registered_payload[command.name] = _serialize_registered_command(command)
    state_payload["registered_commands"] = registered_payload
    _write_server_state_payload(file_path, state_payload)

    sync_results: list[dict[str, Any]] = []
    if sync_with_clients:
        for registered_client in get_anan_client_registry().values():
            try:
                _push_registered_command_to_client(registered_client, command)
                sync_results.append({"client_name": registered_client.name, "status": "updated"})
            except HTTPException as exc:
                sync_results.append(
                    {
                        "client_name": registered_client.name,
                        "status": "failed",
                        "status_code": exc.status_code,
                        "detail": str(exc.detail),
                    }
                )

    return {
        "status": "updated",
        "scope": "global",
        "command": _registered_command_response(command, available_on_client=False),
        "sync_with_clients": bool(sync_with_clients),
        "client_results": sync_results,
        "clients_file": file_path,
    }


# Backward-compatible alias used by existing tests/callers.
add_client_command = add_command_or_cli


@mcp_tool("remove_client_command")
def remove_client_command(command_name: str, sync_with_clients: bool = True, client_name: str | None = None) -> dict[str, Any]:
    """Remove a global registered command and delete it from all registered clients."""
    normalized_command_name = command_name.strip()
    if not normalized_command_name:
        raise HTTPException(status_code=400, detail="command_name must not be empty.")

    file_path = get_anan_clients_file_path()
    state_payload = _load_server_state_payload_for_update(file_path)
    registered_payload = state_payload.get("registered_commands", {})
    removed = registered_payload.pop(normalized_command_name, None)
    if removed is None:
        raise HTTPException(status_code=404, detail=f"Command '{normalized_command_name}' is not registered.")

    state_payload["registered_commands"] = registered_payload
    _write_server_state_payload(file_path, state_payload)

    sync_results: list[dict[str, Any]] = []
    if sync_with_clients:
        for registered_client in get_anan_client_registry().values():
            try:
                _remove_registered_command_from_client(registered_client, normalized_command_name)
                sync_results.append({"client_name": registered_client.name, "status": "removed"})
            except HTTPException as exc:
                sync_results.append(
                    {
                        "client_name": registered_client.name,
                        "status": "failed",
                        "status_code": exc.status_code,
                        "detail": str(exc.detail),
                    }
                )

    return {
        "status": "updated",
        "scope": "global",
        "ignored_client_name": client_name,
        "command_name": normalized_command_name,
        "sync_with_clients": bool(sync_with_clients),
        "client_results": sync_results,
        "clients_file": file_path,
    }


# Backward-compatible alias used by existing tests/callers.
list_anan_clients = list_servers


async def health_http(request: Request) -> JSONResponse:
    """Expose a simple health endpoint for direct HTTP checks."""
    return JSONResponse({"status": "ok"})


async def root_http(request: Request) -> HTMLResponse:
    """Expose a simple landing page for the HTTP app."""
    return HTMLResponse("<html><body><h1>MCP server is reachable</h1></body></html>")


async def firewall_status_http(request: Request) -> JSONResponse:
    """Return a simple firewall status payload for the expected HTTP API."""
    return JSONResponse(firewall_status())


def firewall_status() -> dict[str, Any]:
    """Return a simple status payload for route compatibility tests."""
    return {"status": "ok", "output": "active"}


# The MCP server exposes its tools under /mcp.
app = mcp.http_app(path="/mcp", transport="streamable-http")
app.add_route("/", root_http, methods=["GET"])
app.add_route("/mcp/health", health_http, methods=["GET"])
app.add_route("/ufw/status", firewall_status_http, methods=["GET"])


class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        context_token = REQUEST_IDENTITY_CONTEXT.set({"request": request})
        request.state.caller_identity_source = "unknown"
        request.state.agent_ip = resolve_agent_ip_from_request(request)

        if AUTH_SETTINGS.mode == "no_auth":
            inbound_username = resolve_username_from_headers(request.headers)
            if inbound_username:
                request.state.caller_username = inbound_username
                request.state.caller_identity_source = "agent_request"

        if AUTH_SETTINGS.mode == "no_auth" or not is_auth_enforced_path(request.url.path):
            try:
                return await call_next(request)
            finally:
                REQUEST_IDENTITY_CONTEXT.reset(context_token)

        try:
            token = get_bearer_token_from_headers(request.headers)
            request.state.oauth_claims = validate_oauth_bearer_token(token)
            oauth_username = get_username_from_oauth_claims(request.state.oauth_claims)
            if oauth_username:
                request.state.caller_username = oauth_username
                request.state.caller_identity_source = "oauth_claim"
        except HTTPException as exc:
            detail_text = str(exc.detail)
            request.state.auth_failure_reason = classify_auth_failure_detail(detail_text)
            summary = extract_auth_failure_summary(detail_text)
            if summary:
                request.state.auth_failure_detail = summary
            try:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
            finally:
                REQUEST_IDENTITY_CONTEXT.reset(context_token)

        try:
            return await call_next(request)
        finally:
            REQUEST_IDENTITY_CONTEXT.reset(context_token)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = datetime.now(timezone.utc)
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            append_request_log(request, 500, elapsed_ms=elapsed_ms)
            raise

        elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        append_request_log(request, response.status_code, response=response, elapsed_ms=elapsed_ms)
        return response


app.add_middleware(AuthenticationMiddleware)
app.add_middleware(RequestLoggingMiddleware)
initialize_request_log()

if AUTH_SETTINGS.mode == "oauth":
    configured_servers = ", ".join(sorted(AUTH_SETTINGS.oauth_servers.keys()))
    source = AUTH_SETTINGS.oauth_source or "unknown"
    print(
        f"[startup] auth_mode=oauth providers={len(AUTH_SETTINGS.oauth_servers)}"
        f" source={source} names={configured_servers}"
    )
else:
    print("[startup] auth_mode=no_auth")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, **get_uvicorn_run_kwargs())
