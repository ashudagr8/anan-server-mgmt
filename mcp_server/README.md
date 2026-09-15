# anan-mcp-server

Professionalized Python MCP server project for controlled command execution through a local helper agent.

## Project Structure

```text
.
├── src/
│   └── anan_mcp_server/
│       ├── __init__.py
│       └── server.py
├── certs/
├── logs/
├── tests/
│   └── test_app.py
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── start_mcp_server.sh
```

## Features

- FastMCP server with streamable HTTP transport.
- Tools: `list_servers`, `readonly_cli_list`, `readonly_cli_run`, `register_server`, `remove_server`, `add_client_command`, `remove_client_command`.
- Direct HTTP route for health checks.
- Configurable HTTPS and auto-generated cert fallback.
- Request logging middleware with timestamp, latency, and request metadata.
- Multiple ANAN client registrations via `ANAN_CLIENTS` and per-tool routing with `client_name`.
- One global registered command registry shared across all registered clients.
- File-backed server state via `anan_clients.json` or `ANAN_CLIENTS_FILE`.

## Requirements

- Python 3.12+
- OpenSSL (only required when generating certs automatically)

## Installation

If you already use the existing virtual environment in `.venv/`:

```bash
./.venv/bin/python -m pip install -r requirements.txt
```

Or with a new environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Preferred startup script:

```bash
./start_mcp_server.sh
```

Manual startup:

```bash
PYTHONPATH=./src ./.venv/bin/python -m uvicorn anan_mcp_server.server:app --host 0.0.0.0 --port 8000
```

## HTTPS and self-signed certificate fallback

When `HTTPS_ENABLED=true`, the server starts in TLS mode and will ensure that a certificate/key pair exists before launching Uvicorn. If `SSL_CERTFILE` and `SSL_KEYFILE` are not provided, it falls back to `./certs/server.crt` and `./certs/server.key`.

If OpenSSL is not already installed, the server attempts to install it automatically using the system package manager before generating the certificate. The generated certificate is a self-signed certificate for `CN=localhost` valid for 365 days and is intended for local/dev use.

Example:

```json
{
  "server": {
    "https_enabled": true,
    "ssl_dir": "./certs",
    "ssl_certfile": "./certs/server.crt",
    "ssl_keyfile": "./certs/server.key"
  }
}
```

This is a convenience for local testing and development; for production, replace it with a CA-issued certificate and a trusted keypair.

## MCP Server Config File

The server can read a JSON configuration file named `mcp_server_config.json`. The default file is located at:

```text
./config/mcp_server_config.json
```

You can override the location with the `MCP_SERVER_CONFIG` environment variable:

```bash
export MCP_SERVER_CONFIG="/path/to/mcp_server_config.json"
```

This file is used for the server-level defaults, including host/port, TLS settings, request logging, agent connection details, client file path, and auth mode settings. If the file does not exist or contains invalid JSON, the app falls back to defaults instead of failing startup.

Example configuration:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8000,
    "request_log_file": "./logs/request.log",
    "https_enabled": true,
    "ssl_dir": "./certs",
    "ssl_certfile": "./certs/fullchain.pem",
    "ssl_keyfile": "./certs/privkey.pem"
  },
	"agent": {
		"ufw_agent_url": "https://127.0.0.1:8443",
		"anan_client_api_key": "abc",
		"ufw_client_ssl_verify": false
	},
  "clients": {
    "file": "./config/anan_clients.json",
    "anan_clients": {}
  },
  "auth": {
    "mode": "no_auth",
    "mvp_non_admin_mode": false,
    "oauth_servers_file": "./config/oauth_servers.json",
    "oauth_servers": {}
  }
}
```

Key points:

- `server.*` controls bind address, port, TLS, and request logging.
- `agent.*` configures the upstream helper agent URL and API key.
- `clients.file` points to the client registry file used by the server.
- `auth.*` controls authentication mode and OAuth settings.
- Environment variables still take precedence over values from this file when they are set.

## Test

```bash
PYTHONPATH=./src ./.venv/bin/python -m unittest discover -s tests -p "test_*.py"
```

## Main Environment Variables

- `HOST`, `PORT`
- `REQUEST_LOG_FILE` (default: `./logs/request.log`)
- `HTTPS_ENABLED`
- `SSL_DIR`, `SSL_CERTFILE`, `SSL_KEYFILE`
- `UFW_AGENT_URL` (default client base URL)
- `ANAN_CLIENT_API_KEY`
- `UFW_CLIENT_SSL_VERIFY` (TLS verification for client HTTPS calls)
- `ANAN_CLIENTS`
- `ANAN_CLIENTS_FILE`
- `MVP_NON_ADMIN_MODE` (`true`/`false`, default `false`)
- `AUTH_MODE` (`no_auth` or `oauth`, default `no_auth`)
- `OAUTH_SERVERS` (JSON payload source for `AUTH_MODE=oauth`)
- `OAUTH_SERVERS_FILE` (path to JSON file source for `AUTH_MODE=oauth`)

## MVP Non-Admin Workflow

Set `MVP_NON_ADMIN_MODE=true` to expose only the non-admin MCP surface.

When enabled, only these tools are registered:

- `list_servers`
- `readonly_cli_list`
- `readonly_cli_run`

State-changing tools are hidden in this mode, including firewall start/stop and server register/remove operations.

This also hides command-management tools (`add_client_command`, `remove_client_command`) in non-admin mode.

Default registered command names on the MCP server:

- `hostname`
- `date_now`
- `uptime`
- `disk_usage`
- `memory_usage`
- `process_list`

Any other command name is rejected by the MCP server before forwarding to the client.

`readonly_cli_list` first synchronizes the target client from the MCP server registry, then returns only the commands currently available on that client.

`readonly_cli_run` also performs a sync attempt before command execution so unreachable or stale clients are repaired opportunistically when possible.

During synchronization, the MCP server:

- pushes every globally registered command to the target client,
- removes commands from the client that are no longer in the server registry, and
- then uses the client's final `/cli/list` response to determine what is actually available.

Example:

```bash
export MVP_NON_ADMIN_MODE="true"
```

Typical flow from an MCP client:

```python
await list_servers()
await readonly_cli_list(client_name="default")
await readonly_cli_run(command_name="hostname", client_name="default")
```

## Command Management Workflow

Use `add_command_or_cli` and `remove_client_command` to manage the global registered command set.

`add_command_or_cli` now coordinates two layers in one tool call:

- MCP server global registry in `anan_clients.json`, which is the source of truth.
- Client policy on every registered client (`/policy/commands`), so each client converges toward the same command set.

Recommended add flow for a new command:

- Provide `command_name`, `binary`, `description`, and optional `aliases` / `fixed_args` / `allow_extra_args`.
- For interactive CLIs, configure non-interactive `fixed_args` so the command can run safely in automation.

`add_command_or_cli` adds a new command or CLI globally to all registered clients and does not require a specific client or server name.

`remove_client_command` removes the command from the global registry and deletes it from every registered client.

The command names exposed to agents are semantic IDs rather than raw Linux binaries. For example:

- `disk_usage` wraps `/usr/bin/df -h`
- `memory_usage` wraps `/usr/bin/free -h`
- `process_list` wraps `/usr/bin/ps aux`

Compatibility notes:

- `client_name` is still accepted by the command-management tools but ignored because command registration is now global.

## Authentication Modes

The server runs in one authentication mode per process start.
There is no fallback across modes at runtime.

- `AUTH_MODE=no_auth`
	- Current behavior: inbound requests are not authenticated.
- `AUTH_MODE=oauth`
	- Inbound requests to `/mcp/*` (except `/mcp/health`) require `Authorization: Bearer <token>`.
	- Token is validated against configured OAuth/OIDC servers.
	- OAuth server config is loaded from `OAUTH_SERVERS_FILE` when set, otherwise from `OAUTH_SERVERS`.

At startup the server prints the selected authentication mode.
For OAuth mode it also prints provider names and whether config came from env or file.

### OAuth Server Configuration

Set `OAUTH_SERVERS` as JSON object (or JSON list) to configure one or more trusted OAuth/OIDC servers.

When using object form, you can optionally include `auth_mode` (or `AUTH_MODE`) at the top level:

- `auth_mode: "oauth"` enables OAuth mode when `AUTH_MODE` environment variable is not set.
- `auth_mode: "no_auth"` keeps the server in no-auth mode when `AUTH_MODE` is not set.
- If `AUTH_MODE` environment variable is set, it takes precedence.

You can provide this JSON in either of these ways:

- Environment variable payload: `OAUTH_SERVERS='...json...'`
- JSON file path: `OAUTH_SERVERS_FILE=/path/to/oauth_servers.json`

When both are set, `OAUTH_SERVERS_FILE` takes precedence.

Object form example:

```bash
export AUTH_MODE="oauth"
export OAUTH_SERVERS='{
	"auth_mode": "oauth",
	"primary": {
		"issuer": "https://login.example.com",
		"audience": "anan-mcp-server",
		"jwks_url": "https://login.example.com/.well-known/jwks.json",
		"algorithms": ["RS256"]
	},
	"backup": {
		"issuer": "https://idp.partner.com",
		"audience": "anan-mcp-server",
		"jwks_url": "https://idp.partner.com/keys",
		"algorithms": ["RS256"]
	}
}'
```

List form example:

```bash
export AUTH_MODE="oauth"
export OAUTH_SERVERS='[
	{
		"name": "primary",
		"issuer": "https://login.example.com",
		"audience": "anan-mcp-server",
		"jwks_url": "https://login.example.com/.well-known/jwks.json",
		"algorithms": ["RS256"]
	}
]'
```

## Multi-Client Routing

Set `ANAN_CLIENTS_FILE` to point at a JSON file when you want to keep ANAN client details in a separate file.
If that file exists, it is loaded first. The file now stores both client inventory and the global registered command registry.

Example file contents:

```json
{
	"clients": {
		"default": {
			"agent_url": "https://127.0.0.1:8443",
			"api_key": "abc",
			"ssl_verify": false
		},
		"beta": {
			"agent_url": "https://beta.example.com",
			"api_key": "beta-key",
			"ssl_verify": true
		}
	},
	"registered_commands": {
		"hostname": {
			"description": "Print system hostname.",
			"aliases": ["hostname"],
			"binary": "/usr/bin/hostname",
			"fixed_args": [],
			"allow_extra_args": false,
			"examples": ["show the hostname"]
		}
	}
}
```

Example:

```bash
export ANAN_CLIENTS='{"alpha":{"agent_url":"https://alpha.example.com","api_key":"alpha-key","ssl_verify":false},"beta":{"agent_url":"https://beta.example.com","api_key":"beta-key","ssl_verify":true}}'
```

If you want to use a different file path, set `ANAN_CLIENTS_FILE`:

```bash
export ANAN_CLIENTS_FILE="/path/to/anan_clients.json"
```

Route a tool call to a specific client by passing `client_name` to the ANAN-facing tools:

```python
await start_firewall(client_name="alpha")
await firewall_status(client_name="beta")
```

Register a new client and verify it is online before it is saved:

```python
await register_server(
	server_name="gamma",
	server_host="10.0.0.20",
	server_port=8443,
	api_key="gamma-key",
	verify_ssl_certificate=False,
)
```

`register_server` performs a `GET /system/hostname` call on the target client using the provided API key. The client is added to `anan_clients.json` only when the hostname check succeeds.
Set `verify_ssl_certificate=True` to enforce certificate validation, or `False` to ignore certificate verification for self-signed/untrusted certificates.

Remove an existing client configuration:

```python
await remove_server(client_name="gamma")
```
