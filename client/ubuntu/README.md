# Linux Command Agent

FastAPI service for policy-controlled Linux command execution over authenticated API endpoints.

## Structure

- src: application modules
- src/anan_client.py: entrypoint
- tests: automated tests
- certs: TLS certificate and key files
- start_anan_client.sh: startup entrypoint
- stop_anan_client.sh: graceful shutdown helper

## Endpoints

- GET /
- GET /cli/list
- POST /commands/run
- POST /policy/commands
- DELETE /policy/commands/{command_name}
- GET /system/hostname

All endpoints require header: X-API-Key.

## Environment Variables

- ANAN_CLIENT_API_KEY
- ANAN_CLIENT_HOST
- ANAN_CLIENT_PORT
- ANAN_CLIENT_EXEC_POLICY_FILE (default: /etc/anan-client/command-policy.json)
- ANAN_CLIENT_HTTPS_CERT
- ANAN_CLIENT_HTTPS_KEY
- ANAN_CLIENT_REQUEST_LOG_FILE (default: logs/anan-client-requests.log)
- ANAN_CLIENT_LOG_RESPONSE_BODY (default: true)

## Run

```bash
sudo ./start_anan_client.sh
```

To stop it cleanly later:

```bash
sudo ./stop_anan_client.sh
```

If the configured TLS files do not exist, the startup script generates a self-signed certificate and key automatically.

Each API request/response is logged to:

```bash
logs/anan-client-requests.log
```

The log file is reset each time the server starts.

## Install As Ubuntu Service

On another Ubuntu machine, copy/clone this project first, then run:

```bash
sudo ./install_service.sh
```

The installer will:

- create .venv if missing
- install Python dependencies
- install /etc/systemd/system/anan-client.service
- create /etc/default/anan-client (if missing)
- enable and start the service

Reinstall/refresh service files:

```bash
sudo ./install_service.sh --reinstall
```

Service management commands:

```bash
sudo systemctl status anan-client.service
sudo systemctl restart anan-client.service
sudo journalctl -u anan-client.service -f
```

Environment file for service settings:

```bash
/etc/default/anan-client
```

Set a strong ANAN_CLIENT_API_KEY in that file, then restart the service.

Uninstall service:

```bash
sudo ./uninstall_service.sh
```

Uninstall and remove service environment file:

```bash
sudo ./uninstall_service.sh --purge
```

## Test

```bash
./.venv/bin/python -m pytest tests -v
```

## MVP Non-Admin Read-Only Mode

The client enforces strict read-only execution for server-registered command runs.

Important architecture notes:

- Fresh installation starts with an empty `allowlist`.
- The MCP server is the source of truth for registered commands and pushes policy entries to the client.
- `GET /system/hostname` is intentionally built in and does not depend on the command policy file, so a fresh client can still be registered before any commands are pushed.

Execution policy guarantees:

- default deny for unknown command names
- no shell execution (argv execution only)
- no sudo
- no extra args accepted
- hard timeout of 15 seconds
- combined stdout/stderr output limit of 256 KB
- global deny guardrails for dangerous binaries (rm, mv, chmod, chown, systemctl, service, reboot, shutdown, iptables, nft, ufw)
- ufw is allowed only for the exact status verbose read-only query

Policy file permissions:

- The command policy file must be owned by root and must not be group/other writable.
- Recommended mode is 600, for example:

```bash
sudo chown root:root /etc/anan-client/command-policy.json
sudo chmod 600 /etc/anan-client/command-policy.json
```

If permissions are too broad or ownership is not root, command execution is denied.

Policy requirements:

- There are no built-in default allowlist or deny-binaries values at runtime.
- The policy file is mandatory; if missing or malformed, startup preflight fails and command execution is denied.
- An empty `allowlist` is valid and represents a fresh client with no registered commands yet.

Policy file locations:

- Active runtime file (used by service): /etc/anan-client/command-policy.json
- Project template you can inspect in the repo: config/command-policy.example.json

Preflight check:

```bash
sudo /home/ashutosh/anan-ubuntu-client/.venv/bin/python /home/ashutosh/anan-ubuntu-client/src/policy_preflight.py
```

The service also runs this preflight automatically before startup.

Run endpoint:

```bash
curl -k -X POST https://127.0.0.1:8000/commands/run \
	-H 'X-API-Key: <key>' \
	-H 'Content-Type: application/json' \
	-d '{"command_name":"uptime"}'
```

Success response shape:

```json
{
	"command_name": "uptime",
	"success": true,
	"stdout": "...",
	"stderr": "",
	"exit_code": 0,
	"duration_ms": 4.18
}
```

Failure response shape (includes standardized error_code):

```json
{
	"command_name": "reboot",
	"success": false,
	"stdout": "",
	"stderr": "Command 'reboot' is not allowed.",
	"exit_code": null,
	"duration_ms": 0.0,
	"error_code": "denied_command"
}
```

Common failure cases:

- unknown command_name -> denied_command
- any args provided -> invalid_args
- command exceeds timeout -> timeout
- output exceeds cap -> output_limit_exceeded

