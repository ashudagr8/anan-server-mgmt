import json
import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app
from config import build_uvicorn_run_kwargs
from execution_policy import (
    ERROR_DENIED_COMMAND,
    ERROR_INVALID_ARGS,
    ERROR_OUTPUT_LIMIT_EXCEEDED,
    ERROR_TIMEOUT,
    CommandResult,
)


os.environ.setdefault("ANAN_CLIENT_API_KEY", "test-key")
client = TestClient(app)
client.headers.update({"X-API-Key": "test-key"})


class TestRootEndpoint:
    def test_root_returns_read_only_structure(self):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "read-only command API"
        assert data["run"] == "/commands/run"
        assert data["hostname"] == "/system/hostname"

    def test_root_requires_api_key(self):
        response = client.get("/", headers={"X-API-Key": ""})
        assert response.status_code == 401



class TestSystemCompatibilityEndpoints:
    def test_hostname_returns_local_hostname(self):
        response = client.get("/system/hostname")
        assert response.status_code == 200
        assert response.json()["hostname"]

    def test_hostname_does_not_depend_on_policy_allowlist(self, tmp_path):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "allowlist": {},
                    "deny_binaries": ["rm"],
                }
            ),
            encoding="utf-8",
        )

        with patch.dict(os.environ, {"ANAN_CLIENT_EXEC_POLICY_FILE": str(policy_file)}, clear=False):
            response = client.get("/system/hostname")

        assert response.status_code == 200
        assert response.json()["hostname"]


class TestCommandDiscoveryAndPolicyEndpoints:
    def test_cli_list_returns_allowed_commands(self, tmp_path):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "allowlist": {
                        "hostname": {"binary": "/usr/bin/hostname", "fixed_args": [], "allow_extra_args": False},
                        "uptime": {"binary": "/usr/bin/uptime", "fixed_args": [], "allow_extra_args": False},
                    },
                    "deny_binaries": ["rm"],
                }
            ),
            encoding="utf-8",
        )

        with patch.dict(os.environ, {"ANAN_CLIENT_EXEC_POLICY_FILE": str(policy_file)}, clear=False):
            response = client.get("/cli/list")

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 2
        assert {item["name"] for item in data["commands"]} == {"hostname", "uptime"}
        assert data["caller_identity"]["username"] == "anonymous"
        assert data["caller_identity"]["source"] == "unknown"
        assert data["caller_identity"]["agent_ip"] == "unknown"

    def test_cli_list_returns_empty_for_fresh_install(self, tmp_path):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "allowlist": {},
                    "deny_binaries": ["rm"],
                }
            ),
            encoding="utf-8",
        )

        with patch.dict(os.environ, {"ANAN_CLIENT_EXEC_POLICY_FILE": str(policy_file)}, clear=False):
            response = client.get("/cli/list")

        assert response.status_code == 200
        assert response.json()["count"] == 0

    def test_cli_list_uses_caller_identity_from_headers(self, tmp_path):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "allowlist": {
                        "hostname": {"binary": "/usr/bin/hostname", "fixed_args": [], "allow_extra_args": False},
                    },
                    "deny_binaries": ["rm"],
                }
            ),
            encoding="utf-8",
        )

        with patch.dict(os.environ, {"ANAN_CLIENT_EXEC_POLICY_FILE": str(policy_file)}, clear=False):
            response = client.get(
                "/cli/list",
                headers={
                    "X-API-Key": "test-key",
                    "X-Caller-Username": "alice",
                    "X-Caller-Source": "agent_response",
                    "X-Agent-IP": "10.2.3.4",
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["caller_identity"]["username"] == "alice"
        assert data["caller_identity"]["source"] == "agent_response"
        assert data["caller_identity"]["agent_ip"] == "10.2.3.4"

    def test_policy_commands_endpoint_adds_and_removes_policy_entries(self, tmp_path):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "allowlist": {
                        "hostname": {"binary": "/usr/bin/hostname", "fixed_args": [], "allow_extra_args": False},
                    },
                    "deny_binaries": ["rm"],
                }
            ),
            encoding="utf-8",
        )

        with patch.dict(os.environ, {"ANAN_CLIENT_EXEC_POLICY_FILE": str(policy_file)}, clear=False):
            add_response = client.post(
                "/policy/commands",
                json={
                    "command_name": "df",
                    "binary": "/usr/bin/df",
                    "fixed_args": ["-h"],
                    "allow_extra_args": False,
                },
            )
            remove_response = client.delete("/policy/commands/hostname")

        assert add_response.status_code == 200
        assert add_response.json()["command_name"] == "df"
        assert remove_response.status_code == 200
        updated_policy = json.loads(policy_file.read_text(encoding="utf-8"))
        assert "df" in updated_policy["allowlist"]
        assert "hostname" not in updated_policy["allowlist"]


class TestRunCommandEndpoint:
    @patch("app.execute_allowed_command")
    def test_run_command_returns_structured_success(self, mock_execute):
        mock_execute.return_value = CommandResult(
            command_name="uptime",
            success=True,
            stdout=" 12:00:00 up 1 day\n",
            stderr="",
            exit_code=0,
            duration_ms=5.4,
        )

        response = client.post("/commands/run", json={"command_name": "uptime"})

        assert response.status_code == 200
        data = response.json()
        assert data == {
            "command_name": "uptime",
            "success": True,
            "stdout": " 12:00:00 up 1 day\n",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 5.4,
            "caller_identity": {
                "username": "anonymous",
                "source": "unknown",
                "agent_ip": "unknown",
            },
        }
        mock_execute.assert_called_once_with(command_name="uptime", extra_args=None)

    @patch("app.execute_allowed_command")
    def test_run_command_uses_caller_identity_from_payload(self, mock_execute):
        mock_execute.return_value = CommandResult(
            command_name="uptime",
            success=True,
            stdout="ok\n",
            stderr="",
            exit_code=0,
            duration_ms=1.0,
        )

        response = client.post(
            "/commands/run",
            json={
                "command_name": "uptime",
                "caller_identity": {
                    "username": "bob",
                    "source": "agent_response",
                    "agent_ip": "34.12.0.8",
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["caller_identity"]["username"] == "bob"
        assert data["caller_identity"]["source"] == "agent_response"
        assert data["caller_identity"]["agent_ip"] == "34.12.0.8"

    def test_run_command_rejects_disallowed_command(self):
        with patch("app.execute_allowed_command") as mock_execute:
            mock_execute.return_value = CommandResult(
                command_name="reboot",
                success=False,
                stdout="",
                stderr="Command 'reboot' is not allowed.",
                exit_code=None,
                duration_ms=0.0,
                error_code=ERROR_DENIED_COMMAND,
            )
            response = client.post("/commands/run", json={"command_name": "reboot"})

        assert response.status_code == 403
        data = response.json()
        assert data["success"] is False
        assert data["error_code"] == ERROR_DENIED_COMMAND
        assert "caller_identity" in data

    @patch("app.execute_allowed_command")
    def test_run_command_rejects_ufw_arg_deviation(self, mock_execute):
        mock_execute.return_value = CommandResult(
            command_name="firewall_status",
            success=False,
            stdout="",
            stderr="Extra arguments are not allowed for this command.",
            exit_code=None,
            duration_ms=0.0,
            error_code=ERROR_INVALID_ARGS,
        )
        response = client.post(
            "/commands/run",
            json={"command_name": "firewall_status", "args": ["status"]},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert data["error_code"] == ERROR_INVALID_ARGS
        assert "caller_identity" in data

    @patch("app.execute_allowed_command")
    def test_run_command_rejects_extra_args_injection(self, mock_execute):
        mock_execute.return_value = CommandResult(
            command_name="uptime",
            success=False,
            stdout="",
            stderr="Extra arguments are not allowed for this command.",
            exit_code=None,
            duration_ms=0.0,
            error_code=ERROR_INVALID_ARGS,
        )
        response = client.post(
            "/commands/run",
            json={"command_name": "uptime", "args": [";", "rm", "-rf", "/"]},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert data["error_code"] == ERROR_INVALID_ARGS
        assert "caller_identity" in data

    @patch("app.execute_allowed_command")
    def test_run_command_timeout_response(self, mock_execute):
        mock_execute.return_value = CommandResult(
            command_name="disk_usage",
            success=False,
            stdout="",
            stderr="",
            exit_code=None,
            duration_ms=15000.0,
            error_code=ERROR_TIMEOUT,
        )

        response = client.post("/commands/run", json={"command_name": "disk_usage"})

        assert response.status_code == 408
        assert response.json()["error_code"] == ERROR_TIMEOUT
        assert "caller_identity" in response.json()

    @patch("app.execute_allowed_command")
    def test_run_command_output_limit_response(self, mock_execute):
        mock_execute.return_value = CommandResult(
            command_name="memory_usage",
            success=False,
            stdout="lots",
            stderr="more",
            exit_code=0,
            duration_ms=2.3,
            error_code=ERROR_OUTPUT_LIMIT_EXCEEDED,
        )

        response = client.post("/commands/run", json={"command_name": "memory_usage"})

        assert response.status_code == 413
        assert response.json()["error_code"] == ERROR_OUTPUT_LIMIT_EXCEEDED
        assert "caller_identity" in response.json()

    def test_run_command_rejects_malformed_payload(self):
        response = client.post("/commands/run", json={"args": []})

        assert response.status_code == 400
        data = response.json()
        assert data["error_code"] == ERROR_INVALID_ARGS

    def test_run_endpoint_requires_api_key(self):
        response = client.post(
            "/commands/run",
            json={"command_name": "hostname"},
            headers={"X-API-Key": ""},
        )
        assert response.status_code == 401


class TestServerConfiguration:
    def test_build_uvicorn_run_kwargs_uses_https_when_cert_and_key_present(self):
        with patch.dict(
            os.environ,
            {
                "ANAN_CLIENT_HOST": "0.0.0.0",
                "ANAN_CLIENT_PORT": "8443",
                "ANAN_CLIENT_HTTPS_CERT": "/tmp/cert.pem",
                "ANAN_CLIENT_HTTPS_KEY": "/tmp/key.pem",
            },
            clear=False,
        ):
            kwargs = build_uvicorn_run_kwargs()

        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["port"] == 8443
        assert kwargs["ssl_certfile"] == "/tmp/cert.pem"
        assert kwargs["ssl_keyfile"] == "/tmp/key.pem"

    def test_build_uvicorn_run_kwargs_omits_https_when_not_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            kwargs = build_uvicorn_run_kwargs()

        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["port"] == 8000
        assert "ssl_certfile" not in kwargs
        assert "ssl_keyfile" not in kwargs
