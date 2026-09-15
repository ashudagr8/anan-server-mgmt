import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from anan_mcp_server import server as app_module


def oauth_servers_json() -> str:
    return json.dumps(
        {
            "primary": {
                "issuer": "https://login.example.com",
                "audience": "anan-mcp-server",
                "jwks_url": "https://login.example.com/.well-known/jwks.json",
                "algorithms": ["RS256"],
            }
        }
    )


class AuthModeTests(unittest.TestCase):
    def test_auth_mode_defaults_to_no_auth(self):
        with patch.dict(os.environ, {"AUTH_MODE": "no_auth"}, clear=False):
            importlib.reload(app_module)

        self.assertEqual(app_module.AUTH_SETTINGS.mode, "no_auth")

    def test_oauth_mode_requires_oauth_servers(self):
        with patch.dict(os.environ, {"AUTH_MODE": "oauth", "OAUTH_SERVERS": "", "OAUTH_SERVERS_FILE": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                importlib.reload(app_module)

        with patch.dict(os.environ, {"AUTH_MODE": "no_auth"}, clear=False):
            importlib.reload(app_module)

    def test_oauth_mode_rejects_requests_without_bearer_token(self):
        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "oauth",
                "OAUTH_SERVERS": oauth_servers_json(),
            },
            clear=False,
        ):
            importlib.reload(app_module)
            client = TestClient(app_module.app)

            response = client.get("/ufw/status")

        self.assertEqual(response.status_code, 401)
        self.assertIn("Authorization", response.json()["detail"])

    def test_oauth_mode_accepts_valid_bearer_token(self):
        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "oauth",
                "OAUTH_SERVERS": oauth_servers_json(),
            },
            clear=False,
        ):
            importlib.reload(app_module)
            with patch.object(app_module, "validate_oauth_bearer_token", return_value={"sub": "alice"}):
                with patch.object(app_module, "firewall_status", return_value={"status": "ok", "output": "active"}):
                    client = TestClient(app_module.app)
                    response = client.get("/ufw/status", headers={"Authorization": "Bearer test-token"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_oauth_mode_logs_username_from_token_claim(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "request.log")
            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "oauth",
                    "OAUTH_SERVERS": oauth_servers_json(),
                    "REQUEST_LOG_FILE": log_file,
                },
                clear=False,
            ):
                importlib.reload(app_module)
                with patch.object(app_module, "validate_oauth_bearer_token", return_value={"preferred_username": "alice"}):
                    with patch.object(app_module, "firewall_status", return_value={"status": "ok", "output": "active"}):
                        client = TestClient(app_module.app)
                        response = client.get("/ufw/status", headers={"Authorization": "Bearer test-token"})

                        self.assertEqual(response.status_code, 200)
                        with open(log_file, encoding="utf-8") as handle:
                            contents = handle.read()

            self.assertIn("user=alice", contents)
            self.assertIn("user_source=oauth_claim", contents)

    def test_oauth_mode_logs_missing_authorization_header_reason(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "request.log")
            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "oauth",
                    "OAUTH_SERVERS": oauth_servers_json(),
                    "REQUEST_LOG_FILE": log_file,
                },
                clear=False,
            ):
                importlib.reload(app_module)
                client = TestClient(app_module.app)

                response = client.post("/mcp")

                self.assertEqual(response.status_code, 401)
                with open(log_file, encoding="utf-8") as handle:
                    contents = handle.read()

            self.assertIn("status=401", contents)
            self.assertIn("auth_failure=missing_authorization_header", contents)

    def test_oauth_mode_logs_invalid_token_detail_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "request.log")
            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "oauth",
                    "OAUTH_SERVERS": oauth_servers_json(),
                    "REQUEST_LOG_FILE": log_file,
                },
                clear=False,
            ):
                importlib.reload(app_module)
                with patch.object(
                    app_module,
                    "validate_oauth_bearer_token",
                    side_effect=HTTPException(
                        status_code=401,
                        detail="Invalid OAuth bearer token. primary: Audience doesn't match",
                    ),
                ):
                    client = TestClient(app_module.app)
                    response = client.post("/mcp", headers={"Authorization": "Bearer token"})

                    self.assertEqual(response.status_code, 401)
                    with open(log_file, encoding="utf-8") as handle:
                        contents = handle.read()

            self.assertIn("auth_failure=invalid_oauth_bearer_token", contents)
            self.assertIn("auth_failure_detail=primary:_Audience_doesn't_match", contents)

    def test_oauth_servers_can_define_multiple_providers(self):
        providers = {
            "primary": {
                "issuer": "https://login.example.com",
                "audience": "anan-mcp-server",
                "jwks_url": "https://login.example.com/.well-known/jwks.json",
                "algorithms": ["RS256"],
            },
            "partner": {
                "issuer": "https://idp.partner.com",
                "audience": "anan-mcp-server",
                "jwks_url": "https://idp.partner.com/keys",
                "algorithms": ["RS256"],
            },
        }

        with patch.dict(os.environ, {"AUTH_MODE": "oauth", "OAUTH_SERVERS": json.dumps(providers)}, clear=False):
            importlib.reload(app_module)

        self.assertEqual(app_module.AUTH_SETTINGS.mode, "oauth")
        self.assertEqual(sorted(app_module.AUTH_SETTINGS.oauth_servers.keys()), ["partner", "primary"])

    def test_oauth_servers_can_be_loaded_from_json_file(self):
        providers = {
            "file_provider": {
                "issuer": "https://idp.file.example.com",
                "audience": "anan-mcp-server",
                "jwks_url": "https://idp.file.example.com/jwks",
                "algorithms": ["RS256"],
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            providers_file = os.path.join(temp_dir, "oauth_servers.json")
            with open(providers_file, "w", encoding="utf-8") as handle:
                json.dump(providers, handle)

            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "oauth",
                    "OAUTH_SERVERS_FILE": providers_file,
                    "OAUTH_SERVERS": "",
                },
                clear=False,
            ):
                importlib.reload(app_module)

        self.assertEqual(app_module.AUTH_SETTINGS.mode, "oauth")
        self.assertEqual(sorted(app_module.AUTH_SETTINGS.oauth_servers.keys()), ["file_provider"])
        self.assertTrue((app_module.AUTH_SETTINGS.oauth_source or "").startswith("file:"))

    def test_auth_mode_can_be_read_from_oauth_servers_file_metadata(self):
        providers = {
            "auth_mode": "oauth",
            "file_provider": {
                "issuer": "https://idp.file.example.com",
                "audience": "anan-mcp-server",
                "jwks_url": "https://idp.file.example.com/jwks",
                "algorithms": ["RS256"],
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            providers_file = os.path.join(temp_dir, "oauth_servers.json")
            with open(providers_file, "w", encoding="utf-8") as handle:
                json.dump(providers, handle)

            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "",
                    "OAUTH_SERVERS_FILE": providers_file,
                    "OAUTH_SERVERS": "",
                },
                clear=False,
            ):
                importlib.reload(app_module)

        self.assertEqual(app_module.AUTH_SETTINGS.mode, "oauth")
        self.assertEqual(sorted(app_module.AUTH_SETTINGS.oauth_servers.keys()), ["file_provider"])

    def test_auth_mode_env_var_overrides_oauth_servers_file_metadata(self):
        providers = {
            "auth_mode": "oauth",
            "file_provider": {
                "issuer": "https://idp.file.example.com",
                "audience": "anan-mcp-server",
                "jwks_url": "https://idp.file.example.com/jwks",
                "algorithms": ["RS256"],
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            providers_file = os.path.join(temp_dir, "oauth_servers.json")
            with open(providers_file, "w", encoding="utf-8") as handle:
                json.dump(providers, handle)

            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "no_auth",
                    "OAUTH_SERVERS_FILE": providers_file,
                    "OAUTH_SERVERS": "",
                },
                clear=False,
            ):
                importlib.reload(app_module)

        self.assertEqual(app_module.AUTH_SETTINGS.mode, "no_auth")


if __name__ == "__main__":
    unittest.main()
