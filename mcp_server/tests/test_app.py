import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.requests import Request

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from anan_mcp_server import server as app_module
from anan_mcp_server.server import (
    AnanClientConfig,
    REQUEST_IDENTITY_CONTEXT,
    call_client_api,
    get_anan_client_config,
    get_anan_client_registry,
    get_available_anan_client_names,
    get_server_config,
    get_ufw_agent_url,
    get_anan_client_api_key,
    get_uvicorn_run_kwargs,
    list_anan_clients,
)


class UFWToolTests(unittest.TestCase):
    def test_get_server_config_uses_environment_overrides(self):
        with patch.dict(os.environ, {"HOST": "127.0.0.1", "PORT": "9000"}, clear=False):
            host, port = get_server_config()

        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 9000)

    def test_mcp_server_uses_config_file_values_when_env_is_unset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "mcp_server_config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "server": {
                            "host": "10.0.0.10",
                            "port": 9100,
                            "request_log_file": "/tmp/mcp-request.log",
                            "https_enabled": False,
                        },
                        "agent": {
                            "ufw_agent_url": "https://config.example.com:9443",
                            "anan_client_api_key": "config-key",
                            "ufw_client_ssl_verify": False,
                        },
                    },
                    handle,
                )

            with patch.dict(os.environ, {"MCP_SERVER_CONFIG": config_path}, clear=False):
                os.environ.pop("HOST", None)
                os.environ.pop("PORT", None)
                os.environ.pop("UFW_AGENT_URL", None)
                os.environ.pop("ANAN_CLIENT_API_KEY", None)

                host, port = get_server_config()
                self.assertEqual(host, "10.0.0.10")
                self.assertEqual(port, 9100)
                self.assertEqual(get_ufw_agent_url(), "https://config.example.com:9443")
                self.assertEqual(get_anan_client_api_key(), "config-key")

    def test_get_anan_client_registry_uses_multiple_clients(self):
        clients_json = (
            '{'
            '"alpha": {"agent_url": "https://alpha.example.com", "api_key": "alpha-key", "ssl_verify": false},'
            '"beta": {"agent_url": "https://beta.example.com", "api_key": "beta-key", "ssl_verify": true}'
            '}'
        )
        with patch.dict(os.environ, {"ANAN_CLIENTS": clients_json}, clear=False):
            registry = get_anan_client_registry()

        self.assertEqual(sorted(registry), ["alpha", "beta"])
        self.assertEqual(registry["alpha"].agent_url, "https://alpha.example.com")
        self.assertFalse(registry["alpha"].ssl_verify)

    def test_get_anan_client_config_returns_named_client(self):
        clients_json = (
            '{'
            '"alpha": {"agent_url": "https://alpha.example.com", "api_key": "alpha-key", "ssl_verify": false},'
            '"beta": {"agent_url": "https://beta.example.com", "api_key": "beta-key", "ssl_verify": true}'
            '}'
        )
        with patch.dict(os.environ, {"ANAN_CLIENTS": clients_json}, clear=False):
            client = get_anan_client_config("beta")

        self.assertEqual(client.name, "beta")
        self.assertEqual(client.agent_url, "https://beta.example.com")

    def test_get_anan_client_registry_uses_json_file_before_env(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with open(clients_file, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "file_client": {
                            "agent_url": "https://file.example.com",
                            "api_key": "file-key",
                            "ssl_verify": False,
                        }
                    },
                    handle,
                )

            with patch.dict(
                os.environ,
                {
                    "ANAN_CLIENTS_FILE": clients_file,
                    "ANAN_CLIENTS": '{"env_client": {"agent_url": "https://env.example.com", "api_key": "env-key", "ssl_verify": false}}',
                },
                clear=False,
            ):
                registry = get_anan_client_registry()

        self.assertEqual(sorted(registry), ["file_client"])
        self.assertEqual(registry["file_client"].agent_url, "https://file.example.com")

    def test_list_anan_clients_returns_registered_clients(self):
        clients_json = (
            '{'
            '"alpha": {"agent_url": "https://alpha.example.com", "api_key": "alpha-key", "ssl_verify": false},'
            '"beta": {"agent_url": "https://beta.example.com", "api_key": "beta-key", "ssl_verify": true}'
            '}'
        )
        with patch.dict(os.environ, {"ANAN_CLIENTS": clients_json}, clear=False):
            result = list_anan_clients()

        self.assertEqual(result["default"], "alpha")
        self.assertEqual([client["name"] for client in result["clients"]], ["alpha", "beta"])

    def test_list_anan_clients_handles_empty_registry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with open(clients_file, "w", encoding="utf-8") as handle:
                json.dump({"clients": {}}, handle)

            with patch.dict(
                os.environ,
                {
                    "ANAN_CLIENTS": "",
                    "ANAN_CLIENTS_FILE": clients_file,
                },
                clear=False,
            ):
                result = list_anan_clients()

        self.assertEqual(result["default"], None)
        self.assertEqual(result["clients"], [])

    def test_list_anan_clients_returns_agent_ip_from_url(self):
        clients_json = '{"local": {"agent_url": "https://127.0.0.1:8443", "api_key": "local-key", "ssl_verify": false}}'
        with patch.dict(os.environ, {"ANAN_CLIENTS": clients_json}, clear=False):
            result = list_anan_clients()

        self.assertEqual(result["clients"][0]["agent_ip"], "127.0.0.1")

    def test_list_anan_clients_does_not_mark_single_client_as_default(self):
        clients_json = '{"local": {"agent_url": "https://127.0.0.1:8443", "api_key": "local-key", "ssl_verify": false}}'
        with patch.dict(os.environ, {"ANAN_CLIENTS": clients_json}, clear=False):
            result = list_anan_clients()

        self.assertIsNone(result["default"])
        self.assertEqual([client["name"] for client in result["clients"]], ["local"])

    def test_request_logging_writes_to_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "requests.log")
            with patch.dict(os.environ, {"REQUEST_LOG_FILE": log_file}, clear=False):
                importlib.reload(app_module)
                client = TestClient(app_module.app)

                response = client.get("/mcp/health")

                self.assertEqual(response.status_code, 200)
                with open(log_file, encoding="utf-8") as handle:
                    contents = handle.read()

                self.assertIn("GET", contents)
                self.assertIn("/mcp/health", contents)
                self.assertIn("user=anonymous", contents)
                self.assertIn("agent_ip=testclient", contents)

    def test_request_logging_uses_forwarded_for_as_agent_ip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "requests.log")
            with patch.dict(os.environ, {"REQUEST_LOG_FILE": log_file}, clear=False):
                importlib.reload(app_module)
                client = TestClient(app_module.app)

                response = client.get("/mcp/health", headers={"x-forwarded-for": "203.0.113.10, 10.0.0.1"})

                self.assertEqual(response.status_code, 200)
                with open(log_file, encoding="utf-8") as handle:
                    contents = handle.read()

                self.assertIn("agent_ip=203.0.113.10", contents)

    def test_call_client_api_propagates_caller_identity_and_uses_agent_fallback(self):
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("test", 8000),
            "scheme": "http",
            "http_version": "1.1",
        }
        request = Request(scope)
        request.state.caller_username = ""
        request.state.caller_identity_source = "unknown"
        request.state.agent_ip = "unknown"

        captured: dict[str, object] = {}

        class _FakeResponse:
            headers: dict[str, str] = {}

            def __init__(self, payload: dict[str, object]):
                self._payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self._payload).encode("utf-8")

        def _fake_urlopen(req, timeout, context):
            captured["request"] = req
            return _FakeResponse(
                {
                    "ok": True,
                    "caller_identity": {"username": "agent_user", "source": "agent_response"},
                }
            )

        token = REQUEST_IDENTITY_CONTEXT.set({"request": request})
        try:
            with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
                payload = call_client_api(
                    client_config=AnanClientConfig(
                        name="default",
                        agent_url="https://10.2.3.4:8443",
                        api_key="secret",
                        ssl_verify=False,
                    ),
                    endpoint="https://10.2.3.4:8443/commands/run",
                    method="POST",
                    data={"command_name": "hostname"},
                )
        finally:
            REQUEST_IDENTITY_CONTEXT.reset(token)

        self.assertEqual(payload["ok"], True)
        self.assertEqual(request.state.caller_username, "agent_user")
        self.assertEqual(request.state.caller_identity_source, "agent_response")
        self.assertEqual(request.state.agent_ip, "10.2.3.4")

        outbound_request = captured["request"]
        self.assertEqual(outbound_request.get_method(), "POST")
        body = json.loads(outbound_request.data.decode("utf-8"))
        self.assertEqual(body["command_name"], "hostname")
        self.assertEqual(body["caller_identity"]["agent_ip"], "10.2.3.4")
        self.assertEqual(body["caller_identity"]["source"], "unknown")
        self.assertEqual(body["caller_identity"]["username"], "unknown")

    def test_call_client_api_keeps_oauth_username_when_agent_returns_fallback(self):
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("test", 8000),
            "scheme": "http",
            "http_version": "1.1",
        }
        request = Request(scope)
        request.state.caller_username = "token_user"
        request.state.caller_identity_source = "oauth_claim"
        request.state.agent_ip = "unknown"

        class _FakeResponse:
            headers: dict[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "caller_identity": {"username": "agent_user", "source": "agent_response"},
                    }
                ).encode("utf-8")

        token = REQUEST_IDENTITY_CONTEXT.set({"request": request})
        try:
            with patch("urllib.request.urlopen", return_value=_FakeResponse()):
                call_client_api(
                    client_config=AnanClientConfig(
                        name="default",
                        agent_url="https://10.2.3.4:8443",
                        api_key="secret",
                        ssl_verify=False,
                    ),
                    endpoint="https://10.2.3.4:8443/commands/run",
                    method="POST",
                    data={"command_name": "hostname"},
                )
        finally:
            REQUEST_IDENTITY_CONTEXT.reset(token)

        self.assertEqual(request.state.caller_username, "token_user")
        self.assertEqual(request.state.caller_identity_source, "oauth_claim")

    def test_get_uvicorn_run_kwargs_uses_https_settings(self):
        with patch.dict(os.environ, {"HTTPS_ENABLED": "true", "SSL_CERTFILE": "/tmp/server.crt", "SSL_KEYFILE": "/tmp/server.key"}, clear=False):
            with patch("anan_mcp_server.server.ensure_https_certificates", return_value=("/tmp/server.crt", "/tmp/server.key")):
                kwargs = get_uvicorn_run_kwargs()

        self.assertEqual(kwargs["ssl_certfile"], "/tmp/server.crt")
        self.assertEqual(kwargs["ssl_keyfile"], "/tmp/server.key")

    def test_ensure_https_certificates_installs_openssl_when_missing(self):
        with patch.dict(os.environ, {"HTTPS_ENABLED": "true"}, clear=False):
            with patch("anan_mcp_server.server.shutil.which", side_effect=[None, "/usr/bin/openssl"]):
                with patch("anan_mcp_server.server.install_openssl_if_missing") as install_mock:
                    with patch("anan_mcp_server.server.os.makedirs"):
                        with patch("anan_mcp_server.server.os.path.exists", return_value=False):
                            with patch("anan_mcp_server.server.subprocess.run") as run_mock:
                                certfile, keyfile = app_module.ensure_https_certificates()

        install_mock.assert_called_once_with()
        self.assertTrue(certfile.endswith("server.crt"))
        self.assertTrue(keyfile.endswith("server.key"))
        run_mock.assert_called_once()

    def test_ensure_https_certificates_generates_missing_configured_files(self):
        with patch.dict(
            os.environ,
            {"HTTPS_ENABLED": "true", "SSL_CERTFILE": "/tmp/custom-server.crt", "SSL_KEYFILE": "/tmp/custom-server.key"},
            clear=False,
        ):
            with patch("anan_mcp_server.server.shutil.which", return_value="/usr/bin/openssl"):
                with patch("anan_mcp_server.server.os.makedirs"):
                    with patch("anan_mcp_server.server.os.path.exists", return_value=False):
                        with patch("anan_mcp_server.server.subprocess.run") as run_mock:
                            certfile, keyfile = app_module.ensure_https_certificates()

        self.assertEqual(certfile, "/tmp/custom-server.crt")
        self.assertEqual(keyfile, "/tmp/custom-server.key")
        run_mock.assert_called_once()

    def test_root_path_serves_index_page(self):
        client = TestClient(app_module.app)

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("MCP server is reachable", response.text)

if __name__ == "__main__":
    unittest.main()
