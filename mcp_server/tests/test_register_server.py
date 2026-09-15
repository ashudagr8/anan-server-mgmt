import json
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from anan_mcp_server.server import (
    AnanClientConfig,
    add_command_or_cli,
    list_readonly_cli_commands,
    register_client,
    register_server,
    remove_client_command,
    remove_server,
    run_readonly_cli_command,
)


class RegisterServerToolTests(unittest.TestCase):
    def _write_state(self, file_path: str, clients: dict[str, object] | None = None, commands: dict[str, object] | None = None) -> None:
        payload = {
            "clients": clients or {},
            "registered_commands": commands or {},
        }
        with open(file_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    def test_register_server_persists_client_after_hostname_probe(self, mock_call_client_api, mock_sync):
        mock_call_client_api.return_value = {"hostname": "ubuntu-client-1"}
        mock_sync.return_value = {
            "available_commands": ("hostname",),
            "unavailable_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                result = register_server(
                    server_name="client-a",
                    server_host="10.1.2.3",
                    server_port=8443,
                    api_key="abc123",
                    verify_ssl_certificate=False,
                )

            with open(clients_file, encoding="utf-8") as handle:
                payload = json.load(handle)

        self.assertEqual(result["status"], "registered")
        self.assertEqual(result["client"]["hostname"], "ubuntu-client-1")
        self.assertEqual(payload["clients"]["client-a"]["agent_url"], "https://10.1.2.3:8443")
        self.assertFalse(payload["clients"]["client-a"]["ssl_verify"])
        self.assertIn("hostname", payload["registered_commands"])

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    def test_register_client_alias_registers_same_way(self, mock_call_client_api, mock_sync):
        mock_call_client_api.return_value = {"hostname": "ubuntu-client-1"}
        mock_sync.return_value = {
            "available_commands": (),
            "unavailable_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                result = register_client(
                    server_name="client-b",
                    server_host="10.1.2.4",
                    server_port=8443,
                    api_key="xyz789",
                    verify_ssl_certificate=False,
                )

        self.assertEqual(result["status"], "registered")
        self.assertEqual(result["client"]["name"], "client-b")

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    def test_register_server_uses_ip_as_default_client_name_when_name_missing(self, mock_call_client_api, mock_sync):
        mock_call_client_api.return_value = {"hostname": "ubuntu-client-1"}
        mock_sync.return_value = {
            "available_commands": (),
            "unavailable_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                result = register_server(
                    server_name=None,
                    server_host="10.1.2.3",
                    server_port=8443,
                    api_key="abc123",
                    verify_ssl_certificate=False,
                )

            with open(clients_file, encoding="utf-8") as handle:
                payload = json.load(handle)

        self.assertEqual(result["client"]["name"], "10.1.2.3")
        self.assertIn("10.1.2.3", payload["clients"])
        self.assertNotIn("None", payload["clients"])

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    def test_register_server_uses_ssl_verification_option_for_probe(self, mock_call_client_api, mock_sync):
        mock_call_client_api.return_value = {"hostname": "ubuntu-client-1"}
        mock_sync.return_value = {
            "available_commands": (),
            "unavailable_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                register_server(
                    server_name="client-a",
                    server_host="10.1.2.3",
                    server_port=8443,
                    api_key="abc123",
                    verify_ssl_certificate=False,
                )

        kwargs = mock_call_client_api.call_args.kwargs
        self.assertEqual(kwargs["endpoint"], "https://10.1.2.3:8443/system/hostname")
        self.assertEqual(kwargs["method"], "GET")

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    def test_register_server_respects_server_ssl_verify_default(self, mock_call_client_api, mock_sync):
        mock_call_client_api.return_value = {"hostname": "ubuntu-client-1"}
        mock_sync.return_value = {
            "available_commands": (),
            "unavailable_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            with patch.dict(
                os.environ,
                {
                    "ANAN_CLIENTS_FILE": clients_file,
                    "MCP_SERVER_CONFIG": os.path.join(temp_dir, "mcp_server_config.json"),
                },
                clear=False,
            ):
                with open(os.path.join(temp_dir, "mcp_server_config.json"), "w", encoding="utf-8") as handle:
                    json.dump({"clients": {"ufw_client_ssl_verify": False}}, handle)

                register_server(
                    server_name="client-a",
                    server_host="10.1.2.3",
                    server_port=8443,
                    api_key="abc123",
                )

        client_config = mock_call_client_api.call_args.kwargs["client_config"]
        self.assertFalse(client_config.ssl_verify)

        with open(clients_file, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertFalse(payload["clients"]["client-a"]["ssl_verify"])

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    def test_updates_preserve_existing_clients_file_mode(self, mock_call_client_api, mock_sync):
        mock_call_client_api.return_value = {"hostname": "ubuntu-client-1"}
        mock_sync.return_value = {
            "available_commands": (),
            "unavailable_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            self._write_state(clients_file)
            os.chmod(clients_file, 0o664)
            initial_mode = stat.S_IMODE(os.stat(clients_file).st_mode)

            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                register_server(
                    server_name="client-a",
                    server_host="10.1.2.3",
                    server_port=8443,
                    api_key="abc123",
                    verify_ssl_certificate=False,
                )
                remove_server(client_name="client-a")

            final_mode = stat.S_IMODE(os.stat(clients_file).st_mode)

        self.assertEqual(initial_mode, final_mode)

    def test_remove_server_deletes_entry_from_clients_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            self._write_state(
                clients_file,
                clients={
                    "client-a": {
                        "agent_url": "https://10.1.2.3:8443",
                        "api_key": "abc123",
                        "ssl_verify": True,
                    },
                    "client-b": {
                        "agent_url": "https://10.1.2.4:8443",
                        "api_key": "def456",
                        "ssl_verify": False,
                    },
                },
            )

            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                result = remove_server(client_name="client-a")

            with open(clients_file, encoding="utf-8") as handle:
                payload = json.load(handle)

        self.assertEqual(result["status"], "removed")
        self.assertNotIn("client-a", payload["clients"])
        self.assertIn("client-b", payload["clients"])

    @patch("anan_mcp_server.server._push_registered_command_to_client")
    def test_add_client_command_updates_global_registry_and_pushes_all_clients(self, mock_push):
        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            self._write_state(
                clients_file,
                clients={
                    "client-a": {
                        "agent_url": "https://10.1.2.3:8443",
                        "api_key": "abc123",
                        "ssl_verify": True,
                    },
                    "client-b": {
                        "agent_url": "https://10.1.2.4:8443",
                        "api_key": "def456",
                        "ssl_verify": False,
                    },
                },
            )

            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                result = add_command_or_cli(
                    command_name="journal_tail",
                    binary="/usr/bin/journalctl",
                    description="Show recent journal entries.",
                    aliases=["journal", "logs"],
                    fixed_args=["-n", "100"],
                )

            with open(clients_file, encoding="utf-8") as handle:
                payload = json.load(handle)

        self.assertEqual(result["status"], "updated")
        self.assertIn("journal_tail", payload["registered_commands"])
        self.assertEqual(mock_push.call_count, 2)

    @patch("anan_mcp_server.server._remove_registered_command_from_client")
    def test_remove_client_command_updates_global_registry_and_deletes_from_all_clients(self, mock_remove):
        with tempfile.TemporaryDirectory() as temp_dir:
            clients_file = os.path.join(temp_dir, "anan_clients.json")
            self._write_state(
                clients_file,
                clients={
                    "client-a": {
                        "agent_url": "https://10.1.2.3:8443",
                        "api_key": "abc123",
                        "ssl_verify": True,
                    },
                    "client-b": {
                        "agent_url": "https://10.1.2.4:8443",
                        "api_key": "def456",
                        "ssl_verify": False,
                    },
                },
                commands={
                    "journal_tail": {
                        "description": "Show recent journal entries.",
                        "aliases": ["journal", "logs"],
                        "binary": "/usr/bin/journalctl",
                        "fixed_args": ["-n", "100"],
                        "allow_extra_args": False,
                        "examples": [],
                    }
                },
            )

            with patch.dict(os.environ, {"ANAN_CLIENTS_FILE": clients_file}, clear=False):
                result = remove_client_command(command_name="journal_tail")

            with open(clients_file, encoding="utf-8") as handle:
                payload = json.load(handle)

        self.assertEqual(result["status"], "updated")
        self.assertNotIn("journal_tail", payload["registered_commands"])
        self.assertEqual(mock_remove.call_count, 2)

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.get_anan_client_config")
    @patch("anan_mcp_server.server.get_registered_command_registry")
    def test_readonly_cli_list_returns_globally_registered_commands_available_on_client(self, mock_registry, mock_get_client, mock_sync):
        mock_get_client.return_value = AnanClientConfig(
            name="client-a",
            agent_url="https://10.1.2.3:8443",
            api_key="abc123",
            ssl_verify=True,
        )
        mock_registry.return_value = {
            "hostname": type("Cmd", (), {"name": "hostname", "description": "Print system hostname.", "aliases": ("hostname",), "examples": (), "allow_extra_args": False})(),
            "disk_usage": type("Cmd", (), {"name": "disk_usage", "description": "Report file system disk space usage.", "aliases": ("df",), "examples": (), "allow_extra_args": False})(),
        }
        mock_sync.return_value = {
            "available_commands": ("hostname",),
            "unavailable_commands": ("disk_usage",),
            "metadata_by_name": {"hostname": {"name": "hostname"}},
            "pushed_commands": ("hostname", "disk_usage"),
            "removed_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }

        result = list_readonly_cli_commands(client_name="client-a")

        self.assertEqual([item["name"] for item in result["commands"]], ["hostname"])
        self.assertEqual(result["unavailable_on_client"], ["disk_usage"])

    @patch("anan_mcp_server.server.call_client_api")
    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.get_anan_client_config")
    def test_readonly_cli_run_syncs_before_execution(self, mock_get_client, mock_sync, mock_call_client_api):
        mock_get_client.return_value = AnanClientConfig(
            name="default",
            agent_url="https://127.0.0.1:8443",
            api_key="secret",
            ssl_verify=False,
        )
        mock_sync.return_value = {
            "available_commands": ("hostname",),
            "unavailable_commands": (),
            "metadata_by_name": {"hostname": {"name": "hostname"}},
            "pushed_commands": ("hostname",),
            "removed_commands": (),
            "push_failures": [],
            "remove_failures": [],
        }
        mock_call_client_api.return_value = {"success": True}

        result = run_readonly_cli_command("hostname")

        self.assertEqual(result, {"success": True})
        kwargs = mock_call_client_api.call_args.kwargs
        self.assertEqual(kwargs["endpoint"], "https://127.0.0.1:8443/commands/run")
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["data"], {"command_name": "hostname"})

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.get_anan_client_config")
    def test_readonly_cli_run_rejects_command_unavailable_after_sync(self, mock_get_client, mock_sync):
        mock_get_client.return_value = AnanClientConfig(
            name="default",
            agent_url="https://127.0.0.1:8443",
            api_key="secret",
            ssl_verify=False,
        )
        mock_sync.return_value = {
            "available_commands": (),
            "unavailable_commands": ("hostname",),
            "metadata_by_name": {},
            "pushed_commands": (),
            "removed_commands": (),
            "push_failures": [{"command_name": "hostname", "status_code": 400, "detail": "missing binary"}],
            "remove_failures": [],
        }

        with self.assertRaises(HTTPException) as exc:
            run_readonly_cli_command("hostname")

        self.assertEqual(exc.exception.status_code, 409)
        self.assertIn("missing binary", str(exc.exception.detail))


if __name__ == "__main__":
    unittest.main()