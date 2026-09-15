import asyncio
import importlib
import os
import sys
import unittest
from unittest.mock import patch

from fastapi import HTTPException

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from anan_mcp_server import server as server_module
from anan_mcp_server.server import AnanClientConfig


class MvpNonAdminModeTests(unittest.TestCase):
    def _load_tool_names(self, module) -> list[str]:
        async def _read_tool_names() -> list[str]:
            tools = await module.mcp.list_tools()
            return [tool.name for tool in tools]

        return asyncio.run(_read_tool_names())

    def test_mvp_mode_exposes_only_non_admin_tools(self):
        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "no_auth",
                "MVP_NON_ADMIN_MODE": "true",
            },
            clear=False,
        ):
            module = importlib.reload(server_module)
            tool_names = self._load_tool_names(module)

        self.assertEqual(tool_names, ["list_servers", "readonly_cli_list", "readonly_cli_run"])

    def test_standard_mode_keeps_existing_tools_available(self):
        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "no_auth",
                "MVP_NON_ADMIN_MODE": "false",
            },
            clear=False,
        ):
            module = importlib.reload(server_module)
            tool_names = self._load_tool_names(module)

        self.assertIn("list_servers", tool_names)
        self.assertIn("register_server", tool_names)
        self.assertIn("remove_server", tool_names)
        self.assertIn("readonly_cli_list", tool_names)
        self.assertIn("readonly_cli_run", tool_names)

    def test_readonly_cli_run_rejects_unknown_command_name(self):
        with self.assertRaises(HTTPException) as exc:
            server_module.run_readonly_cli_command("not_allowed")

        self.assertEqual(exc.exception.status_code, 400)
        self.assertIn("Unknown command", str(exc.exception.detail))

    @patch("anan_mcp_server.server._sync_registered_commands_to_client")
    @patch("anan_mcp_server.server.call_client_api")
    @patch("anan_mcp_server.server.get_anan_client_config")
    def test_readonly_cli_run_calls_expected_client_endpoint(self, mock_get_client, mock_call_client_api, mock_sync):
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

        result = server_module.run_readonly_cli_command("hostname")

        self.assertEqual(result, {"success": True})
        mock_call_client_api.assert_called_once()
        kwargs = mock_call_client_api.call_args.kwargs
        self.assertEqual(kwargs["endpoint"], "https://127.0.0.1:8443/commands/run")
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["data"], {"command_name": "hostname"})


if __name__ == "__main__":
    unittest.main()
