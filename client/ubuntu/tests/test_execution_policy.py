import execution_policy
from subprocess import CompletedProcess, TimeoutExpired
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from execution_policy import (
    COMMAND_TIMEOUT_SECONDS,
    ERROR_DENIED_COMMAND,
    ERROR_INVALID_ARGS,
    ERROR_OUTPUT_LIMIT_EXCEEDED,
    ERROR_TIMEOUT,
    CommandValidationError,
    ensure_runtime_policy_file,
    execute_allowed_command,
)


class TestAllowlist:
    def test_missing_policy_file_is_denied(self, tmp_path, monkeypatch):
        missing_file = tmp_path / "does-not-exist.json"
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(missing_file))

        with pytest.raises(CommandValidationError) as exc_info:
            execute_allowed_command("hostname")

        assert exc_info.value.error_code == ERROR_DENIED_COMMAND
        assert "is required" in exc_info.value.message

    def test_empty_allowlist_denies_execution_without_failing_policy_load(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            """
            {
              "allowlist": {},
              "deny_binaries": ["rm", "ufw"]
            }
            """,
            encoding="utf-8",
        )
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("hostname")

        assert exc_info.value.error_code == ERROR_DENIED_COMMAND


class TestExecutionPolicy:
    @staticmethod
    def _write_default_like_policy(policy_file):
        policy_file.write_text(
            """
            {
              "allowlist": {
                "hostname": {"binary": "/usr/bin/hostname", "fixed_args": [], "allow_extra_args": false},
                "uptime": {"binary": "/usr/bin/uptime", "fixed_args": [], "allow_extra_args": false},
                "disk_usage": {"binary": "/usr/bin/df", "fixed_args": ["-h"], "allow_extra_args": false},
                "memory_usage": {"binary": "/usr/bin/free", "fixed_args": ["-h"], "allow_extra_args": false},
                "firewall_status": {"binary": "/usr/sbin/ufw", "fixed_args": ["status", "verbose"], "allow_extra_args": false}
              },
              "deny_binaries": ["rm", "mv", "chmod", "chown", "systemctl", "service", "reboot", "shutdown", "iptables", "nft", "ufw"]
            }
            """,
            encoding="utf-8",
        )

    @pytest.mark.parametrize(
        "command_name, expected_argv",
        [
            ("hostname", ["/usr/bin/hostname"]),
            ("uptime", ["/usr/bin/uptime"]),
            ("disk_usage", ["/usr/bin/df", "-h"]),
            ("memory_usage", ["/usr/bin/free", "-h"]),
            ("firewall_status", ["/usr/sbin/ufw", "status", "verbose"]),
        ],
    )
    @patch("execution_policy.subprocess.run")
    def test_allowed_commands_execute_with_fixed_argv(
        self,
        mock_run,
        command_name,
        expected_argv,
        tmp_path,
        monkeypatch,
    ):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        mock_run.return_value = CompletedProcess(args=expected_argv, returncode=0, stdout=b"ok", stderr=b"")

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            result = execute_allowed_command(command_name)

        assert result.success is True
        assert result.error_code is None
        called_argv = mock_run.call_args.args[0]
        assert called_argv == expected_argv
        assert mock_run.call_args.kwargs["shell"] is False
        assert mock_run.call_args.kwargs["timeout"] == COMMAND_TIMEOUT_SECONDS

    @patch("execution_policy.subprocess.run")
    def test_disallowed_command_is_rejected_before_execution(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("reboot")

        assert exc_info.value.error_code == ERROR_DENIED_COMMAND
        mock_run.assert_not_called()

    @patch("execution_policy.subprocess.run")
    def test_empty_command_name_is_rejected(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("   ")

        assert exc_info.value.error_code == ERROR_INVALID_ARGS
        mock_run.assert_not_called()

    @patch("execution_policy.subprocess.run")
    def test_ufw_args_deviation_is_rejected(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("firewall_status", extra_args=["disable"])

        assert exc_info.value.error_code == ERROR_INVALID_ARGS
        mock_run.assert_not_called()

    @patch("execution_policy.subprocess.run")
    def test_extra_args_injection_is_rejected(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("uptime", extra_args=[";", "rm", "-rf", "/"])

        assert exc_info.value.error_code == ERROR_INVALID_ARGS
        mock_run.assert_not_called()

    @patch("execution_policy.subprocess.run")
    def test_timeout_returns_standardized_error(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        mock_run.side_effect = TimeoutExpired("/usr/bin/uptime", COMMAND_TIMEOUT_SECONDS)

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            result = execute_allowed_command("uptime")

        assert result.success is False
        assert result.error_code == ERROR_TIMEOUT
        assert result.exit_code is None

    @patch("execution_policy.subprocess.run")
    def test_output_limit_returns_standardized_error(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        self._write_default_like_policy(policy_file)
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        huge_stdout = b"a" * (300 * 1024)
        mock_run.return_value = CompletedProcess(
            args=["/usr/bin/df", "-h"],
            returncode=0,
            stdout=huge_stdout,
            stderr=b"",
        )

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            result = execute_allowed_command("disk_usage")

        assert result.success is False
        assert result.error_code == ERROR_OUTPUT_LIMIT_EXCEEDED
        assert "<truncated>" in result.stdout


class TestExecutionPolicyConfigFile:
    def test_missing_runtime_policy_file_is_created(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        monkeypatch.setattr(execution_policy, "DEFAULT_POLICY_FILE", str(policy_file))
        monkeypatch.setattr(execution_policy.os, "geteuid", lambda: 0)
        monkeypatch.delenv("ANAN_CLIENT_EXEC_POLICY_FILE", raising=False)

        created = ensure_runtime_policy_file()

        assert created == policy_file
        assert policy_file.exists()
        data = policy_file.read_text(encoding="utf-8")
        assert '"allowlist"' in data
        assert '"deny_binaries"' in data

    @patch("execution_policy.subprocess.run")
    def test_custom_policy_file_overrides_allow_and_deny(self, mock_run, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text(
            """
            {
              "allowlist": {
                "host_alias": {
                  "binary": "/usr/bin/hostname",
                  "fixed_args": [],
                  "allow_extra_args": false
                }
              },
              "deny_binaries": ["rm", "ufw"]
            }
            """,
            encoding="utf-8",
        )
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
            mock_run.return_value = CompletedProcess(args=["/usr/bin/hostname"], returncode=0, stdout=b"ok", stderr=b"")
            result = execute_allowed_command("host_alias")

        assert result.success is True
        assert mock_run.call_args.args[0] == ["/usr/bin/hostname"]

    def test_policy_file_must_be_root_owned(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text("{}", encoding="utf-8")
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=1000, st_mode=0o100600)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("hostname")

        assert exc_info.value.error_code == ERROR_DENIED_COMMAND
        assert "must be owned by root" in exc_info.value.message

    def test_policy_file_cannot_be_group_or_other_writable(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "command-policy.json"
        policy_file.write_text("{}", encoding="utf-8")
        monkeypatch.setenv("ANAN_CLIENT_EXEC_POLICY_FILE", str(policy_file))

        with patch("pathlib.Path.stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100666)):
            with pytest.raises(CommandValidationError) as exc_info:
                execute_allowed_command("hostname")

        assert exc_info.value.error_code == ERROR_DENIED_COMMAND
        assert "cannot be group/other writable" in exc_info.value.message
