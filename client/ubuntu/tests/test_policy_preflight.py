from unittest.mock import patch

from execution_policy import CommandValidationError, ExecutionPolicy
from policy_preflight import main


def test_preflight_success_returns_zero(capsys):
    with patch(
        "policy_preflight.load_execution_policy",
        return_value=ExecutionPolicy(allowlist={}, deny_binaries=set()),
    ):
        exit_code = main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Policy preflight passed" in captured.out


def test_preflight_policy_error_returns_one(capsys):
    with patch(
        "policy_preflight.load_execution_policy",
        side_effect=CommandValidationError("denied_command", "bad permissions"),
    ):
        exit_code = main()

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Policy preflight failed" in captured.err
