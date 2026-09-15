"""
Tests for audit logging functionality
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import sys
import os

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from audit import (
    log_command_execution,
    log_policy_decision,
    log_configuration_change,
    get_audit_log_retention_info,
)


def test_command_execution_logging():
    """Test command execution event logging"""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset the logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        # Import fresh to pick up environment variable
        from audit import get_audit_logger
        audit_logger = get_audit_logger()
        
        # Log a command execution
        log_command_execution(
            timestamp=datetime.now(tz=timezone.utc),
            username="testuser",
            ip_address="192.168.1.100",
            command_name="test_command",
            binary_path="/usr/bin/test",
            command_args=["arg1", "arg2"],
            success=True,
            exit_code=0,
            error_code=None,
            denial_reason=None,
            duration_ms=123.45,
            hostname="test-host",
            source="test",
        )
        
        # Check log file was created and contains data
        log_file = Path(tmpdir) / "audit.log"
        assert log_file.exists(), "Audit log file was not created"
        
        # Read and verify log content
        log_content = log_file.read_text()
        assert len(log_content) > 0, "Audit log is empty"
        
        # Parse JSON from log
        log_entry = json.loads(log_content.strip().split(" - ", 1)[1])
        assert log_entry["event_type"] == "command_execution"
        assert log_entry["username"] == "testuser"
        assert log_entry["ip_address"] == "192.168.1.100"
        assert log_entry["command_name"] == "test_command"
        assert log_entry["binary_path"] == "/usr/bin/test"
        assert log_entry["success"] is True
        assert log_entry["exit_code"] == 0
        
        print("✓ test_command_execution_logging passed")


def test_policy_decision_logging():
    """Test policy decision event logging"""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset the logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        # Import fresh
        from audit import get_audit_logger
        audit_logger = get_audit_logger()
        
        # Log a policy decision
        log_policy_decision(
            timestamp=datetime.now(tz=timezone.utc),
            username="testuser",
            ip_address="192.168.1.100",
            command_name="denied_command",
            binary_path="/usr/bin/dangerous",
            decision="denied",
            reason="Binary 'dangerous' is denied by policy",
            hostname="test-host",
            source="test",
        )
        
        # Check log file
        log_file = Path(tmpdir) / "audit.log"
        assert log_file.exists(), "Audit log file was not created"
        
        log_content = log_file.read_text()
        log_entry = json.loads(log_content.strip().split(" - ", 1)[1])
        assert log_entry["event_type"] == "policy_decision"
        assert log_entry["decision"] == "denied"
        assert "policy" in log_entry["reason"].lower()
        
        print("✓ test_policy_decision_logging passed")


def test_configuration_change_logging():
    """Test configuration change event logging"""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset the logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        # Import fresh
        from audit import get_audit_logger
        audit_logger = get_audit_logger()
        
        # Log a configuration change
        log_configuration_change(
            timestamp=datetime.now(tz=timezone.utc),
            username="admin",
            ip_address="192.168.1.100",
            operation="add_command",
            command_name="new_cmd",
            details={"binary": "/usr/bin/new", "allow_extra_args": False},
            hostname="test-host",
            source="test",
        )
        
        # Check log file
        log_file = Path(tmpdir) / "audit.log"
        assert log_file.exists(), "Audit log file was not created"
        
        log_content = log_file.read_text()
        log_entry = json.loads(log_content.strip().split(" - ", 1)[1])
        assert log_entry["event_type"] == "configuration_change"
        assert log_entry["operation"] == "add_command"
        assert log_entry["command_name"] == "new_cmd"
        
        print("✓ test_configuration_change_logging passed")


def test_log_persistence():
    """Test that logs persist across multiple operations"""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset the logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        # Import fresh
        from audit import get_audit_logger
        
        # Log first event
        log_command_execution(
            timestamp=datetime.now(tz=timezone.utc),
            username="user1",
            ip_address="192.168.1.1",
            command_name="cmd1",
            binary_path="/bin/cmd1",
            success=True,
            exit_code=0,
            hostname="host1",
            source="api",
        )
        
        # Log second event
        log_policy_decision(
            timestamp=datetime.now(tz=timezone.utc),
            username="user2",
            ip_address="192.168.1.2",
            command_name="cmd2",
            binary_path="/bin/cmd2",
            decision="denied",
            reason="Test",
            hostname="host1",
            source="api",
        )
        
        # Verify both events are in log
        log_file = Path(tmpdir) / "audit.log"
        log_content = log_file.read_text()
        lines = log_content.strip().split('\n')
        
        assert len(lines) == 2, f"Expected 2 log entries, got {len(lines)}"
        
        entry1 = json.loads(lines[0].split(" - ", 1)[1])
        entry2 = json.loads(lines[1].split(" - ", 1)[1])
        
        assert entry1["event_type"] == "command_execution"
        assert entry2["event_type"] == "policy_decision"
        
        print("✓ test_log_persistence passed")


if __name__ == "__main__":
    print("Running audit logging tests...\n")
    test_command_execution_logging()
    test_policy_decision_logging()
    test_configuration_change_logging()
    test_log_persistence()
    print("\n✅ All audit logging tests passed!")
