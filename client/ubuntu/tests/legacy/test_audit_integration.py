"""
Integration test demonstrating audit logging with mock FastAPI endpoints
This test shows how audit events are captured during API operations.
"""

import json
import tempfile
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from audit import (
    log_command_execution,
    log_policy_decision,
    log_configuration_change,
)


def simulate_command_execution_success():
    """Simulate successful command execution audit trail"""
    print("\n📋 Scenario 1: Successful Command Execution")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        from audit import get_audit_logger
        audit_logger = get_audit_logger()
        
        # User executes 'get_status' command successfully
        print("User: admin (192.168.1.100)")
        print("Action: Execute 'get_status' command")
        print()
        
        log_command_execution(
            timestamp=datetime.now(tz=timezone.utc),
            username="admin",
            ip_address="192.168.1.100",
            command_name="get_status",
            binary_path="/usr/bin/systemctl",
            command_args=["status", "nginx"],
            success=True,
            exit_code=0,
            error_code=None,
            denial_reason=None,
            duration_ms=245.67,
            hostname="prod-server",
            source="web-ui",
        )
        
        # Display audit log
        log_file = Path(tmpdir) / "audit.log"
        log_entry = json.loads(log_file.read_text().strip().split(" - ", 1)[1])
        
        print("Audit Log Entry:")
        print(json.dumps(log_entry, indent=2))
        print()
        print("✓ Success: Command executed and logged")


def simulate_denied_command():
    """Simulate denied command attempt"""
    print("\n📋 Scenario 2: Denied Command Attempt")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        from audit import get_audit_logger
        audit_logger = get_audit_logger()
        
        print("User: attacker (192.168.1.50)")
        print("Action: Attempt to execute 'rm' command")
        print()
        
        # Log policy decision - command denied
        log_policy_decision(
            timestamp=datetime.now(tz=timezone.utc),
            username="attacker",
            ip_address="192.168.1.50",
            command_name="delete_files",
            binary_path="rm",
            decision="denied",
            reason="Binary 'rm' is denied by policy.",
            hostname="prod-server",
            source="external-api",
        )
        
        # Also log execution attempt
        log_command_execution(
            timestamp=datetime.now(tz=timezone.utc),
            username="attacker",
            ip_address="192.168.1.50",
            command_name="delete_files",
            binary_path="rm",
            success=False,
            exit_code=None,
            error_code="denied_command",
            denial_reason="Binary 'rm' is denied by policy.",
            duration_ms=5.12,
            hostname="prod-server",
            source="external-api",
        )
        
        # Display audit logs
        log_file = Path(tmpdir) / "audit.log"
        log_content = log_file.read_text()
        lines = log_content.strip().split('\n')
        
        print("Audit Log Entries:")
        for i, line in enumerate(lines, 1):
            log_entry = json.loads(line.split(" - ", 1)[1])
            print(f"\nEntry {i} ({log_entry['event_type']}):")
            print(json.dumps(log_entry, indent=2))
        
        print("\n✓ Alert: Denied command attempt has been logged")


def simulate_policy_change():
    """Simulate policy configuration change"""
    print("\n📋 Scenario 3: Policy Configuration Change")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Reset logger
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        from audit import get_audit_logger
        audit_logger = get_audit_logger()
        
        print("User: admin (192.168.1.100)")
        print("Action: Add new command to execution policy")
        print()
        
        # Admin adds new allowed command
        log_configuration_change(
            timestamp=datetime.now(tz=timezone.utc),
            username="admin",
            ip_address="192.168.1.100",
            operation="add_command",
            command_name="backup_database",
            details={
                "binary": "/usr/local/bin/backup.sh",
                "fixed_args": ["--safe"],
                "allow_extra_args": False,
            },
            hostname="prod-server",
            source="management-api",
        )
        
        # Display audit log
        log_file = Path(tmpdir) / "audit.log"
        log_entry = json.loads(log_file.read_text().strip().split(" - ", 1)[1])
        
        print("Audit Log Entry:")
        print(json.dumps(log_entry, indent=2))
        print()
        print("✓ Info: Policy change has been recorded")


def simulate_audit_retention():
    """Demonstrate audit log retention and cleanup"""
    print("\n📋 Scenario 4: Audit Log Retention")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['ANAN_CLIENT_AUDIT_LOG_DIR'] = tmpdir
        
        # Create multiple audit entries
        import logging
        logger = logging.getLogger("anan_client.audit")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        from audit import get_audit_logger, get_audit_log_retention_info
        audit_logger = get_audit_logger()
        
        print("Creating sample audit entries...")
        print()
        
        # Log 5 different events
        for i in range(5):
            log_command_execution(
                timestamp=datetime.now(tz=timezone.utc),
                username=f"user{i}",
                ip_address=f"192.168.1.{100+i}",
                command_name=f"command_{i}",
                binary_path=f"/usr/bin/cmd{i}",
                success=True,
                exit_code=0,
                hostname="server",
                source="api",
            )
        
        # Get retention info
        retention_info = get_audit_log_retention_info()
        
        print("Audit Log Retention Information:")
        print(json.dumps(retention_info, indent=2))
        print()
        print(f"✓ {retention_info['file_count']} log file(s)")
        print(f"✓ Total size: {retention_info['total_size_bytes']} bytes")
        print(f"✓ Retention period: {retention_info['retention_days']} days")
        print(f"✓ Automatic cleanup enabled on service startup")


def main():
    print("\n" + "="*60)
    print("AUDIT LOGGING INTEGRATION TEST")
    print("="*60)
    
    simulate_command_execution_success()
    simulate_denied_command()
    simulate_policy_change()
    simulate_audit_retention()
    
    print("\n" + "="*60)
    print("✅ All integration scenarios completed successfully!")
    print("="*60)
    print("\nKey Features Demonstrated:")
    print("  ✓ Comprehensive command execution logging")
    print("  ✓ Policy decision and denial tracking")
    print("  ✓ Configuration change audit trail")
    print("  ✓ Log retention and statistics")
    print("  ✓ JSON-formatted, machine-parseable events")


if __name__ == "__main__":
    main()
