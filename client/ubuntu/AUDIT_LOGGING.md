# Audit Logging Implementation

## Overview

The ANAN Client now includes a comprehensive audit logging system that captures all security-relevant events. Audit logs are automatically retained for 30 days and persist across service restarts.

## Features

### 1. **Comprehensive Event Capture**
   - **Timestamp**: UTC timestamp with timezone information (ISO 8601 format)
   - **Username**: Extracted from request headers or payload
   - **IP Address**: Source IP address of the requester
   - **Command Information**: Logical command name and actual binary path
   - **Execution Result**: Success/denied status and exit code
   - **Denial Reason**: Detailed reason if command was denied
   - **Duration**: Execution time in milliseconds
   - **Hostname**: Target system hostname
   - **Source**: Source identifier for the request

### 2. **Event Types**

#### Command Execution Events
- Captured when a command is executed (successfully or denied)
- Includes command binary path, arguments, exit code, and error details
- Stored in audit log with full context

**Successful Execution Example:**
```json
{
  "event_type": "command_execution",
  "timestamp": "2024-08-09T10:30:45.123456+00:00",
  "username": "admin",
  "ip_address": "192.168.1.100",
  "source": "api",
  "hostname": "ubuntu-client",
  "command_name": "get_status",
  "binary_path": "/usr/bin/systemctl",
  "command_args": ["status", "nginx"],
  "success": true,
  "exit_code": 0,
  "error_code": null,
  "denial_reason": null,
  "duration_ms": 125.45
}
```

**Denied Command Example:**
```json
{
  "event_type": "command_execution",
  "timestamp": "2024-08-09T10:35:22.654321+00:00",
  "username": "attacker",
  "ip_address": "192.168.1.50",
  "source": "external-api",
  "hostname": "ubuntu-client",
  "command_name": "delete_files",
  "binary_path": "/bin/rm",
  "command_args": ["important_file.txt"],
  "success": false,
  "exit_code": null,
  "error_code": "denied_command",
  "denial_reason": "Binary 'rm' is denied by policy.",
  "duration_ms": 5.12
}
```

**Key Points for Denied Commands:**
- `success` is always `false`
- `error_code` identifies the type of denial (e.g., `"denied_command"`, `"invalid_args"`, `"timeout"`)
- `denial_reason` provides a detailed explanation of why the command was denied
- `exit_code` is `null` for denied commands
- `command_args` are logged even for denied commands to show what was attempted

#### Policy Decision Events
- Recorded when a command is denied by policy enforcement
- Includes the decision reason and policy violation details

Example event:
```json
{
  "event_type": "policy_decision",
  "timestamp": "2024-08-09T10:35:12.789012+00:00",
  "username": "user",
  "ip_address": "192.168.1.101",
  "source": "api",
  "hostname": "ubuntu-client",
  "command_name": "dangerous_cmd",
  "binary_path": "rm",
  "decision": "denied",
  "reason": "Binary 'rm' is denied by policy."
}
```

#### Configuration Change Events
- Logged when the command execution policy is modified
- Tracks additions and removals of allowed commands

Example event:
```json
{
  "event_type": "configuration_change",
  "timestamp": "2024-08-09T10:40:00.456789+00:00",
  "username": "admin",
  "ip_address": "192.168.1.100",
  "source": "api",
  "hostname": "ubuntu-client",
  "operation": "add_command",
  "command_name": "backup_database",
  "details": {
    "binary": "/usr/local/bin/backup.sh",
    "fixed_args": ["--safe"],
    "allow_extra_args": false
  }
}
```

### 3. **Error Codes and Denial Reasons**

When a command is denied, the audit log includes both an `error_code` and a `denial_reason`. Here are the possible error codes:

| Error Code | Denial Reason | Description |
|-----------|---------------|-------------|
| `denied_command` | "Binary 'X' is denied by policy." or "Command 'X' is not allowed." | Command is not in the allowlist or binary is in the deny list |
| `invalid_args` | "Invalid arguments" or "Extra arguments are not allowed for this command." | Invalid or disallowed arguments provided |
| `timeout` | "Command execution timeout" | Command execution exceeded timeout limit (15 seconds) |
| `output_limit_exceeded` | "Output limit exceeded" | Command output exceeded size limit (256 KB) |

Example audit log entry for each type:

**Denied Command (not in allowlist):**
```json
{
  "success": false,
  "error_code": "denied_command",
  "denial_reason": "Command 'unknown_cmd' is not allowed.",
  "exit_code": null
}
```

**Denied Command (binary in deny list):**
```json
{
  "success": false,
  "error_code": "denied_command",
  "denial_reason": "Binary 'rm' is denied by policy.",
  "exit_code": null
}
```

**Invalid Arguments:**
```json
{
  "success": false,
  "error_code": "invalid_args",
  "denial_reason": "Extra arguments are not allowed for this command.",
  "exit_code": null
}
```

**Command Timeout:**
```json
{
  "success": false,
  "error_code": "timeout",
  "denial_reason": "Command execution timeout",
  "exit_code": null
}
```

## Storage and Retention

### Log Location
- **Default**: `logs/audit/audit.log`
- **Environment Variable**: `ANAN_CLIENT_AUDIT_LOG_DIR`

To customize the audit log directory:
```bash
export ANAN_CLIENT_AUDIT_LOG_DIR=/var/log/anan/audit
```

### Retention Policy
- **Retention Period**: 30 days (configurable in audit.py)
- **Cleanup Strategy**: Automatic cleanup of logs older than retention period
- **Frequency**: Cleanup runs on service startup
- **Persistence**: Logs persist across service restarts (append mode)

### Log Format
Each line in the audit log is a complete JSON object for easy parsing and analysis:
```
2024-08-09 10:30:45 - {"event_type": "command_execution", ...}
2024-08-09 10:35:12 - {"event_type": "policy_decision", ...}
```

## API Endpoints

### New Endpoints

#### GET `/audit/info`
Returns information about audit log retention and current status.

**Authentication**: Required (API key)

**Response**:
```json
{
  "audit_logs": {
    "log_directory": "/home/ashutosh/anan-ubuntu-client/logs/audit",
    "retention_days": 30,
    "total_size_bytes": 1024576,
    "log_files": [
      {
        "filename": "audit.log",
        "size_bytes": 1024576,
        "modified": "2024-08-09T10:50:00+00:00"
      }
    ],
    "file_count": 1
  },
  "caller_identity": {
    "username": "admin",
    "source": "api",
    "agent_ip": "192.168.1.100"
  }
}
```

## Configuration

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANAN_CLIENT_AUDIT_LOG_DIR` | `logs/audit` | Directory for audit log files |
| `ANAN_CLIENT_REQUEST_LOG_FILE` | `logs/anan-client-requests.log` | HTTP request log file |
| `ANAN_CLIENT_LOG_RESPONSE_BODY` | `true` | Whether to log response bodies |

## Usage Examples

### View Audit Logs

```bash
# View all audit logs
cat logs/audit/audit.log

# Filter for denied commands
grep "denied" logs/audit/audit.log

# Count events by type
grep -o '"event_type":"[^"]*' logs/audit/audit.log | sort | uniq -c

# Find all commands executed by a specific user
grep '"username":"admin"' logs/audit/audit.log
```

### Parse JSON Logs

```bash
# Pretty print audit logs
cat logs/audit/audit.log | jq '.'

# Extract only successful command executions
cat logs/audit/audit.log | jq 'select(.event_type=="command_execution" and .success==true)'

# Find all denied commands by policy
cat logs/audit/audit.log | jq 'select(.event_type=="policy_decision" and .decision=="denied")'

# Get audit logs for a specific date
cat logs/audit/audit.log | jq "select(.timestamp | startswith(\"2024-08-09\"))"
```

### Query Audit Info via API

```bash
# Get audit log information
curl -H "X-API-Key: your-api-key" \
  https://client-host:8000/audit/info

# Format output nicely
curl -H "X-API-Key: your-api-key" \
  https://client-host:8000/audit/info | jq '.'
```

## Security Considerations

### Log Protection
- Audit logs should be stored with restricted file permissions
- Consider implementing log aggregation to centralized logging systems
- Ensure audit logs are backed up regularly
- Monitor audit logs for suspicious patterns

### What Gets Logged
- ✅ All command execution attempts (success and failure)
- ✅ Policy decisions and enforcement actions
- ✅ Configuration changes to the execution policy
- ✅ Source IP addresses and usernames
- ✅ Error codes and denial reasons
- ⚠️ Command output is NOT included in audit logs (only stored in request logs)

### Log Analysis Recommendations
1. Monitor for repeated failed attempts from the same IP/user
2. Alert on any policy configuration changes
3. Review denied commands for patterns indicating attack attempts
4. Track successful execution of sensitive commands
5. Verify audit logs are being rotated on schedule

## Implementation Details

### Module: `src/audit.py`

The audit logging module provides:
- `get_audit_logger()`: Returns configured audit logger instance
- `log_command_execution()`: Logs command execution events
- `log_policy_decision()`: Logs policy enforcement decisions
- `log_configuration_change()`: Logs policy modifications
- `log_access_attempt()`: Logs API access attempts
- `get_audit_log_retention_info()`: Returns audit log statistics
- `_cleanup_old_audit_logs()`: Automatic cleanup of old logs

### Log Rotation Strategy
- Uses daily log file naming scheme
- Automatic cleanup on service startup
- Configurable retention period (default: 30 days)
- Append mode ensures logs persist across restarts

## Testing

### Manual Testing

```bash
# 1. Start the service
python -m uvicorn src.app:app --reload

# 2. Execute a command
curl -H "X-API-Key: test-key" \
  -H "X-Caller-Username: testuser" \
  -H "X-Agent-IP: 192.168.1.1" \
  -H "Content-Type: application/json" \
  -d '{"command_name": "hostname"}' \
  http://localhost:8000/commands/run

# 3. Check audit log
cat logs/audit/audit.log | jq '.'

# 4. Get audit info
curl -H "X-API-Key: test-key" http://localhost:8000/audit/info | jq '.'
```

## Future Enhancements

1. **Log Rotation**: Implement size-based rotation in addition to time-based
2. **Encryption**: Encrypt audit logs at rest
3. **Log Streaming**: Stream logs to external systems (syslog, ELK, etc.)
4. **Alerting**: Real-time alerts for suspicious activities
5. **Search API**: Full-text search endpoint for audit logs
6. **Compliance Reports**: Generate compliance and audit reports
7. **Signatures**: Digital signatures for log tamper detection
