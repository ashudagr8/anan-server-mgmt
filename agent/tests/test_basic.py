import json
import logging
import asyncio
import os

import httpx

from anan_agent import (
    GeminiProviderAdapter,
    _detect_duplicate_registrations,
    _extract_existing_command_keys,
    _is_add_cli_from_file_intent,
    _load_registration_entries_from_file,
    _prompt_and_load_registration_entries,
    _resolve_registration_tool_name,
    apply_user_guided_registration_changes,
    build_unavailable_tool_message,
    build_tool_payload,
    execute_tool,
    extract_readonly_commands_catalog,
    extract_inline_tool_calls,
    fallback_unavailable_tools_to_readonly,
    find_unavailable_tool_names,
    format_registration_payload_lines,
    format_chat_message,
    get_available_tool_names,
    get_tool_input_schema,
    is_read_only_information_request,
    infer_readonly_command_from_keywords,
    load_config,
    normalize_provider,
    normalize_tool_arguments,
    parse_unknown_readonly_command_error,
    pick_nearest_registered_command,
    prompt_tool_confirmation,
    render_terminal_text,
    resolve_add_client_command_confirmation,
    should_attempt_tool_auto_continue,
    synthesize_readonly_tool_calls,
    trim_to_sentence_limit,
    with_mcp_retry,
)


def test_load_config_default():
    config = load_config()
    assert config["model_provider"] == "ollama"
    assert isinstance(config["ollama_model"], str)
    assert config["ollama_model"]
    assert isinstance(config["gemini_model"], str)
    assert config["gemini_model"]
    assert isinstance(config["gemini_api_key"], str)
    assert "github_model" not in config
    assert "github_base_url" not in config
    assert "github_token" not in config
    assert config["mcp_server_url"] == ""
    assert config["mcp_base_url"] == ""
    assert isinstance(config["temperature"], float)
    assert 0.0 <= config["temperature"] <= 2.0
    assert isinstance(config["assistant_max_sentences"], int)
    assert config["assistant_max_sentences"] > 0
    assert isinstance(config["system_prompt"], str)
    assert config["system_prompt"]
    assert isinstance(config["oauth_enabled"], bool)
    assert isinstance(config["oauth_token_url"], str)
    assert isinstance(config["oauth_client_id"], str)
    assert isinstance(config["oauth_client_secret"], str)
    assert isinstance(config["oauth_audience"], str)
    assert isinstance(config["oauth_scope"], str)


def test_load_config_explicit(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "model_provider": "github",
        "ollama_model": "test-model",
        "MCP_BASE_URL": "https://example.com/mcp",
        "OAUTH_ENABLED": True,
        "OAUTH_TOKEN_URL": "https://issuer.example.com/oauth/token",
        "OAUTH_CLIENT_ID": "client-id",
        "OAUTH_CLIENT_SECRET": "client-secret",
        "OAUTH_AUDIENCE": "https://api.example.com",
        "OAUTH_SCOPE": "mcp.read mcp.write",
        "temperature": 0.2,
        "assistant_max_sentences": 2,
        "system_prompt": "You are test system prompt"
    }), encoding="utf-8")

    config = load_config(str(config_file))
    assert config["model_provider"] == "ollama"
    assert config["ollama_model"] == "test-model"
    assert "github_model" not in config
    assert "github_base_url" not in config
    assert "github_token" not in config
    assert config["mcp_server_url"] == "https://example.com/mcp"
    assert config["mcp_base_url"] == "https://example.com/mcp"
    assert config["temperature"] == 0.2
    assert config["assistant_max_sentences"] == 2
    assert config["system_prompt"] == "You are test system prompt"
    assert config["oauth_enabled"] is True
    assert config["oauth_token_url"] == "https://issuer.example.com/oauth/token"
    assert config["oauth_client_id"] == "client-id"
    assert config["oauth_client_secret"] == "client-secret"
    assert config["oauth_audience"] == "https://api.example.com"
    assert config["oauth_scope"] == "mcp.read mcp.write"


def test_load_config_system_prompt_lines(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "ollama_model": "test-model",
        "mcp_server_url": "https://example.com/mcp",
        "temperature": 0.4,
        "assistant_max_sentences": 1,
        "system_prompt": [
            "Line one",
            "Line two",
            "Line three"
        ]
    }), encoding="utf-8")

    config = load_config(str(config_file))
    assert config["temperature"] == 0.4
    assert config["system_prompt"] == "Line one\nLine two\nLine three"


def test_load_config_gemini_provider(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "model_provider": "gemini",
        "GEMINI_MODEL": "gemini-2.0-flash",
        "GEMINI_API_KEY": "test-api-key",
        "MCP_BASE_URL": "https://example.com/mcp"
    }), encoding="utf-8")

    config = load_config(str(config_file))
    assert config["model_provider"] == "gemini"
    assert config["gemini_model"] == "gemini-2.0-flash"
    assert config["gemini_api_key"] == "test-api-key"


def test_load_config_ssl_verify_setting(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "MCP_BASE_URL": "https://example.com/mcp",
        "VERIFY_SSL_CERTIFICATE": False,
    }), encoding="utf-8")

    config = load_config(str(config_file))
    assert config["verify_ssl_certificate"] is False


def test_with_mcp_retry_passes_verify_flag_to_transport(monkeypatch):
    captured = {}

    class FakeTransport:
        def __init__(self, url, headers=None, auth=None, verify=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["auth"] = auth
            captured["verify"] = verify

    class FakeMCPClient:
        def __init__(self, transport):
            captured["transport"] = transport

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_operation(mcp):
        return {"ok": True}

    monkeypatch.setattr("anan_agent.StreamableHttpTransport", FakeTransport)
    monkeypatch.setattr("anan_agent.MCPClient", FakeMCPClient)
    monkeypatch.setattr("anan_agent.build_oauth_token_manager", lambda _settings: None)
    monkeypatch.setattr("anan_agent.build_mcp_identity_headers", lambda: {"X-Agent-Username": "tester"})

    result = asyncio.run(with_mcp_retry({
        "mcp_server_url": "https://example.com/mcp",
        "oauth_enabled": False,
        "verify_ssl_certificate": False,
    }, fake_operation))

    assert result == {"ok": True}
    assert captured["verify"] is False
    assert captured["url"] == "https://example.com/mcp"


def test_normalize_provider_supports_gemini_aliases():
    assert normalize_provider("gemini", "ollama") == "gemini"
    assert normalize_provider("google_gemini", "ollama") == "gemini"
    assert normalize_provider("google", "ollama") == "gemini"
    assert normalize_provider("ollama", "gemini") == "ollama"


def test_normalize_provider_supports_openrouter_aliases():
    assert normalize_provider("openrouter", "ollama") == "openrouter"
    assert normalize_provider("open_router", "ollama") == "openrouter"
    assert normalize_provider("openrouter.ai", "ollama") == "openrouter"


def test_load_config_openrouter_provider(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "model_provider": "openrouter",
        "OPENROUTER_MODEL": "openai/gpt-4o-mini",
        "OPENROUTER_API_KEY": "test-openrouter-key",
        "MCP_BASE_URL": "https://example.com/mcp"
    }), encoding="utf-8")

    config = load_config(str(config_file))
    assert config["model_provider"] == "openrouter"
    assert config["openrouter_model"] == "openai/gpt-4o-mini"
    assert config["openrouter_api_key"] == "test-openrouter-key"


def test_gemini_parameters_sanitizer_removes_unsupported_schema_fields():
    adapter = GeminiProviderAdapter()
    sanitized = adapter._sanitize_gemini_parameters(
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "command_name": {
                    "type": "string",
                    "description": "Command to run",
                },
                "flags": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["command_name", "unknown_field"],
        }
    )

    assert sanitized["type"] == "OBJECT"
    assert "additionalProperties" not in sanitized
    assert sanitized["properties"]["command_name"]["type"] == "STRING"
    assert sanitized["properties"]["flags"]["type"] == "ARRAY"
    assert sanitized["required"] == ["command_name"]


def test_load_config_invalid_json_logs_warning(tmp_path, caplog):
    config_file = tmp_path / "config.json"
    config_file.write_text('{"model_provider": "ollama",}', encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="anan_agent"):
        config = load_config(str(config_file))

    assert config["model_provider"] == "ollama"
    assert "Invalid config" in caplog.text


def test_connection_errors_are_classified_as_server_unreachable():
    from anan_agent import is_server_unreachable_error

    assert is_server_unreachable_error(httpx.ConnectError("connection refused")) is True
    assert is_server_unreachable_error(httpx.ConnectTimeout("timed out")) is True
    assert is_server_unreachable_error(RuntimeError("Connection refused by server")) is True
    assert is_server_unreachable_error(RuntimeError("401 Unauthorized")) is False


def test_trim_to_sentence_limit_keeps_first_sentence():
    text = "First sentence. Second sentence. Third sentence."
    assert trim_to_sentence_limit(text, 1) == "First sentence."


def test_render_terminal_text_formats_markdown_tables():
    text = "Here is the status:\n\n| Name | Status |\n| --- | --- |\n| Alpha | OK |\n| Beta | Needs review |\n"

    rendered = render_terminal_text(text)

    assert "Here is the status:" in rendered
    assert "| Name | Status |" not in rendered
    assert "Alpha" in rendered
    assert "Needs review" in rendered
    assert "+" in rendered


def test_render_terminal_text_wraps_long_markdown_table_cells(monkeypatch):
    monkeypatch.setattr(
        "anan_agent.shutil.get_terminal_size",
        lambda fallback: os.terminal_size((50, 24)),
    )
    command = "/opt/example/bin/process --config /tmp/sample.conf --with-extra-arguments that must wrap cleanly"
    text = (
        "Top process:\n\n"
        "| PID | Command |\n"
        "| --- | --- |\n"
        f"| 123 | {command} |\n"
    )

    rendered = render_terminal_text(text)
    lines = rendered.splitlines()

    assert command not in rendered
    assert any(line.startswith("| 123 ") for line in lines)
    assert sum(1 for line in lines if line.startswith("|     | ")) >= 2
    assert any(line.startswith("|     | ") and "cleanly" in line for line in lines)


def test_render_terminal_text_formats_json_payloads():
    rendered = render_terminal_text('{"status": "success", "upgrades": [{"package": "apt", "type": "security"}]}')

    assert "status: success" in rendered
    assert "upgrades:" in rendered
    assert "package" in rendered
    assert "apt" in rendered
    assert '"status": "success"' not in rendered


def test_render_terminal_text_formats_fenced_json_blocks():
    rendered = render_terminal_text("Here is the result:\n\n```json\n{\"status\": \"success\", \"count\": 2}\n```")

    assert "Here is the result:" in rendered
    assert "status: success" in rendered
    assert "count: 2" in rendered
    assert "```json" not in rendered


def test_format_chat_message_for_assistant_adds_header_and_border():
    rendered = format_chat_message("assistant", "First line\nSecond line", timestamp="09:41")

    assert rendered.startswith("Assistant  09:41")
    assert "\n| First line" in rendered
    assert "\n| Second line" in rendered


def test_format_chat_message_for_user_adds_header_without_assistant_border():
    rendered = format_chat_message("user", "Check firewall status", timestamp="09:42")

    assert rendered.startswith("You  09:42")
    assert "\n  Check firewall status" in rendered
    assert "\n| " not in rendered


class _FakeTextItem:
    def __init__(self, text):
        self.text = text


class _FakeToolResult:
    def __init__(self, structured_content=None, content=None):
        self.structured_content = structured_content
        self.content = content if content is not None else []


def test_build_tool_payload_prefers_structured_content():
    result = _FakeToolResult(structured_content={"commands": [{"name": "uptime"}]})
    payload = build_tool_payload(result)
    assert payload == '{"commands": [{"name": "uptime"}]}'


def test_build_tool_payload_uses_text_content_when_no_structured_content():
    result = _FakeToolResult(content=[_FakeTextItem("line 1"), _FakeTextItem("line 2")])
    payload = build_tool_payload(result)
    assert payload == "line 1\nline 2"


def test_build_tool_payload_formats_process_snapshot_for_readonly_cli_run():
    stdout = (
        "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        "root 100 0.0 0.1 1 1 ? S Aug07 0:00 [kthreadd]\n"
        "ashutosh 200 2.3 1.2 1 1 ? Sl Aug07 0:01 /home/ashutosh/.vscode-server/server/node\n"
        "root 300 0.4 2.8 1 1 ? Sl Aug07 0:02 /usr/bin/python -m uvicorn app:app\n"
        "ashutosh 400 1.1 5.5 1 1 ? Sl Aug07 0:03 pylance-server\n"
    )
    result = _FakeToolResult(structured_content={
        "command_name": "process_list",
        "success": True,
        "stdout": stdout,
        "exit_code": 0,
        "duration_ms": 12.5,
    })

    payload = build_tool_payload(result, tool_name="readonly_cli_run")
    parsed = json.loads(payload)

    assert parsed["command_name"] == "process_list"
    assert parsed["success"] is True
    assert parsed["summary"]["total_processes"] == 4
    assert parsed["summary"]["running"] == 0
    assert parsed["summary"]["sleeping"] == 4
    assert parsed["summary"]["kernel_threads"] == 1
    assert parsed["top_cpu"][0]["pid"] == 200
    assert parsed["top_memory"][0]["pid"] == 400
    assert parsed["raw_output_omitted"] is True
    assert "VS Code server processes detected" in parsed["notable"]
    assert "MCP server process detected" in parsed["notable"]
    assert "Python language server process detected" in parsed["notable"]


def test_build_tool_payload_keeps_non_process_readonly_cli_run_payload():
    result = _FakeToolResult(structured_content={
        "command_name": "uptime",
        "success": True,
        "stdout": "10:00 up 1 day",
    })

    payload = build_tool_payload(result, tool_name="readonly_cli_run")
    parsed = json.loads(payload)

    assert parsed["command_name"] == "uptime"
    assert parsed["stdout"] == "10:00 up 1 day"


def test_extract_inline_tool_calls_parses_function_markup():
    reply, tool_calls = extract_inline_tool_calls(
        "I'll help with that.\n\n"
        "<function=readonly_cli_run>\n"
        "<parameter=command_name>\n"
        "top\n"
        "</parameter>\n"
        "<parameter=client_name>\n"
        "default\n"
        "</parameter>\n"
        "</function>\n"
        "</tool_call>"
    )

    assert reply == "I'll help with that."
    assert tool_calls == [{
        "id": None,
        "name": "readonly_cli_run",
        "arguments": {
            "command_name": "top",
            "client_name": "default",
        },
    }]


def test_extract_inline_tool_calls_returns_original_text_without_markup():
    reply, tool_calls = extract_inline_tool_calls("Plain assistant reply")

    assert reply == "Plain assistant reply"
    assert tool_calls == []


def test_normalize_tool_arguments_add_client_command_parses_list_fields_and_binary(monkeypatch):
    monkeypatch.setattr("anan_agent.shutil.which", lambda value: "/usr/bin/apt" if value == "apt" else None)

    normalized = normalize_tool_arguments(
        "add_client_command",
        {
            "command_name": "check_pending_upgrades",
            "binary": "apt",
            "aliases": '["pending-upgrades", "check-upgrades"]',
            "fixed_args": '["list", "-u"]',
            "allow_extra_args": "false",
            "sync_with_clients": "true",
        },
    )

    assert normalized["binary"] == "/usr/bin/apt"
    assert normalized["aliases"] == ["pending-upgrades", "check-upgrades"]
    assert normalized["fixed_args"] == ["list", "-u"]
    assert normalized["allow_extra_args"] is False
    assert normalized["sync_with_clients"] is True


def test_normalize_tool_arguments_add_client_command_requires_absolute_binary_when_unresolvable(monkeypatch):
    monkeypatch.setattr("anan_agent.shutil.which", lambda _value: None)

    try:
        normalize_tool_arguments(
            "add_client_command",
            {
                "command_name": "check_pending_upgrades",
                "binary": "apt",
                "aliases": ["pending-upgrades"],
                "fixed_args": ["list", "-u"],
            },
        )
        raise AssertionError("Expected ValueError for unresolved non-absolute binary")
    except ValueError as exc:
        assert "absolute binary path" in str(exc)


def test_load_registration_entries_from_file_accepts_single_object(tmp_path):
    payload = {
        "command_name": "check_updates",
        "binary": "/usr/bin/apt",
        "fixed_args": ["list", "-u"],
    }
    config_file = tmp_path / "registrations.json"
    config_file.write_text(json.dumps(payload), encoding="utf-8")

    entries, resolved_path = _load_registration_entries_from_file(str(config_file))

    assert resolved_path.endswith("registrations.json")
    assert entries == [payload]


def test_load_registration_entries_from_file_accepts_commands_wrapper(tmp_path):
    payload = {
        "commands": [
            {"command_name": "check_updates", "binary": "/usr/bin/apt"},
            {"command_name": "process_list", "binary": "/usr/bin/ps"},
        ]
    }
    config_file = tmp_path / "registrations.json"
    config_file.write_text(json.dumps(payload), encoding="utf-8")

    entries, _resolved_path = _load_registration_entries_from_file(str(config_file))

    assert len(entries) == 2
    assert entries[0]["command_name"] == "check_updates"
    assert entries[1]["command_name"] == "process_list"


def test_prompt_and_load_registration_entries_retries_until_valid_path(tmp_path):
    valid_payload = {
        "commands": [
            {
                "command_name": "check_updates",
                "binary": "/usr/bin/apt",
            }
        ]
    }
    valid_file = tmp_path / "registrations.json"
    valid_file.write_text(json.dumps(valid_payload), encoding="utf-8")

    responses = iter(["abc.json", str(valid_file)])
    outputs = []

    entries, resolved_path, cancel_message = _prompt_and_load_registration_entries(
        input_fn=lambda _prompt: next(responses),
        output_fn=outputs.append,
    )

    assert cancel_message == ""
    assert resolved_path.endswith("registrations.json")
    assert len(entries) == 1
    assert entries[0]["command_name"] == "check_updates"
    assert any("File validation failed:" in line for line in outputs)


def test_prompt_and_load_registration_entries_cancels_on_cancel_token():
    outputs = []

    entries, resolved_path, cancel_message = _prompt_and_load_registration_entries(
        input_fn=lambda _prompt: "cancel",
        output_fn=outputs.append,
    )

    assert entries is None
    assert resolved_path is None
    assert cancel_message == "Registration cancelled by user."


def test_prompt_and_load_registration_entries_retries_on_empty_input():
    responses = iter(["", "exit"])
    outputs = []

    entries, resolved_path, cancel_message = _prompt_and_load_registration_entries(
        input_fn=lambda _prompt: next(responses),
        output_fn=outputs.append,
    )

    assert entries is None
    assert resolved_path is None
    assert cancel_message == "Registration cancelled by user."
    assert any("File path cannot be empty." in line for line in outputs)


def test_extract_existing_command_keys_reads_names_and_aliases():
    names, aliases = _extract_existing_command_keys([
        {"name": "process_list", "aliases": ["ps", "processes"]},
        {"name": "Memory_Usage", "aliases": ["mem"]},
    ])

    assert names == {"process_list", "memory_usage"}
    assert aliases == {"ps", "processes", "mem"}


def test_detect_duplicate_registrations_filters_internal_duplicates():
    kept, skipped = _detect_duplicate_registrations([
        {
            "command_name": "process_list",
            "aliases": ["ps", "processes"],
        },
        {
            "command_name": "process_list",
            "aliases": ["plist"],
        },
        {
            "command_name": "uptime",
            "aliases": ["ps"],
        },
    ])

    assert len(kept) == 1
    assert kept[0]["command_name"] == "process_list"
    assert len(skipped) == 2
    assert any("duplicate command_name in file" in item["reasons"] for item in skipped)
    assert any("duplicate alias in file: ps" in item["reasons"] for item in skipped)


def test_detect_duplicate_registrations_filters_server_duplicates():
    kept, skipped = _detect_duplicate_registrations(
        [
            {"command_name": "process_list", "aliases": ["ps"]},
            {"command_name": "uptime", "aliases": ["up"]},
        ],
        existing_names={"process_list"},
        existing_aliases={"up"},
    )

    assert len(kept) == 0
    assert len(skipped) == 2
    reasons = [reason for item in skipped for reason in item["reasons"]]
    assert "command_name already exists on server" in reasons
    assert "alias already exists on server: up" in reasons


def test_is_add_cli_from_file_intent_detects_plain_add_cli_request():
    assert _is_add_cli_from_file_intent("add a new cli") is True
    assert _is_add_cli_from_file_intent("register command for uptime") is True


def test_is_add_cli_from_file_intent_rejects_remove_flows():
    assert _is_add_cli_from_file_intent("remove cli command uptime") is False
    assert _is_add_cli_from_file_intent("delete command process_snapshot") is False


def test_resolve_registration_tool_name_prefers_add_client_command():
    resolved = _resolve_registration_tool_name({"add_client_command", "add_command_or_cli"})
    assert resolved == "add_client_command"


def test_resolve_registration_tool_name_falls_back_to_add_command_or_cli():
    resolved = _resolve_registration_tool_name({"add_command_or_cli"})
    assert resolved == "add_command_or_cli"


def test_get_tool_input_schema_returns_parameters_for_matching_tool():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "add_client_command",
                "parameters": {
                    "type": "object",
                    "properties": {"binary": {"type": "string"}},
                },
            },
        }
    ]

    schema = get_tool_input_schema(tools, "add_client_command")
    assert schema == {
        "type": "object",
        "properties": {"binary": {"type": "string"}},
    }


def test_get_available_tool_names_extracts_function_names():
    tools = [
        {
            "type": "function",
            "function": {"name": "firewall_status", "parameters": {"type": "object"}},
        },
        {
            "type": "function",
            "function": {"name": "list_rules", "parameters": {"type": "object"}},
        },
    ]

    names = get_available_tool_names(tools)
    assert names == {"firewall_status", "list_rules"}


def test_find_unavailable_tool_names_returns_only_missing_names():
    requested = [
        {"name": "firewall_status", "arguments": {}},
        {"name": "non_existent_tool", "arguments": {}},
        {"name": "another_missing", "arguments": {}},
        {"name": "non_existent_tool", "arguments": {}},
    ]

    unavailable = find_unavailable_tool_names(requested, {"firewall_status", "list_rules"})
    assert unavailable == ["another_missing", "non_existent_tool"]


def test_build_unavailable_tool_message_includes_missing_names():
    message = build_unavailable_tool_message(["non_existent_tool", "unsupported_action"])
    assert "not available in this session" in message
    assert "non_existent_tool" in message
    assert "unsupported_action" in message


def test_prompt_tool_confirmation_accepts_yes_and_renders_minimal_payload():
    output = []
    schema = {"type": "object", "properties": {"binary": {"type": "string"}}}
    payload = {"binary": "/usr/bin/apt", "fixed_args": ["list", "-u"]}

    confirmation = prompt_tool_confirmation(
        "add_client_command",
        payload,
        schema,
        input_fn=lambda _prompt: "1",
        output_fn=output.append,
    )

    rendered = "\n".join(output)
    assert confirmation["approved"] is True
    assert confirmation["outcome"] == "approved"
    assert "{" not in rendered
    assert '"/usr/bin/apt"' not in rendered
    assert "- binary: /usr/bin/apt" in rendered
    assert "- fixed_args: list, -u" in rendered


def test_prompt_tool_confirmation_defaults_to_no():
    confirmation = prompt_tool_confirmation(
        "add_client_command",
        {"binary": "/usr/bin/apt"},
        {"type": "object"},
        input_fn=lambda _prompt: "",
        output_fn=lambda _line: None,
    )

    assert confirmation["approved"] is False
    assert confirmation["outcome"] == "cancelled"


def test_prompt_tool_confirmation_option_two_cancels_registration():
    confirmation = prompt_tool_confirmation(
        "add_client_command",
        {"binary": "apt"},
        {"type": "object"},
        input_fn=lambda _prompt: "2",
        output_fn=lambda _line: None,
    )

    assert confirmation["approved"] is False
    assert confirmation["outcome"] == "cancelled"
    assert confirmation["required_changes"] == ""
    assert confirmation["retry_preference"] == ""


def test_prompt_tool_confirmation_cancel_does_not_prompt_for_reason():
    confirmation = prompt_tool_confirmation(
        "add_client_command",
        {"binary": "/usr/bin/ss"},
        {"type": "object"},
        input_fn=lambda _prompt: "2",
        output_fn=lambda _line: None,
    )

    assert confirmation["approved"] is False
    assert confirmation["outcome"] == "cancelled"
    assert confirmation["cancel_reason"] == ""


def test_format_registration_payload_lines_lists_are_comma_separated():
    lines = format_registration_payload_lines({
        "command_name": "socket_stats",
        "aliases": ["ss", "socket-stats"],
        "fixed_args": [],
        "allow_extra_args": True,
    })

    rendered = "\n".join(lines)
    assert "- aliases: ss, socket-stats" in rendered
    assert "- fixed_args: (empty)" in rendered
    assert "- allow_extra_args: true" in rendered


def test_apply_user_guided_registration_changes_updates_aliases():
    payload = {
        "command_name": "socket_stats",
        "binary": "/usr/bin/ss",
        "aliases": ["ss"],
        "fixed_args": [],
    }

    updated, changed, fields = apply_user_guided_registration_changes(
        payload,
        "please modify aliases to include network connections",
    )

    assert changed is True
    assert "aliases" in fields
    assert updated["aliases"] == ["ss", "network", "connections"]


def test_resolve_add_client_command_confirmation_cancels_from_option_two():
    result = resolve_add_client_command_confirmation(
        {
            "command_name": "socket_stats",
            "binary": "/usr/bin/ss",
            "aliases": ["ss"],
            "fixed_args": [],
            "allow_extra_args": True,
        },
        {"type": "object"},
        input_fn=lambda _prompt: "2",
        output_fn=lambda _line: None,
    )

    assert result["status"] == "cancelled"


def test_resolve_add_client_command_confirmation_cancelled_status():
    result = resolve_add_client_command_confirmation(
        {
            "command_name": "socket_stats",
            "binary": "/usr/bin/ss",
            "aliases": ["ss"],
        },
        {"type": "object"},
        input_fn=lambda _prompt: "2",
        output_fn=lambda _line: None,
    )

    assert result["status"] == "cancelled"
    assert result["cancel_reason"] == ""


def test_should_attempt_tool_auto_continue_detects_intent_action_text():
    text = "I can see that there's a check_updates command available. Let me run that to see what updates are available."

    assert should_attempt_tool_auto_continue(text) is True


def test_should_attempt_tool_auto_continue_skips_questions():
    text = "I can run check_updates. Should I proceed?"

    assert should_attempt_tool_auto_continue(text) is False


def test_should_attempt_tool_auto_continue_skips_empty_or_non_string():
    assert should_attempt_tool_auto_continue("") is False
    assert should_attempt_tool_auto_continue(None) is False


def test_is_read_only_information_request_detects_show_status_queries():
    assert is_read_only_information_request("show me list of process on server") is True
    assert is_read_only_information_request("what is the current memory usage?") is True


def test_is_read_only_information_request_rejects_mutating_requests():
    assert is_read_only_information_request("remove this server from registry") is False
    assert is_read_only_information_request("install updates now") is False


def test_extract_readonly_commands_catalog_from_structured_payload():
    tool_result = _FakeToolResult(structured_content={
        "commands": [
            {
                "name": "process_list",
                "aliases": ["ps", "processes"],
                "examples": ["list running processes"],
                "description": "Report process snapshot",
                "read_only": True,
            }
        ]
    })

    catalog = extract_readonly_commands_catalog(tool_result)
    assert len(catalog) == 1
    assert catalog[0]["name"] == "process_list"
    assert "ps" in catalog[0]["aliases"]


def test_synthesize_readonly_tool_calls_prefers_direct_tool_when_high_confidence():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "list_servers",
                "description": "List all registered servers with their names and IP addresses.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "readonly_cli_run",
                "description": "Run one readonly command.",
                "parameters": {"type": "object"},
            },
        },
    ]

    readonly_catalog = [
        {
            "name": "process_list",
            "aliases": ["processes"],
            "examples": ["show running processes"],
            "description": "Report process snapshot",
            "read_only": True,
        }
    ]

    calls = synthesize_readonly_tool_calls(
        "list all registered servers",
        tools,
        {"list_servers", "readonly_cli_run"},
        readonly_catalog,
    )

    assert calls == [{"id": None, "name": "list_servers", "arguments": {}}]


def test_synthesize_readonly_tool_calls_falls_back_to_readonly_command():
    readonly_catalog = [
        {
            "name": "process_list",
            "aliases": ["ps", "running processes"],
            "examples": ["list running processes"],
            "description": "Report process snapshot",
            "read_only": True,
        }
    ]

    calls = synthesize_readonly_tool_calls(
        "show me running processes",
        [],
        {"readonly_cli_run"},
        readonly_catalog,
    )

    assert calls == [{
        "id": None,
        "name": "readonly_cli_run",
        "arguments": {"command_name": "process_list"},
    }]


def test_synthesize_readonly_tool_calls_handles_long_prompt_with_typos():
    readonly_catalog = [
        {
            "name": "process_list",
            "aliases": ["ps", "running processes", "processes"],
            "examples": ["show running processes"],
            "description": "Report a snapshot of current processes",
            "read_only": True,
        }
    ]

    calls = synthesize_readonly_tool_calls(
        "show me process running on default server in a tablur format",
        [],
        {"readonly_cli_run"},
        readonly_catalog,
    )

    assert calls == [{
        "id": None,
        "name": "readonly_cli_run",
        "arguments": {"command_name": "process_list"},
    }]


def test_fallback_unavailable_tools_to_readonly_converts_missing_name():
    readonly_catalog = [
        {"name": "process_list", "aliases": ["processes"], "examples": [], "description": "", "read_only": True},
        {"name": "memory_usage", "aliases": ["memory"], "examples": [], "description": "", "read_only": True},
    ]

    calls = fallback_unavailable_tools_to_readonly(
        ["processes"],
        "show processes",
        {"readonly_cli_run"},
        readonly_catalog,
    )

    assert calls == [{
        "id": None,
        "name": "readonly_cli_run",
        "arguments": {"command_name": "process_list"},
    }]


def test_infer_readonly_command_from_keywords_processes():
    inferred = infer_readonly_command_from_keywords("please show me list of process on default server")
    assert inferred == "process_list"


def test_synthesize_readonly_tool_calls_uses_keyword_fallback_when_catalog_empty():
    calls = synthesize_readonly_tool_calls(
        "please show me list of process on default server",
        [],
        {"readonly_cli_run"},
        [],
    )

    assert calls == [{
        "id": None,
        "name": "readonly_cli_run",
        "arguments": {"command_name": "process_list"},
    }]


def test_parse_unknown_readonly_command_error_extracts_fields():
    parsed = parse_unknown_readonly_command_error(
        "Error calling tool 'readonly_cli_run': 400: Unknown command 'time'. "
        "Registered commands: check_updates, date_now, uptime"
    )

    assert parsed["unknown_command"] == "time"
    assert parsed["registered_commands"] == ["check_updates", "date_now", "uptime"]


def test_pick_nearest_registered_command_prefers_similar_candidate():
    nearest = pick_nearest_registered_command(
        "top",
        ["check_updates", "top_snapshot", "uptime"],
    )

    assert nearest == "top_snapshot"


def test_execute_tool_readonly_cli_run_retries_once_with_nearest_command(monkeypatch):
    call_args = []

    class FakeMCP:
        async def call_tool(self, _tool_name, arguments):
            call_args.append(arguments.get("command_name"))
            if arguments.get("command_name") == "top":
                raise RuntimeError(
                    "Error calling tool 'readonly_cli_run': 400: Unknown command 'top'. "
                    "Registered commands: top_snapshot, uptime"
                )
            return {"ok": True, "executed": arguments.get("command_name")}

    async def fake_with_mcp_retry(_settings, operation, server_url=None, operation_name="mcp_call"):
        _ = server_url, operation_name
        return await operation(FakeMCP())

    async def passthrough_status(_message, operation):
        return await operation

    monkeypatch.setattr("anan_agent.load_config", lambda _config_path=None: {
        "mcp_server_url": "https://example.com/mcp",
        "oauth_enabled": False,
    })
    monkeypatch.setattr("anan_agent.with_mcp_retry", fake_with_mcp_retry)
    monkeypatch.setattr("anan_agent.run_with_animated_status", passthrough_status)

    result = asyncio.run(
        execute_tool(
            "readonly_cli_run",
            {"command_name": "top", "client_name": "default"},
            server_url="https://example.com/mcp",
        )
    )

    assert result == {"ok": True, "executed": "top_snapshot"}
    assert call_args == ["top", "top_snapshot"]


def test_execute_tool_readonly_cli_run_returns_standard_error_when_no_nearest(monkeypatch):
    class FakeMCP:
        async def call_tool(self, _tool_name, _arguments):
            raise RuntimeError(
                "Error calling tool 'readonly_cli_run': 400: Unknown command 'zzzz'. "
                "Registered commands: check_updates, process_list"
            )

    async def fake_with_mcp_retry(_settings, operation, server_url=None, operation_name="mcp_call"):
        _ = server_url, operation_name
        return await operation(FakeMCP())

    async def passthrough_status(_message, operation):
        return await operation

    monkeypatch.setattr("anan_agent.load_config", lambda _config_path=None: {
        "mcp_server_url": "https://example.com/mcp",
        "oauth_enabled": False,
    })
    monkeypatch.setattr("anan_agent.with_mcp_retry", fake_with_mcp_retry)
    monkeypatch.setattr("anan_agent.run_with_animated_status", passthrough_status)

    result = asyncio.run(
        execute_tool(
            "readonly_cli_run",
            {"command_name": "zzzz", "client_name": "default"},
            server_url="https://example.com/mcp",
        )
    )

    assert "error" in result
    assert "no close fallback command was found" in result["error"]
    assert "check_updates" in result["error"]
