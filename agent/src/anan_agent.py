from fastmcp import Client as MCPClient
import asyncio
import difflib
from datetime import datetime
import getpass
import json
import os
import re
import shutil
import sys
import textwrap
from pathlib import Path
from urllib.parse import quote

import httpx
import ollama
import logging
from logging.handlers import RotatingFileHandler
from fastmcp.client.transports.http import StreamableHttpTransport

from oauth import OAuthTokenManager


OLLAMA_MODEL = "qwen3:4b"
GEMINI_MODEL = "gemini-1.5-flash"
OPENROUTER_MODEL = "openai/gpt-4o-mini"
MODEL_PROVIDER = "ollama"
GEMINI_API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
OPENROUTER_API_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant."
DEFAULT_TEMPERATURE = 0.8
DEFAULT_ASSISTANT_MAX_SENTENCES = 20
UNAVAILABLE_TOOL_MESSAGE = (
    "I cannot execute the requested action because one or more required tools "
    "are not available in this session. I can continue only with currently "
    "registered MCP tools."
)
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "config.json"
LOG_DIR = REPO_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "anan_agent.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Reset (truncate) log file on program start to provide a fresh log per run.
try:
    LOG_FILE.open("w", encoding="utf-8").close()
except Exception:
    # If the file cannot be created/truncated, continue; logging will
    # surface issues when handlers are attached.
    pass

# Determine log levels from environment variables, with sensible defaults.
env_level = os.getenv("ANAN_AGENT_LOG_LEVEL", "DEBUG").upper()
file_level = getattr(logging, env_level, None)
if not isinstance(file_level, int):
    file_level = logging.DEBUG

console_env = os.getenv("ANAN_AGENT_CONSOLE_LEVEL", "CRITICAL").upper()
console_level = getattr(logging, console_env, None)
if not isinstance(console_level, int):
    console_level = logging.CRITICAL


class NoTracebackFormatter(logging.Formatter):
    """Format console logs without appending exception tracebacks."""

    def format(self, record):
        # Keep stack traces in file logs while suppressing them in console output.
        exc_info, exc_text = record.exc_info, record.exc_text
        record.exc_info = None
        record.exc_text = None
        try:
            return super().format(record)
        finally:
            record.exc_info = exc_info
            record.exc_text = exc_text

# Configure logger to capture code path, errors, and debug messages
logger = logging.getLogger("anan_agent")
logger.setLevel(file_level)
file_handler = RotatingFileHandler(str(LOG_FILE), maxBytes=5_000_000, backupCount=5, encoding="utf-8")
formatter = logging.Formatter("%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(funcName)s() - %(message)s")
file_handler.setFormatter(formatter)
file_handler.setLevel(file_level)
logger.addHandler(file_handler)

# Console handler uses its own level (defaults to CRITICAL)
console_handler = logging.StreamHandler()
console_handler.setLevel(console_level)
console_handler.setFormatter(NoTracebackFormatter("%(levelname)s: %(message)s"))
logger.addHandler(console_handler)

logger.debug("Logger initialized. file_level=%s console_level=%s", file_level, console_level)


_oauth_token_manager = None
_oauth_token_manager_key = None


def normalize_system_prompt(value, fallback):
    """Normalize prompt config to a non-empty string."""
    if isinstance(value, str):
        prompt = value.strip()
        return prompt if prompt else fallback

    if isinstance(value, list):
        lines = []
        for line in value:
            line_text = str(line).strip()
            if line_text:
                lines.append(line_text)
        if lines:
            return "\n".join(lines)

    return fallback


def normalize_temperature(value, fallback):
    """Normalize temperature to a float within the supported range."""
    try:
        temp = float(value)
    except (TypeError, ValueError):
        return fallback

    if temp < 0.0:
        return 0.0
    if temp > 2.0:
        return 2.0
    return temp


def normalize_provider(value, fallback):
    """Normalize configured model provider to a supported value."""
    if isinstance(value, str):
        provider = value.strip().lower()
        if provider == "ollama":
            return "ollama"
        if provider in {"gemini", "google_gemini", "google"}:
            return "gemini"
        if provider in {"openrouter", "open_router", "openrouter.ai"}:
            return "openrouter"
        if provider.replace("_", "").replace(".", "") == "openrouter":
            return "openrouter"
    return fallback


def normalize_optional_string(value, fallback=""):
    """Normalize optional string config values with whitespace trimmed."""
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def sanitize_identity_header_value(value, fallback=""):
    """Normalize a caller identity header value to a single safe token."""
    text = normalize_optional_string(value, fallback)
    if not text:
        return fallback

    text = re.sub(r"\s+", "_", text)
    text = "".join(ch for ch in text if ch.isprintable() and ch not in {"\n", "\r", "\t"})
    text = text[:128]
    return text or fallback


def get_local_os_username():
    """Return the local OS account name for MCP identity propagation."""
    candidates = [
        os.getenv("ANAN_AGENT_USERNAME"),
        os.getenv("USER"),
        os.getenv("LOGNAME"),
    ]

    try:
        candidates.append(getpass.getuser())
    except Exception:
        logger.debug("Unable to resolve local OS username via getpass.getuser()", exc_info=True)

    for candidate in candidates:
        username = sanitize_identity_header_value(candidate)
        if username:
            return username

    return ""


def build_mcp_identity_headers():
    """Build MCP request headers used for caller identity propagation."""
    username = get_local_os_username()
    if not username:
        return {}
    return {"X-Agent-Username": username}


class ModelProviderAdapter:
    """Provider adapter contract for model-specific request/response handling."""

    def request_model_response(self, settings, messages, tools=None):
        raise NotImplementedError()

    def request_final_response(self, settings, messages):
        raise NotImplementedError()


class OllamaProviderAdapter(ModelProviderAdapter):
    """Adapter for Ollama chat completion APIs."""

    def request_model_response(self, settings, messages, tools=None):
        response = ollama.chat(
            model=settings["ollama_model"],
            messages=messages,
            tools=tools,
            stream=False,
            options={"temperature": settings["temperature"]},
        )

        raw_tool_calls = response.get("message", {}).get("tool_calls") or []
        tool_calls = []
        for tool_call in raw_tool_calls:
            function_payload = tool_call.get("function", {})
            tool_calls.append({
                "id": tool_call.get("id"),
                "name": function_payload.get("name", ""),
                "arguments": function_payload.get("arguments", {}),
            })

        no_tool_reply = response.get("message", {}).get("content", "")
        inline_reply, inline_tool_calls = extract_inline_tool_calls(no_tool_reply)
        if inline_tool_calls:
            logger.info("Parsed %d inline tool call(s) from assistant text", len(inline_tool_calls))
            no_tool_reply = inline_reply
            tool_calls = inline_tool_calls

        return response, tool_calls, no_tool_reply

    def request_final_response(self, settings, messages):
        final = ollama.chat(
            model=settings["ollama_model"],
            messages=messages,
            stream=False,
            options={"temperature": settings["temperature"]},
        )
        return final.get("message", {}).get("content", "")


class OpenRouterProviderAdapter(ModelProviderAdapter):
    """Adapter for OpenRouter-compatible model providers via OpenAI-compatible API."""

    def _resolve_api_key(self, settings):
        api_key = normalize_optional_string(
            settings.get("openrouter_api_key")
            or os.getenv("ANAN_AGENT_OPENROUTER_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
        )
        if not api_key:
            raise RuntimeError(
                "OpenRouter provider requires an API key. "
                "Set openrouter_api_key in config or OPENROUTER_API_KEY environment variable."
            )
        return api_key

    def _build_openrouter_request(self, settings, messages, tools=None):
        payload_messages = []
        for message in messages:
            role = message.get("role")
            content = message.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content)

            if role == "system":
                payload_messages.append({"role": "system", "content": content})
                continue

            if role == "tool":
                payload_messages.append({
                    "role": "tool",
                    "tool_call_id": message.get("tool_call_id", ""),
                    "name": message.get("name", ""),
                    "content": content,
                })
                continue

            payload_messages.append({"role": role if role in {"user", "assistant"} else "user", "content": content})

        payload = {
            "model": normalize_optional_string(settings.get("openrouter_model"), OPENROUTER_MODEL),
            "messages": payload_messages,
            "temperature": settings["temperature"],
            "stream": False,
        }

        if tools:
            payload["tools"] = []
            for tool in tools:
                function_payload = tool.get("function", {})
                function_name = function_payload.get("name")
                if not function_name:
                    continue
                payload["tools"].append(
                    {
                        "type": "function",
                        "function": {
                            "name": function_name,
                            "description": function_payload.get("description", ""),
                            "parameters": function_payload.get("parameters", {"type": "object", "properties": {}}),
                        },
                    }
                )

        return payload

    def _call_openrouter_api(self, settings, payload):
        api_key = self._resolve_api_key(settings)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        site_url = os.getenv("ANAN_AGENT_OPENROUTER_SITE_URL") or os.getenv("OPENROUTER_SITE_URL")
        if site_url:
            headers["HTTP-Referer"] = site_url

        app_name = os.getenv("ANAN_AGENT_OPENROUTER_APP_NAME") or os.getenv("OPENROUTER_APP_NAME")
        if app_name:
            headers["X-Title"] = app_name

        endpoint = f"{OPENROUTER_API_BASE_URL}/chat/completions"
        with httpx.Client(timeout=90.0) as client:
            response = client.post(endpoint, headers=headers, json=payload)

        if response.status_code >= 400:
            try:
                error_body = response.json()
            except ValueError:
                error_body = response.text
            raise RuntimeError(f"OpenRouter API request failed: HTTP {response.status_code} - {error_body}")

        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError("OpenRouter API returned non-JSON response") from exc

    def request_model_response(self, settings, messages, tools=None):
        payload = self._build_openrouter_request(settings, messages, tools=tools)
        response = self._call_openrouter_api(settings, payload)

        choices = response.get("choices") or []
        if not choices:
            raise RuntimeError(f"OpenRouter response contained no choices: {response}")

        message = choices[0].get("message") or {}
        raw_content = message.get("content") or ""
        if not isinstance(raw_content, str):
            raw_content = json.dumps(raw_content)

        tool_calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function", {})
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}
            tool_calls.append({
                "id": call.get("id"),
                "name": function.get("name", ""),
                "arguments": arguments,
            })

        no_tool_reply = raw_content
        inline_reply, inline_tool_calls = extract_inline_tool_calls(no_tool_reply)
        if inline_tool_calls:
            logger.info("Parsed %d inline tool call(s) from OpenRouter assistant text", len(inline_tool_calls))
            no_tool_reply = inline_reply
            tool_calls = inline_tool_calls

        normalized_response = {
            "provider": "openrouter",
            "message": {
                "content": no_tool_reply,
                "tool_calls": [
                    {
                        "id": call["id"],
                        "function": {
                            "name": call["name"],
                            "arguments": call["arguments"],
                        },
                    }
                    for call in tool_calls
                ],
            },
            "raw_response": response,
        }

        return normalized_response, tool_calls, no_tool_reply

    def request_final_response(self, settings, messages):
        payload = self._build_openrouter_request(settings, messages, tools=None)
        response = self._call_openrouter_api(settings, payload)
        choices = response.get("choices") or []
        if not choices:
            raise RuntimeError(f"OpenRouter response contained no choices: {response}")

        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        if not isinstance(content, str):
            content = json.dumps(content)
        return content.strip()


class GeminiProviderAdapter(ModelProviderAdapter):
    """Adapter for Google Gemini models via Google AI Studio REST API."""

    _TYPE_MAP = {
        "object": "OBJECT",
        "array": "ARRAY",
        "string": "STRING",
        "integer": "INTEGER",
        "number": "NUMBER",
        "boolean": "BOOLEAN",
    }

    def _resolve_api_key(self, settings):
        api_key = normalize_optional_string(
            settings.get("gemini_api_key")
            or os.getenv("ANAN_AGENT_GEMINI_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
            or os.getenv("GEMINI_API_KEY")
        )
        if not api_key:
            raise RuntimeError(
                "Gemini provider requires a Google AI Studio API key. "
                "Set gemini_api_key in config or GOOGLE_API_KEY environment variable."
            )
        return api_key

    def _build_gemini_request(self, settings, messages, tools=None):
        system_prompt = ""
        contents = []

        for message in messages:
            role = message.get("role")
            content = message.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content)

            if role == "system":
                if content.strip():
                    system_prompt = content.strip()
                continue

            gemini_role = "model" if role == "assistant" else "user"
            if role == "tool":
                content = f"Tool output:\n{content}"

            contents.append(
                {
                    "role": gemini_role,
                    "parts": [{"text": content}],
                }
            )

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": settings["temperature"],
            },
        }

        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}],
            }

        if tools:
            function_declarations = []
            for tool in tools:
                function_payload = tool.get("function", {})
                function_name = function_payload.get("name")
                if not function_name:
                    continue
                raw_parameters = function_payload.get("parameters", {"type": "object", "properties": {}})
                function_declarations.append(
                    {
                        "name": function_name,
                        "description": function_payload.get("description", ""),
                        "parameters": self._sanitize_gemini_parameters(raw_parameters),
                    }
                )

            if function_declarations:
                payload["tools"] = [{"functionDeclarations": function_declarations}]

        return payload

    def _sanitize_gemini_parameters(self, schema):
        """Convert JSON-schema-like tool parameters to Gemini-compatible schema."""
        sanitized = self._sanitize_gemini_schema_node(schema)
        if not isinstance(sanitized, dict):
            return {"type": "OBJECT", "properties": {}}

        if "type" not in sanitized:
            if isinstance(sanitized.get("properties"), dict):
                sanitized["type"] = "OBJECT"
            elif isinstance(sanitized.get("items"), dict):
                sanitized["type"] = "ARRAY"

        if sanitized.get("type") == "OBJECT" and "properties" not in sanitized:
            sanitized["properties"] = {}

        return sanitized

    def _sanitize_gemini_schema_node(self, schema):
        if not isinstance(schema, dict):
            return None

        sanitized = {}

        schema_type = schema.get("type")
        if isinstance(schema_type, str):
            mapped_type = self._TYPE_MAP.get(schema_type.strip().lower())
            if mapped_type:
                sanitized["type"] = mapped_type

        description = schema.get("description")
        if isinstance(description, str) and description.strip():
            sanitized["description"] = description.strip()

        enum_values = schema.get("enum")
        if isinstance(enum_values, list) and enum_values:
            sanitized["enum"] = enum_values

        nullable = schema.get("nullable")
        if isinstance(nullable, bool):
            sanitized["nullable"] = nullable

        properties = schema.get("properties")
        if isinstance(properties, dict):
            converted_properties = {}
            for key, value in properties.items():
                converted_child = self._sanitize_gemini_schema_node(value)
                if isinstance(converted_child, dict):
                    converted_properties[str(key)] = converted_child
            sanitized["properties"] = converted_properties

            required = schema.get("required")
            if isinstance(required, list) and converted_properties:
                required_filtered = [
                    str(item)
                    for item in required
                    if str(item) in converted_properties
                ]
                if required_filtered:
                    sanitized["required"] = required_filtered

        items = schema.get("items")
        if isinstance(items, dict):
            converted_items = self._sanitize_gemini_schema_node(items)
            if isinstance(converted_items, dict):
                sanitized["items"] = converted_items

        return sanitized or None

    def _call_gemini_api(self, settings, payload):
        model_name = normalize_optional_string(settings.get("gemini_model"), GEMINI_MODEL)
        api_key = self._resolve_api_key(settings)
        endpoint = f"{GEMINI_API_BASE_URL}/models/{quote(model_name, safe='')}:generateContent"

        with httpx.Client(timeout=90.0) as client:
            response = client.post(
                endpoint,
                params={"key": api_key},
                json=payload,
            )

        if response.status_code >= 400:
            try:
                error_body = response.json()
            except ValueError:
                error_body = response.text
            raise RuntimeError(f"Gemini API request failed: HTTP {response.status_code} - {error_body}")

        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError("Gemini API returned non-JSON response") from exc

    def request_model_response(self, settings, messages, tools=None):
        payload = self._build_gemini_request(settings, messages, tools=tools)
        response = self._call_gemini_api(settings, payload)

        candidates = response.get("candidates") or []
        if not candidates:
            prompt_feedback = response.get("promptFeedback")
            raise RuntimeError(f"Gemini response contained no candidates: {prompt_feedback}")

        parts = ((candidates[0].get("content") or {}).get("parts") or [])
        text_segments = []
        tool_calls = []

        for part in parts:
            text_value = part.get("text")
            if isinstance(text_value, str) and text_value.strip():
                text_segments.append(text_value)

            function_call = part.get("functionCall")
            if isinstance(function_call, dict):
                tool_calls.append({
                    "id": None,
                    "name": function_call.get("name", ""),
                    "arguments": function_call.get("args", {}) or {},
                })

        no_tool_reply = "\n".join(text_segments).strip()
        normalized_response = {
            "provider": "gemini",
            "message": {
                "content": no_tool_reply,
                "tool_calls": [
                    {
                        "id": call["id"],
                        "function": {
                            "name": call["name"],
                            "arguments": call["arguments"],
                        },
                    }
                    for call in tool_calls
                ],
            },
            "raw_response": response,
        }

        return normalized_response, tool_calls, no_tool_reply

    def request_final_response(self, settings, messages):
        payload = self._build_gemini_request(settings, messages, tools=None)
        response = self._call_gemini_api(settings, payload)

        candidates = response.get("candidates") or []
        if not candidates:
            prompt_feedback = response.get("promptFeedback")
            raise RuntimeError(f"Gemini response contained no candidates: {prompt_feedback}")

        parts = ((candidates[0].get("content") or {}).get("parts") or [])
        text_segments = []
        for part in parts:
            text_value = part.get("text")
            if isinstance(text_value, str) and text_value.strip():
                text_segments.append(text_value)

        return "\n".join(text_segments).strip()


def get_model_adapter(provider):
    """Factory for selecting the appropriate model provider adapter."""
    if provider == "ollama":
        return OllamaProviderAdapter()
    if provider == "gemini":
        return GeminiProviderAdapter()
    if provider == "openrouter":
        return OpenRouterProviderAdapter()
    raise RuntimeError(f"Unsupported model provider: {provider}")


def normalize_max_sentences(value, fallback):
    """Normalize sentence cap to a positive integer."""
    try:
        count = int(value)
    except (TypeError, ValueError):
        return fallback

    return count if count > 0 else fallback


def normalize_bool(value, fallback=False):
    """Normalize booleans from bool/str/int-like config values."""
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False

    return fallback


def trim_to_sentence_limit(text, max_sentences):
    """Trim assistant output to at most N sentences."""
    if not isinstance(text, str):
        return str(text)

    content = text.strip()
    if not content:
        return content

    parts = list(re.finditer(r"[^.!?\n]+[.!?]?", content))
    if not parts:
        return content

    if len(parts) <= max_sentences:
        return content

    cutoff = parts[max_sentences - 1].end()
    return content[:cutoff].rstrip()


def render_terminal_text(text):
    """Render markdown tables and JSON-like content into readable terminal output."""
    if not isinstance(text, str):
        return str(text)

    def wrap_table_cells(rows):
        if not rows:
            return []

        column_count = len(rows[0])
        normalized_rows = [
            [str(row[idx]).strip() if idx < len(row) else "" for idx in range(column_count)]
            for row in rows
        ]
        widths = [max(len(row[idx]) for row in normalized_rows) for idx in range(column_count)]

        terminal_width = shutil.get_terminal_size((120, 20)).columns
        max_table_width = max(40, terminal_width - 2)
        min_widths = []
        for idx, width in enumerate(widths):
            header_width = max(3, len(normalized_rows[0][idx]))
            preferred_min = max(header_width, 20) if idx == column_count - 1 and column_count > 1 else header_width
            min_widths.append(min(width, preferred_min))

        current_width = sum(widths) + (3 * column_count) + 1
        while current_width > max_table_width:
            shrinkable = [idx for idx, width in enumerate(widths) if width > min_widths[idx]]
            if not shrinkable:
                break

            widest_idx = max(shrinkable, key=lambda idx: widths[idx] - min_widths[idx])
            widths[widest_idx] -= 1
            current_width -= 1

        wrapped_rows = []
        for row in normalized_rows:
            wrapped_cells = []
            for idx, value in enumerate(row):
                wrapped = textwrap.wrap(
                    value,
                    width=max(1, widths[idx]),
                    break_long_words=True,
                    break_on_hyphens=False,
                )
                wrapped_cells.append(wrapped or [""])
            wrapped_rows.append(wrapped_cells)

        return widths, wrapped_rows

    fenced_json_pattern = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)

    def replace_fenced_json(match):
        body = match.group(1).strip()
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            return match.group(0)

        return format_json_for_terminal(parsed)

    text = fenced_json_pattern.sub(replace_fenced_json, text)

    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        parsed = None

    if isinstance(parsed, (dict, list)):
        return format_json_for_terminal(parsed)

    lines = text.splitlines()
    if not lines:
        return text

    rendered_lines = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped:
            rendered_lines.append("")
            i += 1
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            table_lines = []
            while i < len(lines):
                current = lines[i].strip()
                if current.startswith("|") and current.endswith("|"):
                    table_lines.append(current)
                    i += 1
                    continue
                break

            if len(table_lines) >= 2:
                parsed_rows = []
                for row in table_lines:
                    cells = [cell.strip() for cell in row.strip().split("|")[1:-1]]
                    if cells:
                        parsed_rows.append(cells)

                if len(parsed_rows) >= 2:
                    header = parsed_rows[0]
                    separator_row = parsed_rows[1]
                    data_rows = parsed_rows[2:]
                    if len(header) == len(separator_row) and all(
                        re.fullmatch(r":?-{3,}:?", str(cell).strip()) for cell in separator_row
                    ):
                        widths, wrapped_rows = wrap_table_cells([header, *data_rows])
                        border = "+-" + "-+-".join("-" * width for width in widths) + "-+"
                        rendered_lines.append(border)

                        for row_idx, wrapped_cells in enumerate(wrapped_rows):
                            row_height = max(len(cell_lines) for cell_lines in wrapped_cells)
                            for line_idx in range(row_height):
                                rendered_lines.append(
                                    "| " + " | ".join(
                                        (
                                            wrapped_cells[col_idx][line_idx]
                                            if line_idx < len(wrapped_cells[col_idx])
                                            else ""
                                        ).ljust(widths[col_idx])
                                        for col_idx in range(len(widths))
                                    ) + " |"
                                )

                            if row_idx == 0:
                                rendered_lines.append(border)
                        rendered_lines.append(border)
                        continue

        rendered_lines.append(lines[i])
        i += 1

    return "\n".join(rendered_lines)


def _build_message_body_lines(content, line_prefix):
    """Prefix each content line while preserving spacing and blank lines."""
    text = str(content) if content is not None else ""
    lines = text.splitlines()
    if not lines:
        return [line_prefix.rstrip()]

    prefixed = []
    for line in lines:
        if line:
            prefixed.append(f"{line_prefix}{line}")
        else:
            prefixed.append(line_prefix.rstrip())
    return prefixed


def format_chat_message(role, content, timestamp=None):
    """Format a single chat message in a professional terminal style."""
    role_name = "Assistant" if role == "assistant" else "You"
    time_label = timestamp or datetime.now().strftime("%H:%M")
    header = f"{role_name}  {time_label}"

    if role == "assistant":
        body_prefix = "| "
    else:
        body_prefix = "  "

    lines = [header]
    lines.extend(_build_message_body_lines(content, body_prefix))
    return "\n".join(lines)


def format_json_for_terminal(value, indent=0):
    """Format JSON-like content as readable key/value output for terminals."""
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            prefix = "  " * indent + f"{key}:"
            if isinstance(item, (dict, list)):
                lines.append(prefix)
                lines.extend(format_json_for_terminal(item, indent + 1).splitlines())
            else:
                lines.append(prefix + f" {item}")
        return "\n".join(lines)

    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append("  " * indent + "-")
                lines.extend(format_json_for_terminal(item, indent + 1).splitlines())
            else:
                lines.append("  " * indent + f"- {item}")
        return "\n".join(lines)

    return f"{'  ' * indent}{value}"


def prettify_username(raw_username):
    """Convert local account names into a readable display name."""
    if not isinstance(raw_username, str):
        return "there"

    username = raw_username.strip()
    if not username:
        return "there"

    cleaned = re.sub(r"[._-]+", " ", username)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return "there"

    return " ".join(part.capitalize() for part in cleaned.split(" "))


async def run_with_animated_status(message, operation):
    """Display a dot animation while an async operation is in progress."""
    if not sys.stdout.isatty():
        return await operation

    stop_event = asyncio.Event()
    pattern = ["", ".", "..", "...", "..", "."]

    async def animate():
        index = 0
        while not stop_event.is_set():
            suffix = pattern[index % len(pattern)]
            frame = f"\r{message}{suffix}   "
            print(frame, end="", flush=True)
            index += 1
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=0.35)
            except asyncio.TimeoutError:
                continue

    animation_task = asyncio.create_task(animate())
    try:
        return await operation
    finally:
        stop_event.set()
        try:
            await animation_task
        except Exception:
            pass
        clear_width = len(message) + 6
        print("\r" + (" " * clear_width) + "\r", end="", flush=True)


async def run_sync_with_animated_status(message, fn, *args, **kwargs):
    """Run a sync function in a worker thread while showing animated status."""
    return await run_with_animated_status(
        message,
        asyncio.to_thread(fn, *args, **kwargs),
    )


def _parse_ps_snapshot_rows(stdout_text):
    """Parse ps-style snapshot output into normalized rows."""
    if not isinstance(stdout_text, str):
        return []

    lines = [line for line in stdout_text.splitlines() if line.strip()]
    if len(lines) < 2:
        return []

    rows = []
    for line in lines[1:]:
        parts = re.split(r"\s+", line.strip(), maxsplit=10)
        if len(parts) < 11:
            continue

        user, pid, cpu, mem, _vsz, _rss, _tty, stat, _start, _time, command = parts
        try:
            pid_value = int(pid)
        except ValueError:
            pid_value = None

        try:
            cpu_value = float(cpu)
        except ValueError:
            cpu_value = 0.0

        try:
            mem_value = float(mem)
        except ValueError:
            mem_value = 0.0

        rows.append({
            "user": user,
            "pid": pid_value,
            "cpu": cpu_value,
            "mem": mem_value,
            "stat": stat,
            "command": command,
        })

    return rows


def _build_process_snapshot_payload(payload):
    """Convert verbose process-list output into a compact structured summary."""
    if not isinstance(payload, dict):
        return None

    command_name = str(payload.get("command_name") or "").strip().lower()
    if command_name not in {"process_list", "process_snapshot"}:
        return None

    stdout_text = payload.get("stdout")
    if not isinstance(stdout_text, str) or not stdout_text.strip():
        return None

    rows = _parse_ps_snapshot_rows(stdout_text)
    if not rows:
        return None

    total_processes = len(rows)
    running_count = sum(1 for row in rows if str(row.get("stat", "")).startswith("R"))
    sleeping_count = sum(1 for row in rows if str(row.get("stat", "")).startswith("S"))
    kernel_threads_count = sum(
        1
        for row in rows
        if isinstance(row.get("command"), str)
        and row["command"].startswith("[")
        and row["command"].endswith("]")
    )

    top_cpu_rows = sorted(rows, key=lambda row: row.get("cpu", 0.0), reverse=True)[:5]
    top_mem_rows = sorted(rows, key=lambda row: row.get("mem", 0.0), reverse=True)[:5]

    def compact_row(row):
        command = str(row.get("command") or "")
        return {
            "pid": row.get("pid"),
            "user": row.get("user"),
            "cpu": round(float(row.get("cpu", 0.0)), 2),
            "mem": round(float(row.get("mem", 0.0)), 2),
            "command": command[:140],
        }

    notable = []
    if any(".vscode-server" in str(row.get("command") or "") for row in rows):
        notable.append("VS Code server processes detected")
    if any("uvicorn" in str(row.get("command") or "") for row in rows):
        notable.append("MCP server process detected")
    if any("pylance" in str(row.get("command") or "").lower() for row in rows):
        notable.append("Python language server process detected")

    return {
        "command_name": command_name,
        "success": bool(payload.get("success", True)),
        "exit_code": payload.get("exit_code"),
        "duration_ms": payload.get("duration_ms"),
        "summary": {
            "total_processes": total_processes,
            "running": running_count,
            "sleeping": sleeping_count,
            "kernel_threads": kernel_threads_count,
        },
        "top_cpu": [compact_row(row) for row in top_cpu_rows],
        "top_memory": [compact_row(row) for row in top_mem_rows],
        "notable": notable,
        "raw_output_omitted": True,
    }


def _format_readonly_cli_run_payload(tool_result):
    """Format readonly_cli_run payloads into compact, model-friendly JSON."""
    payload = extract_structured_tool_payload(tool_result)
    if not isinstance(payload, dict):
        return None

    process_snapshot_payload = _build_process_snapshot_payload(payload)
    if process_snapshot_payload is not None:
        return json.dumps(process_snapshot_payload)

    return None


def build_tool_payload(tool_result, tool_name=None):
    """Build a model-friendly string payload from MCP tool results."""
    if tool_name == "readonly_cli_run":
        formatted_payload = _format_readonly_cli_run_payload(tool_result)
        if isinstance(formatted_payload, str) and formatted_payload.strip():
            return formatted_payload

    if isinstance(tool_result, (dict, list)):
        return json.dumps(tool_result)

    # FastMCP CallToolResult often contains structured data that is
    # easier for the model to use than the Python object repr.
    structured = getattr(tool_result, "structured_content", None)
    if structured:
        try:
            return json.dumps(structured)
        except (TypeError, ValueError):
            pass

    # Fall back to textual content parts exposed by FastMCP objects.
    content_items = getattr(tool_result, "content", None)
    if isinstance(content_items, list):
        text_parts = []
        for item in content_items:
            text = getattr(item, "text", None)
            if text:
                text_parts.append(text)
        if text_parts:
            return "\n".join(text_parts)

    return str(tool_result)


def extract_inline_tool_calls(text):
    """Parse XML-like inline tool call markup returned as assistant text."""
    if not isinstance(text, str):
        return "", []

    pattern = re.compile(r"<function=([^>]+)>(.*?)</function>", re.DOTALL)
    parameter_pattern = re.compile(r"<parameter=([^>]+)>(.*?)</parameter>", re.DOTALL)
    tool_calls = []

    for match in pattern.finditer(text):
        tool_name = match.group(1).strip()
        raw_body = match.group(2)
        arguments = {}
        for parameter_match in parameter_pattern.finditer(raw_body):
            parameter_name = parameter_match.group(1).strip()
            parameter_value = parameter_match.group(2).strip()
            arguments[parameter_name] = parameter_value

        if tool_name:
            tool_calls.append({
                "id": None,
                "name": tool_name,
                "arguments": arguments,
            })

    if not tool_calls:
        return text, []

    cleaned = pattern.sub("", text)
    cleaned = re.sub(r"</tool_call>", "", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned, tool_calls


def parse_json_string(value):
    """Best-effort parse for JSON-encoded argument fragments."""
    if not isinstance(value, str):
        return value

    candidate = value.strip()
    if not candidate:
        return value

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return value


def should_attempt_tool_auto_continue(reply_text):
    """Detect intent-style replies that should trigger one auto tool-call retry."""
    if not isinstance(reply_text, str):
        return False

    normalized = reply_text.strip().lower()
    if not normalized:
        return False

    if "?" in normalized:
        return False

    intent_markers = [
        "i'll",
        "i will",
        "let me",
        "going to",
        "i can",
        "i can see",
        "i'm going to",
    ]
    action_markers = [
        "run",
        "check",
        "fetch",
        "list",
        "execute",
        "look up",
        "see what",
    ]

    has_intent = any(marker in normalized for marker in intent_markers)
    has_action = any(marker in normalized for marker in action_markers)
    return has_intent and has_action


def request_model_response(provider, settings, messages, tools=None):
    """Request a model response and return response object, tool calls, and text content."""
    adapter = get_model_adapter(provider)
    return adapter.request_model_response(settings, messages, tools=tools)


def request_model_final_response(provider, settings, messages):
    """Request a final assistant response after tool execution."""
    adapter = get_model_adapter(provider)
    return adapter.request_final_response(settings, messages)


def normalize_tool_arguments(tool_name, arguments):
    """Normalize model-supplied tool arguments to MCP contract-friendly types."""
    if isinstance(arguments, str):
        arguments = parse_json_string(arguments)

    if not isinstance(arguments, dict):
        return arguments

    normalized = dict(arguments)

    # Common bool coercion for tool arguments occasionally emitted as strings.
    for field_name in ("allow_extra_args", "sync_with_clients", "verify_ssl_certificate"):
        if field_name in normalized:
            normalized[field_name] = normalize_bool(normalized[field_name], normalized[field_name])

    if tool_name != "add_client_command":
        return normalized

    for field_name in ("command_name", "description", "client_name", "binary"):
        if isinstance(normalized.get(field_name), str):
            normalized[field_name] = normalized[field_name].strip()

    for list_field in ("aliases", "fixed_args"):
        if list_field not in normalized:
            continue

        parsed_value = parse_json_string(normalized[list_field])
        if isinstance(parsed_value, list):
            normalized[list_field] = [str(item).strip() for item in parsed_value if str(item).strip()]
        elif isinstance(parsed_value, str):
            stripped = parsed_value.strip()
            normalized[list_field] = [stripped] if stripped else []
        else:
            normalized[list_field] = parsed_value

    binary = normalized.get("binary")
    if isinstance(binary, str) and binary and not binary.startswith("/"):
        resolved_binary = shutil.which(binary)
        if resolved_binary and resolved_binary.startswith("/"):
            logger.info("Normalized add_client_command binary from '%s' to '%s'", binary, resolved_binary)
            normalized["binary"] = resolved_binary
        else:
            raise ValueError(
                "add_client_command requires an absolute binary path (for example /usr/bin/apt). "
                f"Could not resolve '{binary}' in PATH."
            )

    return normalized


def _normalize_identifier(value):
    """Normalize command identifiers for duplicate checks."""
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _is_add_cli_from_file_intent(user_text):
    """Detect when the user intends to register CLI commands from a local file."""
    normalized = _normalize_match_text(user_text)
    if not normalized:
        return False

    tokens = set(_tokenize_match_text(normalized))
    add_markers = {"add", "register", "import"}
    cli_markers = {"cli", "command", "commands"}
    negative_markers = {"remove", "delete", "unregister"}
    if tokens & negative_markers:
        return False

    # For CLI registration requests, default to file-driven workflow and ask for file path.
    if tokens & add_markers and tokens & cli_markers:
        return True

    file_markers = {"file", "path", "json"}
    return bool(tokens & file_markers) and bool(tokens & cli_markers)


def _prompt_registration_file_path(input_fn=input, output_fn=print):
    """Ask user for local file path containing CLI registrations."""
    output_fn("Please provide the JSON file path for CLI registrations.")
    try:
        raw = input_fn("File path: ")
    except (EOFError, KeyboardInterrupt):
        return ""
    return raw.strip() if isinstance(raw, str) else ""


def _load_registration_entries_from_file(file_path):
    """Load CLI registration entries from a JSON object, array, or {commands:[...]} wrapper."""
    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("File path is empty.")

    path = Path(file_path).expanduser()
    if not path.exists():
        raise ValueError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON file: {exc}") from exc

    if isinstance(payload, dict):
        if isinstance(payload.get("commands"), list):
            entries = payload["commands"]
        else:
            entries = [payload]
    elif isinstance(payload, list):
        entries = payload
    else:
        raise ValueError("JSON must be an object, array, or {\"commands\": [...]}.")

    normalized_entries = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Entry #{index} must be an object.")
        normalized_entries.append(entry)

    return normalized_entries, str(path)


def _prompt_and_load_registration_entries(input_fn=input, output_fn=print):
    """Prompt until a valid registration file path is provided or the user cancels."""
    cancel_tokens = {"cancel", "quit", "exit"}

    def _assistant_output(message):
        output_fn(format_chat_message("assistant", render_terminal_text(message)))

    _assistant_output("Please provide the JSON file path for CLI registrations.\nType 'cancel' to abort.")
    while True:
        try:
            raw = input_fn("File path: ")
        except (EOFError, KeyboardInterrupt):
            return None, None, "Registration cancelled by user."

        file_path = raw.strip() if isinstance(raw, str) else ""
        if not file_path:
            _assistant_output("File path cannot be empty. Please provide a valid JSON file path, or type 'cancel' to abort.")
            continue

        if file_path.lower() in cancel_tokens:
            return None, None, "Registration cancelled by user."

        try:
            entries, resolved_path = _load_registration_entries_from_file(file_path)
            return entries, resolved_path, ""
        except ValueError as exc:
            _assistant_output(f"File validation failed: {exc}\nPlease provide a valid JSON file path, or type 'cancel' to abort.")


def _extract_existing_command_keys(readonly_catalog):
    """Extract normalized command names and aliases from readonly catalog."""
    names = set()
    aliases = set()

    for item in readonly_catalog or []:
        if not isinstance(item, dict):
            continue

        name = _normalize_identifier(item.get("name"))
        if name:
            names.add(name)

        item_aliases = item.get("aliases") if isinstance(item.get("aliases"), list) else []
        for alias in item_aliases:
            alias_text = _normalize_identifier(alias)
            if alias_text:
                aliases.add(alias_text)

    return names, aliases


def _detect_duplicate_registrations(candidates, existing_names=None, existing_aliases=None):
    """Split file entries into unique candidates and skipped duplicates with reasons."""
    existing_names = existing_names or set()
    existing_aliases = existing_aliases or set()

    kept = []
    skipped = []
    seen_names = set()
    seen_aliases = set()

    for item in candidates:
        if not isinstance(item, dict):
            skipped.append({"payload": item, "reasons": ["entry is not an object"]})
            continue

        command_name = _normalize_identifier(item.get("command_name"))
        item_aliases = item.get("aliases") if isinstance(item.get("aliases"), list) else []
        normalized_aliases = []
        for alias in item_aliases:
            alias_text = _normalize_identifier(alias)
            if alias_text:
                normalized_aliases.append(alias_text)

        reasons = []
        if not command_name:
            reasons.append("missing command_name")
        if command_name and command_name in existing_names:
            reasons.append("command_name already exists on server")
        if command_name and command_name in seen_names:
            reasons.append("duplicate command_name in file")

        per_entry_seen_aliases = set()
        for alias in normalized_aliases:
            if alias in per_entry_seen_aliases:
                reasons.append(f"duplicate alias in file: {alias}")
            per_entry_seen_aliases.add(alias)

        for alias in normalized_aliases:
            if alias in existing_aliases:
                reasons.append(f"alias already exists on server: {alias}")
            if alias in seen_aliases:
                reasons.append(f"duplicate alias in file: {alias}")

        if reasons:
            skipped.append({"payload": item, "reasons": sorted(set(reasons))})
            continue

        kept.append(item)
        if command_name:
            seen_names.add(command_name)
        seen_aliases.update(normalized_aliases)

    return kept, skipped


def _resolve_registration_tool_name(available_tool_names):
    """Pick the best available MCP tool for CLI registration."""
    if "add_client_command" in available_tool_names:
        return "add_client_command"
    if "add_command_or_cli" in available_tool_names:
        return "add_command_or_cli"
    return ""


async def _run_add_cli_from_file_workflow(settings, tools, available_tool_names, readonly_catalog, input_fn=input, output_fn=print):
    """Handle add-client-command registration from a local file in one guided flow."""
    registration_tool_name = _resolve_registration_tool_name(available_tool_names)
    if not registration_tool_name:
        return {
            "handled": True,
            "message": (
                "Cannot register commands because no supported registration tool is available in this MCP session. "
                "Expected one of: add_client_command, add_command_or_cli."
            ),
        }

    entries, resolved_path, cancel_message = _prompt_and_load_registration_entries(
        input_fn=input_fn,
        output_fn=output_fn,
    )
    if entries is None:
        return {"handled": True, "message": cancel_message}

    normalized_entries = []
    normalize_errors = []
    for index, entry in enumerate(entries, start=1):
        try:
            normalized = normalize_tool_arguments("add_client_command", entry)
            normalized_entries.append(normalized)
        except Exception as exc:
            normalize_errors.append(f"Entry #{index}: {exc}")

    if normalize_errors:
        return {
            "handled": True,
            "message": "Validation failed for one or more entries:\n" + "\n".join(normalize_errors),
        }

    current_catalog = list(readonly_catalog or [])
    if "readonly_cli_list" in available_tool_names:
        try:
            readonly_list_result = await execute_tool("readonly_cli_list", {}, settings["mcp_server_url"])
            refreshed_catalog = extract_readonly_commands_catalog(readonly_list_result)
            if refreshed_catalog:
                current_catalog = refreshed_catalog
        except Exception:
            logger.exception("Failed to refresh readonly command catalog for duplicate detection")

    existing_names, existing_aliases = _extract_existing_command_keys(current_catalog)
    entries_to_register, skipped_entries = _detect_duplicate_registrations(
        normalized_entries,
        existing_names,
        existing_aliases,
    )

    if not entries_to_register:
        lines = [
            f"Processed file: {resolved_path}",
            f"Total entries: {len(entries)}",
            f"Skipped as duplicates: {len(skipped_entries)}",
            "No commands were eligible for registration.",
        ]
        if skipped_entries:
            lines.append("Duplicate details:")
            for skipped in skipped_entries:
                payload = skipped.get("payload", {}) if isinstance(skipped, dict) else {}
                command_name = payload.get("command_name") if isinstance(payload, dict) else ""
                display_name = command_name or "(unknown)"
                reasons = skipped.get("reasons", []) if isinstance(skipped, dict) else []
                lines.append(f"- {display_name}: {', '.join(reasons)}")
        return {"handled": True, "message": "\n".join(lines)}

    tool_schema = get_tool_input_schema(tools, registration_tool_name)
    results = []
    for payload in entries_to_register:
        confirmation = resolve_add_client_command_confirmation(
            payload,
            tool_schema,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        confirmation_status = confirmation.get("status")
        command_name = payload.get("command_name", "")

        if confirmation_status != "approved":
            reason = confirmation.get("cancel_reason") or confirmation.get("required_changes", "")
            results.append({
                "command_name": command_name,
                "status": confirmation_status or "cancelled",
                "reason": reason,
            })
            continue

        final_payload = confirmation.get("payload", payload)
        tool_result = await execute_tool(registration_tool_name, final_payload, settings["mcp_server_url"])
        tool_error = tool_result.get("error") if isinstance(tool_result, dict) else None
        results.append({
            "command_name": final_payload.get("command_name", ""),
            "status": "failed" if tool_error else "success",
            "reason": tool_error or "",
        })

    success_count = sum(1 for item in results if item.get("status") == "success")
    failed_count = sum(1 for item in results if item.get("status") == "failed")
    cancelled_count = sum(1 for item in results if item.get("status") in {"cancelled", "edit_requested"})

    summary_lines = [
        f"Processed file: {resolved_path}",
        f"Total entries: {len(entries)}",
        f"Skipped as duplicates: {len(skipped_entries)}",
        f"Registered successfully: {success_count}",
        f"Failed: {failed_count}",
        f"Cancelled: {cancelled_count}",
    ]

    if skipped_entries:
        summary_lines.append("Duplicate details:")
        for skipped in skipped_entries:
            payload = skipped.get("payload", {}) if isinstance(skipped, dict) else {}
            command_name = payload.get("command_name") if isinstance(payload, dict) else ""
            display_name = command_name or "(unknown)"
            reasons = skipped.get("reasons", []) if isinstance(skipped, dict) else []
            summary_lines.append(f"- {display_name}: {', '.join(reasons)}")

    if results:
        summary_lines.append("Registration results:")
        for result in results:
            display_name = result.get("command_name") or "(unknown)"
            status = result.get("status") or "unknown"
            reason = result.get("reason")
            if reason:
                summary_lines.append(f"- {display_name}: {status} ({reason})")
            else:
                summary_lines.append(f"- {display_name}: {status}")

    return {"handled": True, "message": "\n".join(summary_lines)}


def parse_unknown_readonly_command_error(exc):
    """Extract unknown command and registered command list from readonly_cli_run errors."""
    message = str(exc)
    unknown_match = re.search(r"Unknown command '([^']+)'", message)
    registered_match = re.search(r"Registered commands:\s*(.+)", message)

    unknown_command = unknown_match.group(1).strip() if unknown_match else ""
    registered_commands = []
    if registered_match:
        registered_raw = registered_match.group(1).strip()
        registered_commands = [
            part.strip()
            for part in registered_raw.split(",")
            if part.strip()
        ]

    return {
        "unknown_command": unknown_command,
        "registered_commands": registered_commands,
    }


def pick_nearest_registered_command(requested_command, registered_commands):
    """Choose the best fallback command candidate, or None if confidence is low."""
    if not isinstance(requested_command, str):
        return None

    requested = requested_command.strip().lower()
    if not requested:
        return None

    candidates = [
        command.strip()
        for command in (registered_commands or [])
        if isinstance(command, str) and command.strip()
    ]
    if not candidates:
        return None

    normalized_map = {command.lower(): command for command in candidates}
    if requested in normalized_map:
        return normalized_map[requested]

    requested_key = re.sub(r"[^a-z0-9]", "", requested)

    # Score by lexical similarity and token overlap to avoid poor substitutions.
    scored_candidates = []
    for candidate in candidates:
        candidate_lower = candidate.lower()
        candidate_key = re.sub(r"[^a-z0-9]", "", candidate_lower)
        ratio = difflib.SequenceMatcher(None, requested_key, candidate_key).ratio()

        requested_tokens = set(filter(None, re.split(r"[_\-\s]+", requested)))
        candidate_tokens = set(filter(None, re.split(r"[_\-\s]+", candidate_lower)))
        overlap = len(requested_tokens & candidate_tokens)
        overlap_bonus = 0.2 if overlap else 0.0

        if requested in candidate_lower or candidate_lower in requested:
            overlap_bonus += 0.15

        score = ratio + overlap_bonus
        scored_candidates.append((score, candidate))

    scored_candidates.sort(key=lambda item: item[0], reverse=True)
    best_score, best_command = scored_candidates[0]

    # Keep threshold conservative to avoid nonsensical retries.
    if best_score < 0.62:
        close_matches = difflib.get_close_matches(requested, [c.lower() for c in candidates], n=1, cutoff=0.72)
        if close_matches:
            return normalized_map[close_matches[0]]
        return None

    return best_command


def get_tool_input_schema(tools, tool_name):
    """Return JSON schema for a tool from loaded tool descriptors."""
    if not isinstance(tools, list):
        return None

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        function_def = tool.get("function")
        if not isinstance(function_def, dict):
            continue

        if function_def.get("name") == tool_name:
            schema = function_def.get("parameters")
            return schema if isinstance(schema, dict) else None

    return None


def get_available_tool_names(tools):
    """Extract available MCP function names from loaded tool descriptors."""
    names = set()
    if not isinstance(tools, list):
        return names

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function_def = tool.get("function")
        if not isinstance(function_def, dict):
            continue

        name = function_def.get("name")
        if isinstance(name, str) and name.strip():
            names.add(name.strip())

    return names


def _normalize_match_text(value):
    """Normalize free text for lightweight lexical matching."""
    if not isinstance(value, str):
        return ""
    lowered = value.lower()
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", lowered)).strip()


def _tokenize_match_text(value):
    """Tokenize normalized text into distinct tokens."""
    normalized = _normalize_match_text(value)
    if not normalized:
        return []
    return [token for token in normalized.split(" ") if token]


def _sequence_similarity(left, right):
    """Return lexical similarity ratio between two strings."""
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, left, right).ratio()


def _token_overlap_score(source_tokens, candidate_tokens):
    """Compute overlap score between token sets."""
    if not source_tokens or not candidate_tokens:
        return 0.0
    source_set = set(source_tokens)
    candidate_set = set(candidate_tokens)

    shared_count = 0
    for candidate in candidate_set:
        if candidate in source_set:
            shared_count += 1
            continue

        # Treat close singular/plural variants as overlapping terms.
        for source in source_set:
            if len(candidate) < 4 or len(source) < 4:
                continue
            if candidate.startswith(source) or source.startswith(candidate):
                shared_count += 1
                break

    if not shared_count:
        return 0.0

    # Prioritize candidate coverage so long user prompts do not dilute matches.
    candidate_coverage = shared_count / len(candidate_set)
    source_coverage = shared_count / len(source_set)
    return (0.7 * candidate_coverage) + (0.3 * source_coverage)


def is_read_only_information_request(user_text):
    """Heuristically detect read-only information requests suitable for auto-routing."""
    normalized = _normalize_match_text(user_text)
    if not normalized:
        return False

    write_verbs = {
        "add",
        "create",
        "delete",
        "destroy",
        "drop",
        "edit",
        "install",
        "kill",
        "modify",
        "patch",
        "reboot",
        "register",
        "remove",
        "restart",
        "shutdown",
        "start",
        "stop",
        "uninstall",
        "update",
        "upgrade",
        "write",
    }
    tokens = _tokenize_match_text(normalized)
    if any(token in write_verbs for token in tokens):
        return False

    info_markers = {
        "check",
        "current",
        "display",
        "get",
        "info",
        "list",
        "report",
        "show",
        "snapshot",
        "status",
        "tell",
        "usage",
        "what",
        "which",
    }
    if any(token in info_markers for token in tokens):
        return True

    starts_with_info_phrase = (
        normalized.startswith("how ")
        or normalized.startswith("what ")
        or normalized.startswith("which ")
    )
    return starts_with_info_phrase or "?" in str(user_text)


def extract_structured_tool_payload(tool_result):
    """Extract structured payload from MCP tool results when possible."""
    if isinstance(tool_result, (dict, list)):
        return tool_result

    structured = getattr(tool_result, "structured_content", None)
    if isinstance(structured, (dict, list)):
        return structured

    content_items = getattr(tool_result, "content", None)
    if isinstance(content_items, list):
        for item in content_items:
            text = getattr(item, "text", None)
            if not isinstance(text, str):
                continue
            candidate = text.strip()
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, (dict, list)):
                return parsed

    return None


def extract_readonly_commands_catalog(tool_result):
    """Build a normalized readonly command catalog from readonly_cli_list output."""
    payload = extract_structured_tool_payload(tool_result)
    if not isinstance(payload, dict):
        return []

    commands = payload.get("commands")
    if not isinstance(commands, list):
        return []

    catalog = []
    for entry in commands:
        if not isinstance(entry, dict):
            continue

        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue

        aliases = entry.get("aliases") if isinstance(entry.get("aliases"), list) else []
        examples = entry.get("examples") if isinstance(entry.get("examples"), list) else []
        description = entry.get("description") if isinstance(entry.get("description"), str) else ""

        catalog.append({
            "name": name.strip(),
            "aliases": [str(alias).strip() for alias in aliases if str(alias).strip()],
            "examples": [str(example).strip() for example in examples if str(example).strip()],
            "description": description.strip(),
            "read_only": bool(entry.get("read_only", True)),
        })

    return catalog


def get_autorunnable_direct_tool_candidates(tools):
    """Return read-only direct tools that can be auto-routed without arguments."""
    blocked_names = {
        "add_command_or_cli",
        "add_client_command",
        "register_server",
        "remove_client_command",
        "remove_server",
        "readonly_cli_list",
        "readonly_cli_run",
    }

    candidates = []
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue

        function_def = tool.get("function")
        if not isinstance(function_def, dict):
            continue

        name = function_def.get("name")
        if not isinstance(name, str):
            continue

        tool_name = name.strip()
        if not tool_name or tool_name in blocked_names:
            continue

        parameters = function_def.get("parameters") if isinstance(function_def.get("parameters"), dict) else {}
        required_fields = parameters.get("required") if isinstance(parameters.get("required"), list) else []
        if required_fields:
            continue

        description = function_def.get("description") if isinstance(function_def.get("description"), str) else ""
        candidates.append({
            "name": tool_name,
            "description": description.strip(),
        })

    return candidates


def _score_candidate_phrases(user_text, phrases):
    """Score candidate phrases against user text using overlap and lexical similarity."""
    normalized_user = _normalize_match_text(user_text)
    user_tokens = _tokenize_match_text(normalized_user)
    if not normalized_user or not user_tokens:
        return 0.0

    best_score = 0.0
    for phrase in phrases:
        normalized_phrase = _normalize_match_text(phrase)
        if not normalized_phrase:
            continue

        phrase_tokens = _tokenize_match_text(normalized_phrase)
        overlap = _token_overlap_score(user_tokens, phrase_tokens)
        lexical = _sequence_similarity(normalized_user, normalized_phrase)
        contains_boost = 0.25 if normalized_phrase in normalized_user else 0.0
        starts_boost = 0.1 if normalized_user.startswith(normalized_phrase) else 0.0
        score = (0.55 * overlap) + (0.35 * lexical) + contains_boost + starts_boost
        if score > best_score:
            best_score = score

    return best_score


def choose_best_direct_tool(user_text, tool_candidates):
    """Select the best matching direct tool candidate for a user request."""
    best_name = None
    best_score = 0.0

    for candidate in tool_candidates or []:
        name = candidate.get("name")
        if not isinstance(name, str) or not name.strip():
            continue

        phrases = [name]
        description = candidate.get("description")
        if isinstance(description, str) and description.strip():
            phrases.append(description)

        score = _score_candidate_phrases(user_text, phrases)
        if score > best_score:
            best_score = score
            best_name = name.strip()

    return best_name, best_score


def choose_best_readonly_command(user_text, readonly_catalog):
    """Select the best matching readonly command for a user request."""
    best_name = None
    best_score = 0.0

    for command in readonly_catalog or []:
        if not isinstance(command, dict):
            continue

        if command.get("read_only") is False:
            continue

        name = command.get("name")
        if not isinstance(name, str) or not name.strip():
            continue

        phrases = [name]
        aliases = command.get("aliases")
        if isinstance(aliases, list):
            phrases.extend(str(alias).strip() for alias in aliases if str(alias).strip())

        description = command.get("description")
        if isinstance(description, str) and description.strip():
            phrases.append(description)

        examples = command.get("examples")
        if isinstance(examples, list):
            phrases.extend(str(example).strip() for example in examples if str(example).strip())

        score = _score_candidate_phrases(user_text, phrases)
        if score > best_score:
            best_score = score
            best_name = name.strip()

    return best_name, best_score


def infer_readonly_command_from_keywords(user_text):
    """Infer a likely readonly command from common informational keywords."""
    tokens = set(_tokenize_match_text(user_text))
    if not tokens:
        return None

    keyword_map = {
        "process_list": {"process", "processes", "ps", "running"},
        "top_snapshot": {"top", "cpu", "tasks"},
        "memory_usage": {"memory", "ram", "free"},
        "disk_usage": {"disk", "filesystem", "storage", "df"},
        "network_stats": {"network", "connections", "netstat", "sockets"},
        "network_interfaces": {"interfaces", "interface", "ip", "addresses"},
        "uptime": {"uptime", "up"},
        "hostname": {"hostname", "host"},
        "date_now": {"date", "time", "clock"},
        "check_updates": {"updates", "upgrade", "upgradable", "packages"},
    }

    best_command = None
    best_hits = 0
    for command_name, keywords in keyword_map.items():
        hits = len(tokens & keywords)
        if hits > best_hits:
            best_hits = hits
            best_command = command_name

    # Require at least one strong keyword hit.
    if best_hits < 1:
        return None
    return best_command


def synthesize_readonly_tool_calls(user_text, tools, available_tool_names, readonly_catalog):
    """Create deterministic tool calls for read-only informational requests."""
    if not is_read_only_information_request(user_text):
        return []

    direct_name = None
    direct_score = 0.0
    direct_candidates = get_autorunnable_direct_tool_candidates(tools)
    if direct_candidates:
        direct_name, direct_score = choose_best_direct_tool(user_text, direct_candidates)

    readonly_name = None
    readonly_score = 0.0
    if "readonly_cli_run" in available_tool_names:
        readonly_name, readonly_score = choose_best_readonly_command(user_text, readonly_catalog)

    if not readonly_name and "readonly_cli_run" in available_tool_names:
        inferred_name = infer_readonly_command_from_keywords(user_text)
        if inferred_name:
            readonly_name = inferred_name
            readonly_score = 0.5

    if direct_name and direct_name in available_tool_names and direct_score >= 0.4 and direct_score >= readonly_score:
        return [{
            "id": None,
            "name": direct_name,
            "arguments": {},
        }]

    if readonly_name and readonly_score >= 0.5 and "readonly_cli_run" in available_tool_names:
        return [{
            "id": None,
            "name": "readonly_cli_run",
            "arguments": {"command_name": readonly_name},
        }]

    return []


def fallback_unavailable_tools_to_readonly(unavailable_tool_names, user_text, available_tool_names, readonly_catalog):
    """Attempt converting missing model-requested tools into readonly command executions."""
    if "readonly_cli_run" not in available_tool_names:
        return []

    command_names = [
        command.get("name")
        for command in (readonly_catalog or [])
        if isinstance(command, dict) and isinstance(command.get("name"), str)
    ]

    converted_calls = []
    used_commands = set()
    for missing_name in unavailable_tool_names or []:
        if not isinstance(missing_name, str) or not missing_name.strip():
            continue
        match = pick_nearest_registered_command(missing_name, command_names)
        if not match or match in used_commands:
            continue
        used_commands.add(match)
        converted_calls.append({
            "id": None,
            "name": "readonly_cli_run",
            "arguments": {"command_name": match},
        })

    if converted_calls:
        return converted_calls

    # If model-suggested names do not map directly, route by user intent.
    return synthesize_readonly_tool_calls(
        user_text,
        tools=[],
        available_tool_names=available_tool_names,
        readonly_catalog=readonly_catalog,
    )


def find_unavailable_tool_names(requested_calls, available_tool_names):
    """Return sorted missing tool names requested by the model."""
    if not requested_calls:
        return []

    missing = set()
    for call in requested_calls:
        if not isinstance(call, dict):
            continue
        name = call.get("name")
        if isinstance(name, str) and name and name not in available_tool_names:
            missing.add(name)

    return sorted(missing)


def build_unavailable_tool_message(unavailable_tool_names):
    """Build user-facing limitation message for unsupported tool requests."""
    if not unavailable_tool_names:
        return UNAVAILABLE_TOOL_MESSAGE

    listed = ", ".join(unavailable_tool_names)
    return f"{UNAVAILABLE_TOOL_MESSAGE} Missing tool(s): {listed}."


def _format_confirmation_value(value):
    """Render a payload value as concise terminal-safe text."""
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(items) if items else "(empty)"

    if isinstance(value, bool):
        return "true" if value else "false"

    if value is None:
        return "(none)"

    text = str(value).strip()
    return text if text else "(empty)"


def format_registration_payload_lines(payload):
    """Render add_client_command payload as deterministic name/value lines."""
    if not isinstance(payload, dict):
        return [f"- value: {_format_confirmation_value(payload)}"]

    field_order = [
        "command_name",
        "binary",
        "description",
        "aliases",
        "fixed_args",
        "allow_extra_args",
        "sync_with_clients",
        "client_name",
    ]

    lines = []
    seen = set()
    for field_name in field_order:
        if field_name in payload:
            lines.append(f"- {field_name}: {_format_confirmation_value(payload.get(field_name))}")
            seen.add(field_name)

    extra_fields = sorted(key for key in payload.keys() if key not in seen)
    for field_name in extra_fields:
        lines.append(f"- {field_name}: {_format_confirmation_value(payload.get(field_name))}")

    if not lines:
        lines.append("- (no parameters provided)")

    return lines


def _merge_unique_values(existing_values, new_values):
    """Append new values to existing list while preserving order and uniqueness."""
    merged = []
    seen = set()
    for item in existing_values + new_values:
        text = str(item).strip()
        if not text:
            continue
        marker = text.lower()
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(text)
    return merged


def _parse_list_values_from_change_request(change_request):
    """Extract candidate list values from free-form change text."""
    if not isinstance(change_request, str):
        return []

    text = change_request.strip()
    if not text:
        return []

    quoted_values = []
    for match in re.findall(r'"([^\"]+)"|\'([^\']+)\'', text):
        candidate = match[0] or match[1]
        candidate = candidate.strip()
        if candidate:
            quoted_values.append(candidate)
    if quoted_values:
        return quoted_values

    include_match = re.search(r"(?:include|add)\s+(.+)$", text, re.IGNORECASE)
    if include_match:
        tail = include_match.group(1).strip()
    else:
        tail = text

    tail = re.sub(r"\b(?:and|plus)\b", ",", tail, flags=re.IGNORECASE)
    parts = [part.strip(" .") for part in tail.split(",")]
    parts = [part for part in parts if part]
    if len(parts) == 1 and " " in parts[0]:
        parts = [token.strip() for token in parts[0].split() if token.strip()]

    return parts


def apply_user_guided_registration_changes(payload, change_request):
    """Apply deterministic payload edits from user guidance when possible."""
    if not isinstance(payload, dict):
        return payload, False, []

    if not isinstance(change_request, str) or not change_request.strip():
        return payload, False, []

    updated = dict(payload)
    applied_fields = []
    guidance = change_request.strip()
    guidance_lower = guidance.lower()

    if "alias" in guidance_lower:
        alias_values = _parse_list_values_from_change_request(guidance)
        if alias_values:
            existing_aliases = updated.get("aliases")
            if not isinstance(existing_aliases, list):
                existing_aliases = []
            updated["aliases"] = _merge_unique_values(existing_aliases, alias_values)
            applied_fields.append("aliases")

    if "fixed_args" in guidance_lower or "fixed args" in guidance_lower:
        fixed_args_values = _parse_list_values_from_change_request(guidance)
        if fixed_args_values:
            existing_fixed_args = updated.get("fixed_args")
            if not isinstance(existing_fixed_args, list):
                existing_fixed_args = []
            updated["fixed_args"] = _merge_unique_values(existing_fixed_args, fixed_args_values)
            applied_fields.append("fixed_args")

    if "allow_extra_args" in guidance_lower or "allow extra args" in guidance_lower:
        if re.search(r"\b(true|yes|enable|enabled|on)\b", guidance_lower):
            updated["allow_extra_args"] = True
            applied_fields.append("allow_extra_args")
        elif re.search(r"\b(false|no|disable|disabled|off)\b", guidance_lower):
            updated["allow_extra_args"] = False
            applied_fields.append("allow_extra_args")

    if "sync_with_clients" in guidance_lower or "sync with clients" in guidance_lower:
        if re.search(r"\b(true|yes|enable|enabled|on)\b", guidance_lower):
            updated["sync_with_clients"] = True
            applied_fields.append("sync_with_clients")
        elif re.search(r"\b(false|no|disable|disabled|off)\b", guidance_lower):
            updated["sync_with_clients"] = False
            applied_fields.append("sync_with_clients")

    binary_match = re.search(r"\b(?:binary|path)\b[^/]*\s(/\S+)", guidance, re.IGNORECASE)
    if binary_match:
        updated["binary"] = binary_match.group(1).strip().rstrip(",.")
        applied_fields.append("binary")

    command_name_match = re.search(
        r"\bcommand_name\b\s*(?:=|:|to)\s*([a-zA-Z0-9_\-]+)",
        guidance,
        re.IGNORECASE,
    )
    if command_name_match:
        updated["command_name"] = command_name_match.group(1).strip()
        applied_fields.append("command_name")

    description_match = re.search(r"\bdescription\b\s*(?:=|:|to)\s*(.+)$", guidance, re.IGNORECASE)
    if description_match:
        description = description_match.group(1).strip().strip('"\'')
        if description:
            updated["description"] = description
            applied_fields.append("description")

    return updated, bool(applied_fields), sorted(set(applied_fields))


def prompt_tool_confirmation(tool_name, payload, _schema, input_fn=input, output_fn=print):
    """Prompt user to confirm a sensitive tool invocation."""
    output_fn("\nConfirmation required before sending command registration to MCP server.")
    output_fn("Registration parameters:")
    for line in format_registration_payload_lines(payload):
        output_fn(line)

    output_fn("Select an action:")
    output_fn("1) Approve and continue")
    output_fn("2) Cancel registration")

    try:
        answer = input_fn("Choice [1/2]: ")
    except (EOFError, KeyboardInterrupt):
        return {
            "approved": False,
            "required_changes": "",
            "retry_preference": "",
            "cancel_reason": "",
            "outcome": "cancelled",
        }

    normalized = answer.strip().lower() if isinstance(answer, str) else ""
    if normalized in {"1", "y", "yes", "approve", "approved"}:
        return {
            "approved": True,
            "required_changes": "",
            "retry_preference": "",
            "cancel_reason": "",
            "outcome": "approved",
        }

    if normalized in {"2", "cancel", "c"}:
        output_fn("Registration cancelled.")
        return {
            "approved": False,
            "required_changes": "",
            "retry_preference": "",
            "cancel_reason": "",
            "outcome": "cancelled",
        }

    output_fn("Invalid choice received; defaulting to cancel.")
    return {
        "approved": False,
        "required_changes": "",
        "retry_preference": "",
        "cancel_reason": "Invalid menu selection.",
        "outcome": "cancelled",
    }


def resolve_add_client_command_confirmation(payload, schema, input_fn=input, output_fn=print, max_rounds=3):
    """Resolve add_client_command confirmation for approve/cancel decisions."""
    current_payload = dict(payload) if isinstance(payload, dict) else payload
    _ = max_rounds
    confirmation = prompt_tool_confirmation("add_client_command", current_payload, schema, input_fn=input_fn, output_fn=output_fn)
    outcome = confirmation.get("outcome")

    if outcome == "approved":
        return {
            "status": "approved",
            "payload": current_payload,
            "required_changes": "",
            "retry_preference": "",
            "cancel_reason": "",
        }

    return {
        "status": "cancelled",
        "payload": current_payload,
        "required_changes": "",
        "retry_preference": "",
        "cancel_reason": confirmation.get("cancel_reason", ""),
    }


def load_config(config_path=None):
    """Load runtime settings from a JSON config file, environment, and explicit defaults only."""
    resolved_path = Path(config_path or os.getenv("ANAN_AGENT_CONFIG", DEFAULT_CONFIG_PATH))
    env_temperature = os.getenv("ANAN_AGENT_TEMPERATURE")
    default_temperature = normalize_temperature(env_temperature, DEFAULT_TEMPERATURE)
    env_max_sentences = os.getenv("ANAN_AGENT_ASSISTANT_MAX_SENTENCES")
    default_max_sentences = normalize_max_sentences(env_max_sentences, DEFAULT_ASSISTANT_MAX_SENTENCES)
    defaults = {
        "model_provider": normalize_provider(os.getenv("ANAN_AGENT_MODEL_PROVIDER"), MODEL_PROVIDER),
        "ollama_model": OLLAMA_MODEL,
        "gemini_model": normalize_optional_string(
            os.getenv("ANAN_AGENT_GEMINI_MODEL", os.getenv("GEMINI_MODEL", GEMINI_MODEL)),
            GEMINI_MODEL,
        ),
        "gemini_api_key": normalize_optional_string(
            os.getenv("ANAN_AGENT_GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", os.getenv("GEMINI_API_KEY", ""))),
            "",
        ),
        "openrouter_model": normalize_optional_string(
            os.getenv("ANAN_AGENT_OPENROUTER_MODEL", os.getenv("OPENROUTER_MODEL", OPENROUTER_MODEL)),
            OPENROUTER_MODEL,
        ),
        "openrouter_api_key": normalize_optional_string(
            os.getenv("ANAN_AGENT_OPENROUTER_API_KEY", os.getenv("OPENROUTER_API_KEY", "")),
            "",
        ),
        "mcp_base_url": normalize_optional_string(
            os.getenv("MCP_BASE_URL") or os.getenv("ANAN_AGENT_MCP_BASE_URL"),
            "",
        ),
        "system_prompt": os.getenv("ANAN_AGENT_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT),
        "temperature": default_temperature,
        "assistant_max_sentences": default_max_sentences,
        "verify_ssl_certificate": normalize_bool(
            os.getenv("ANAN_AGENT_VERIFY_SSL_CERTIFICATE", os.getenv("VERIFY_SSL_CERTIFICATE", os.getenv("MCP_VERIFY_SSL_CERTIFICATE", "true"))),
            True,
        ),
        "oauth_enabled": normalize_bool(os.getenv("OAUTH_ENABLED", "false"), False),
        "oauth_token_url": os.getenv("OAUTH_TOKEN_URL", ""),
        "oauth_client_id": os.getenv("OAUTH_CLIENT_ID", ""),
        "oauth_client_secret": os.getenv("OAUTH_CLIENT_SECRET", ""),
        "oauth_audience": os.getenv("OAUTH_AUDIENCE", ""),
        "oauth_scope": os.getenv("OAUTH_SCOPE", ""),
    }

    # Preserve compatibility for existing key consumers without inventing a default server URL.
    defaults["mcp_server_url"] = defaults["mcp_base_url"]

    if not resolved_path.exists():
        return defaults

    try:
        with resolved_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Invalid config at %s; falling back to defaults. Error: %s", resolved_path, exc)
        return defaults

    system_prompt = normalize_system_prompt(
        loaded.get("system_prompt", defaults["system_prompt"]),
        defaults["system_prompt"],
    )
    temperature = normalize_temperature(
        loaded.get("temperature", defaults["temperature"]),
        defaults["temperature"],
    )
    assistant_max_sentences = normalize_max_sentences(
        loaded.get("assistant_max_sentences", defaults["assistant_max_sentences"]),
        defaults["assistant_max_sentences"],
    )

    mcp_base_url = loaded.get(
        "MCP_BASE_URL",
        loaded.get("mcp_base_url", loaded.get("mcp_server_url", defaults["mcp_base_url"])),
    )
    oauth_enabled = normalize_bool(
        loaded.get("OAUTH_ENABLED", loaded.get("oauth_enabled", defaults["oauth_enabled"])),
        defaults["oauth_enabled"],
    )
    verify_ssl_certificate = normalize_bool(
        loaded.get("VERIFY_SSL_CERTIFICATE", loaded.get("verify_ssl_certificate", defaults["verify_ssl_certificate"])),
        defaults["verify_ssl_certificate"],
    )
    oauth_token_url = loaded.get("OAUTH_TOKEN_URL", loaded.get("oauth_token_url", defaults["oauth_token_url"]))
    oauth_client_id = loaded.get("OAUTH_CLIENT_ID", loaded.get("oauth_client_id", defaults["oauth_client_id"]))
    oauth_client_secret = loaded.get(
        "OAUTH_CLIENT_SECRET",
        loaded.get("oauth_client_secret", defaults["oauth_client_secret"]),
    )
    oauth_audience = loaded.get("OAUTH_AUDIENCE", loaded.get("oauth_audience", defaults["oauth_audience"]))
    oauth_scope = loaded.get("OAUTH_SCOPE", loaded.get("oauth_scope", defaults["oauth_scope"]))

    return {
        "model_provider": normalize_provider(loaded.get("model_provider", defaults["model_provider"]), defaults["model_provider"]),
        "ollama_model": loaded.get("ollama_model", defaults["ollama_model"]),
        "gemini_model": normalize_optional_string(
            loaded.get("GEMINI_MODEL", loaded.get("gemini_model", defaults["gemini_model"])),
            defaults["gemini_model"],
        ),
        "gemini_api_key": normalize_optional_string(
            loaded.get("GEMINI_API_KEY", loaded.get("gemini_api_key", defaults["gemini_api_key"])),
            defaults["gemini_api_key"],
        ),
        "openrouter_model": normalize_optional_string(
            loaded.get("OPENROUTER_MODEL", loaded.get("openrouter_model", defaults["openrouter_model"])),
            defaults["openrouter_model"],
        ),
        "openrouter_api_key": normalize_optional_string(
            loaded.get("OPENROUTER_API_KEY", loaded.get("openrouter_api_key", defaults["openrouter_api_key"])),
            defaults["openrouter_api_key"],
        ),
        "mcp_base_url": mcp_base_url,
        "mcp_server_url": mcp_base_url,
        "system_prompt": system_prompt,
        "temperature": temperature,
        "assistant_max_sentences": assistant_max_sentences,
        "verify_ssl_certificate": verify_ssl_certificate,
        "oauth_enabled": oauth_enabled,
        "oauth_token_url": oauth_token_url,
        "oauth_client_id": oauth_client_id,
        "oauth_client_secret": oauth_client_secret,
        "oauth_audience": oauth_audience,
        "oauth_scope": oauth_scope,
    }


def require_mcp_server_url(settings):
    """Return the configured MCP server URL or raise a clear configuration error."""
    server_url = settings.get("mcp_server_url") or settings.get("mcp_base_url")
    if isinstance(server_url, str):
        server_url = server_url.strip()
    if not server_url:
        raise ValueError(
            "MCP server URL is required. Set MCP_BASE_URL or ANAN_AGENT_MCP_BASE_URL in the environment or in agent/config/config.json."
        )
    return server_url


def is_unauthorized_mcp_error(exc):
    """Best-effort detection for 401s surfaced by the FastMCP client."""
    if getattr(exc, "status_code", None) == 401:
        return True

    message = str(exc).lower()
    return "401" in message and ("unauthorized" in message or "401:" in message or "status" in message)


def is_server_unreachable_error(exc):
    """Best-effort detection for MCP connection failures indicating the server is down."""
    if exc is None:
        return False

    message = str(exc).lower()
    if any(token in message for token in ["connection refused", "connect timeout", "timed out", "name or service not known", "network is unreachable", "temporarily unavailable", "failed to connect"]):
        return True

    exception_type = type(exc).__name__.lower()
    if exception_type in {"connecterror", "connecttimeout", "httpxconnecterror", "httpxconnecttimeout"}:
        return True

    return False


def oauth_safe_error_message(status_code=401):
    """Return a user-safe auth error without exposing secrets."""
    return (
        f"MCP request failed with status {status_code} after OAuth token refresh retry. "
        "Verify token URL, issuer/audience, client credentials, and token expiry."
    )


def build_oauth_token_manager(settings):
    """Construct OAuth token manager when OAuth is enabled."""
    global _oauth_token_manager
    global _oauth_token_manager_key

    if not settings.get("oauth_enabled"):
        return None

    required = ["oauth_token_url", "oauth_client_id", "oauth_client_secret"]
    missing = [key for key in required if not str(settings.get(key, "")).strip()]
    if missing:
        raise RuntimeError(
            "OAuth is enabled but missing required configuration: " + ", ".join(missing)
        )

    manager_key = (
        settings["oauth_token_url"],
        settings["oauth_client_id"],
        settings["oauth_client_secret"],
        settings.get("oauth_audience", ""),
        settings.get("oauth_scope", ""),
    )

    if _oauth_token_manager is not None and _oauth_token_manager_key == manager_key:
        return _oauth_token_manager

    _oauth_token_manager = OAuthTokenManager(
        token_url=settings["oauth_token_url"],
        client_id=settings["oauth_client_id"],
        client_secret=settings["oauth_client_secret"],
        audience=settings.get("oauth_audience", ""),
        scope=settings.get("oauth_scope", ""),
        logger=logger,
    )
    _oauth_token_manager_key = manager_key
    return _oauth_token_manager


async def with_mcp_retry(settings, operation, server_url=None, operation_name="mcp_call"):
    """Run an MCP operation with optional OAuth and one-time 401 retry."""
    resolved_server_url = server_url if server_url is not None else require_mcp_server_url(settings)
    verify_ssl = settings.get("verify_ssl_certificate", True)
    token_manager = build_oauth_token_manager(settings)
    identity_headers = build_mcp_identity_headers()

    for attempt in (1, 2):
        auth = None
        if token_manager is not None:
            force_refresh = attempt == 2
            token = await token_manager.get_access_token(force_refresh=force_refresh)
            auth = token

        try:
            transport = StreamableHttpTransport(
                resolved_server_url,
                headers=identity_headers,
                auth=auth,
                verify=verify_ssl,
            )
            async with MCPClient(transport) as mcp:
                return await operation(mcp)
        except Exception as exc:
            if token_manager is not None and attempt == 1 and is_unauthorized_mcp_error(exc):
                logger.warning(
                    "%s received 401 unauthorized. Refreshing OAuth token and retrying once.",
                    operation_name,
                )
                continue
            raise


# This script acts as a CLI client that connects an LLM provider
# with a remote MCP server that exposes executable tools. The typical
# flow is:
#  1. Discover available tools from the MCP server and convert them
#     to the function format supported by chat providers.
#  2. Enter a persistent conversation loop where the user types input.
#  3. Send the conversation history; if the model requests
#     a tool, execute that tool on the MCP server and append the result
#     to the conversation history.
#  4. Send the tool results back to the model for a final assistant
#     response and display that to the user.
#
# Usage: run this module directly. Type `exit` or `quit` to stop.

async def load_mcp_tools(config_path=None):
    """Connect to the MCP server and return OpenAI-style function tools.

    Returns a list of tool descriptors formatted as 'function'
    objects so the model can request tool execution during a chat.
    If the MCP server cannot be reached, the function exits the program.
    """
    settings = load_config(config_path)
    logger.debug("load_mcp_tools: using MCP server %s", settings.get("mcp_server_url"))
    try:
        logger.info("Requesting tool list from MCP server")

        async def list_tools_operation(mcp):
            return await mcp.list_tools()

        tools_list = await run_with_animated_status(
            "Fetching response from MCP server",
            with_mcp_retry(
                settings,
                list_tools_operation,
                operation_name="list_tools",
            ),
        )

        # Convert to format Ollama understands
        ollama_tools = []
        for tool in tools_list:
                ollama_tools.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.input_schema,
                },
            })
        return ollama_tools
    except Exception as e:
        if settings.get("oauth_enabled") and is_unauthorized_mcp_error(e):
            logger.error("MCP authentication failed after retry: %s", type(e).__name__)
            print(f"Error: {oauth_safe_error_message(401)}")
            sys.exit(1)
        if is_server_unreachable_error(e):
            logger.error("MCP server is not reachable or not running: %s", type(e).__name__)
            print("Error: MCP server is not reachable or not running. Please start the MCP server and try again.")
            sys.exit(1)
        logger.exception("Failed to load MCP tools from %s", settings.get("mcp_server_url"))
        print("Error: cannot connect to MCP server. See log for details.")
        sys.exit(1)

async def execute_tool(tool_name: str, arguments: dict, server_url=None):
    """Execute a named tool on the MCP server.

    Returns whatever the MCP tool returns. On error, returns a dict
    with an `error` key so the assistant can surface the failure.
    """
    settings = load_config()
    if server_url is not None:
        resolved_server_url = server_url.strip() if isinstance(server_url, str) else server_url
    else:
        resolved_server_url = require_mcp_server_url(settings)
    normalized_arguments = normalize_tool_arguments(tool_name, arguments)
    logger.debug("execute_tool: %s on %s with args=%s", tool_name, resolved_server_url, normalized_arguments)
    try:
        async def invoke_with_arguments(call_arguments):
            async def call_tool_operation(mcp):
                return await mcp.call_tool(tool_name, call_arguments)

            return await run_with_animated_status(
                "Fetching response from MCP server",
                with_mcp_retry(
                    settings,
                    call_tool_operation,
                    server_url=resolved_server_url,
                    operation_name=f"call_tool:{tool_name}",
                ),
            )

        result = await invoke_with_arguments(normalized_arguments)
        logger.debug("Tool %s returned: %s", tool_name, result)
        return result
    except Exception as e:
        if settings.get("oauth_enabled") and is_unauthorized_mcp_error(e):
            logger.error("Tool %s authentication failed after retry", tool_name)
            return {"error": oauth_safe_error_message(401)}

        if tool_name == "readonly_cli_run":
            parsed = parse_unknown_readonly_command_error(e)
            requested_command = parsed["unknown_command"]
            registered_commands = parsed["registered_commands"]
            fallback_command = pick_nearest_registered_command(requested_command, registered_commands)

            if fallback_command:
                fallback_arguments = dict(normalized_arguments) if isinstance(normalized_arguments, dict) else {
                    "command_name": fallback_command,
                }
                fallback_arguments["command_name"] = fallback_command
                logger.warning(
                    "readonly_cli_run unknown command '%s'; retrying once with nearest command '%s'",
                    requested_command,
                    fallback_command,
                )

                try:
                    result = await invoke_with_arguments(fallback_arguments)
                    logger.info(
                        "readonly_cli_run fallback succeeded: requested='%s' fallback='%s'",
                        requested_command,
                        fallback_command,
                    )
                    return result
                except Exception as fallback_exc:
                    logger.exception(
                        "readonly_cli_run fallback failed for '%s' after initial command '%s'",
                        fallback_command,
                        requested_command,
                    )
                    return {
                        "error": (
                            f"Command '{requested_command}' is not registered. "
                            f"Retried once with nearest command '{fallback_command}' but it failed: {fallback_exc}"
                        )
                    }

            if requested_command and registered_commands:
                logger.info(
                    "readonly_cli_run unknown command '%s' has no confident fallback match",
                    requested_command,
                )
                return {
                    "error": (
                        f"Command '{requested_command}' is not registered and no close fallback command was found. "
                        f"Registered commands: {', '.join(registered_commands)}"
                    )
                }

        logger.exception("Error executing tool %s", tool_name)
        return {"error": str(e)}


async def main(config_path=None):
    """Main CLI loop.

    Steps:
    - Load and display available MCP tools.
    - Maintain `messages` as the running conversation history.
    - For each user input, send the history to Ollama.
      - If the model requests no tools, print the reply and continue.
      - If the model requests tools, execute them against the MCP
        server, append tool outputs to history, and ask the model for
        a final response which is then displayed.
    """

    settings = load_config(config_path)
    provider = settings["model_provider"]

    logger.info("Starting main loop")
    logger.info("Configured model provider: %s", provider)
    if provider == "gemini":
        logger.info("Using Gemini model: %s", settings["gemini_model"])
        selected_model = settings["gemini_model"]
    elif provider == "openrouter":
        logger.info("Using OpenRouter model: %s", settings["openrouter_model"])
        selected_model = settings["openrouter_model"]
    else:
        logger.info("Using Ollama model: %s", settings["ollama_model"])
        selected_model = settings["ollama_model"]
    tools = await load_mcp_tools(config_path)
    available_tool_names = get_available_tool_names(tools)
    readonly_commands_catalog = []

    if "readonly_cli_list" in available_tool_names:
        try:
            readonly_list_result = await execute_tool("readonly_cli_list", {}, settings["mcp_server_url"])
            readonly_commands_catalog = extract_readonly_commands_catalog(readonly_list_result)
            logger.info("Loaded %d readonly commands for routing", len(readonly_commands_catalog))
        except Exception:
            logger.exception("Failed to load readonly command catalog for routing")

    print("Anan Ubuntu Agent is ready")
    print(f"Connected tools: {len(available_tool_names)} | Model: {selected_model}")
    print("Ask a task in plain language. Type 'exit' to quit.")
    logger.info("Loaded %d tools", len(tools))
    logger.debug("Available tool names: %s", sorted(available_tool_names))
    for tool in tools:
        logger.debug("Available tool: %s - %s", tool['function']['name'], tool['function']['description'])

    # Conversation history that will be passed to the model on each turn.
    # Each entry is a dict with `role` (user/assistant/tool) and `content`.
    messages = [{"role": "system", "content": settings["system_prompt"]}]

    while True:
        try:
            user_msg = input("You: ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_msg:
            continue
        if user_msg.strip().lower() in ("exit", "quit"):
            print("Goodbye.")
            break

        print()
        print(format_chat_message("user", user_msg))

        if _is_add_cli_from_file_intent(user_msg):
            workflow_result = await _run_add_cli_from_file_workflow(
                settings=settings,
                tools=tools,
                available_tool_names=available_tool_names,
                readonly_catalog=readonly_commands_catalog,
            )
            if workflow_result.get("handled"):
                workflow_reply = trim_to_sentence_limit(
                    workflow_result.get("message", ""),
                    settings["assistant_max_sentences"],
                )
                print()
                print(format_chat_message("assistant", render_terminal_text(workflow_reply)))
                print()
                messages.append({"role": "user", "content": user_msg})
                messages.append({"role": "assistant", "content": workflow_reply})
                continue

        # Add the user's message to the running history before calling the model.
        messages.append({"role": "user", "content": user_msg})

        # Send to configured model provider with tools available.
        try:
            response, tool_calls, no_tool_reply = await run_sync_with_animated_status(
                "Thinking",
                request_model_response,
                provider,
                settings,
                messages,
                tools=tools,
            )

            # Some models produce an intent sentence first and only emit the
            # tool call after a follow-up turn; bridge that gap automatically.
            if not tool_calls and should_attempt_tool_auto_continue(no_tool_reply):
                logger.info("Attempting one auto-continue pass to obtain tool call")
                followup_messages = messages + [
                    {"role": "assistant", "content": no_tool_reply},
                    {
                        "role": "user",
                        "content": (
                            "Proceed now using available tools for the previous request. "
                            "Do not ask for confirmation unless the tool is add_client_command."
                        ),
                    },
                ]
                response2, tool_calls2, no_tool_reply2 = await run_sync_with_animated_status(
                    "Thinking",
                    request_model_response,
                    provider,
                    settings,
                    followup_messages,
                    tools=tools,
                )
                if tool_calls2:
                    logger.info("Auto-continue produced %d tool call(s)", len(tool_calls2))
                    response, tool_calls, no_tool_reply = response2, tool_calls2, no_tool_reply2
        except Exception:
            logger.exception("Error calling model provider: %s", provider)
            print(f"Error: failed to call model provider '{provider}'. See log for details.")
            return

        # If the model did not request any tools, the assistant's reply is
        # complete and can be printed directly. Append that reply to
        # history so subsequent turns remain contextually aware.
        if not tool_calls:
            if not readonly_commands_catalog and "readonly_cli_list" in available_tool_names:
                try:
                    readonly_list_result = await execute_tool("readonly_cli_list", {}, settings["mcp_server_url"])
                    refreshed_catalog = extract_readonly_commands_catalog(readonly_list_result)
                    if refreshed_catalog:
                        readonly_commands_catalog = refreshed_catalog
                        logger.info(
                            "Refreshed readonly command catalog on demand with %d commands",
                            len(readonly_commands_catalog),
                        )
                except Exception:
                    logger.exception("On-demand readonly command catalog refresh failed")

            synthesized_calls = synthesize_readonly_tool_calls(
                user_msg,
                tools,
                available_tool_names,
                readonly_commands_catalog,
            )
            if synthesized_calls:
                logger.info(
                    "Synthesized %d routed tool call(s) for read-only request without explicit model tool calls",
                    len(synthesized_calls),
                )
                tool_calls = synthesized_calls

        if not tool_calls:
            reply = trim_to_sentence_limit(no_tool_reply, settings["assistant_max_sentences"])
            logger.info("Assistant replied without tool calls")
            logger.debug("Assistant reply: %s", reply)
            print()
            print(format_chat_message("assistant", render_terminal_text(reply)))
            print()
            messages.append({"role": "assistant", "content": reply})
            continue

        # The model requested one or more tools. Append the model's tool
        # request message to history so the tool execution context is preserved.
        appended_tool_request_message = False
        messages.append({"role": "assistant", "content": no_tool_reply})
        appended_tool_request_message = True
        normalized_calls = []
        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue
            normalized_calls.append({
                "id": tool_call.get("id"),
                "name": tool_call.get("name", ""),
                "arguments": tool_call.get("arguments", {}),
            })

        unavailable_tool_names = find_unavailable_tool_names(normalized_calls, available_tool_names)
        if unavailable_tool_names:
            fallback_calls = fallback_unavailable_tools_to_readonly(
                unavailable_tool_names,
                user_msg,
                available_tool_names,
                readonly_commands_catalog,
            )
            if fallback_calls:
                logger.warning(
                    "Model requested unavailable tool(s) %s; routed to readonly fallback calls: %s",
                    unavailable_tool_names,
                    [call.get("arguments", {}).get("command_name") for call in fallback_calls],
                )
                if appended_tool_request_message and messages:
                    messages.pop()
                normalized_calls = fallback_calls
            else:
                logger.warning("Model requested unavailable tool(s): %s", unavailable_tool_names)
                if appended_tool_request_message and messages:
                    messages.pop()

                limitation_reply = build_unavailable_tool_message(unavailable_tool_names)
                print()
                print(format_chat_message("assistant", render_terminal_text(limitation_reply)))
                print()
                messages.append({"role": "assistant", "content": limitation_reply})
                continue

        for tool_call in normalized_calls:
            tool_name = tool_call["name"]
            args = tool_call["arguments"]

            # Tool call payloads may arrive as JSON strings; normalize them
            # into Python objects prior to execution.
            if isinstance(args, str):
                args = parse_json_string(args)

            if isinstance(args, dict):
                try:
                    args = normalize_tool_arguments(tool_name, args)
                except Exception as exc:
                    logger.error("Argument normalization failed for tool %s: %s", tool_name, exc)
                    tool_result = {"error": str(exc)}
                    tool_payload = build_tool_payload(tool_result, tool_name=tool_name)
                    messages.append({
                        "role": "tool",
                        "content": tool_payload,
                    })
                    continue

            if tool_name in {"add_client_command", "add_command_or_cli"} and isinstance(args, dict):
                tool_schema = get_tool_input_schema(tools, tool_name)
                confirmation_result = resolve_add_client_command_confirmation(args, tool_schema)
                status = confirmation_result.get("status")
                if status != "approved":
                    required_changes = confirmation_result.get("required_changes", "")
                    retry_preference = confirmation_result.get("retry_preference", "")
                    cancel_reason = confirmation_result.get("cancel_reason", "")

                    if status == "cancelled":
                        logger.info("User cancelled %s tool call", tool_name)
                        tool_result = {
                            "status": "cancelled",
                            "message": f"User cancelled {tool_name} registration.",
                            "cancel_reason": cancel_reason,
                        }
                    else:
                        logger.info("User requested changes for %s tool call", tool_name)
                        tool_result = {
                            "status": "edit_requested",
                            "error": f"User requested changes before confirming {tool_name}.",
                            "required_changes": required_changes,
                            "retry_preference": retry_preference,
                        }

                    tool_payload = build_tool_payload(tool_result, tool_name=tool_name)
                    messages.append({
                        "role": "tool",
                        "content": tool_payload,
                    })
                    continue

                args = confirmation_result.get("payload", args)

            logger.info("Invoking tool: %s", tool_name)
            logger.debug("Tool args: %s", args)

            # Execute the requested tool on the MCP server and append the
            # tool's output to the conversation history with role 'tool'.
            tool_result = await execute_tool(tool_name, args, settings["mcp_server_url"])
            logger.debug("Tool %s result: %s", tool_name, tool_result)

            tool_payload = build_tool_payload(tool_result, tool_name=tool_name)
            messages.append({
                "role": "tool",
                "content": tool_payload,
            })

        # Send the augmented conversation (including tool outputs) back to
        # the model so it can produce a final assistant response.
        final_reply = await run_sync_with_animated_status(
            "Thinking",
            request_model_final_response,
            provider,
            settings,
            messages,
        )

        if not final_reply.strip():
            logger.warning("Model returned empty final reply after tool execution; falling back to tool output")
            # Avoid blank terminal responses by surfacing the most recent
            # tool output when the model returns empty content.
            for message in reversed(messages):
                if message.get("role") == "tool" and message.get("content"):
                    final_reply = message["content"]
                    break

        reply = trim_to_sentence_limit(final_reply, settings["assistant_max_sentences"])
        print()
        print(format_chat_message("assistant", render_terminal_text(reply)))
        print()
        messages.append({"role": "assistant", "content": reply})
        

if __name__ == "__main__":
    asyncio.run(main())