# anan-ufw-agent

Minimal project structure for an MCP-driven UFW agent.

## Setup

1. Create a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Run the agent:

   ```bash
   ./start_anan_agent.sh
   ```

3. Optional: set provider and model settings in `config.json`.
   The agent supports flexible model integration for varying deployment needs: local LLM runtimes such as Ollama for privacy-focused, self-hosted inference; direct integration with Google Gemini for leading frontier model access; and OpenRouter for selecting from a broad range of model providers based on performance, cost, and capability requirements.

4. Optional: enable MCP OAuth client-credentials authentication.
   If OAuth is disabled, existing no-auth behavior is unchanged.

5. Optional: set `temperature` and `system_prompt` in `config.json`.
   `temperature` defaults to `0.8` and supports values from `0.0` to `2.0`.
   `system_prompt` supports either a single string or an array of lines.

## MCP Auth Configuration

The client supports both no-auth and OAuth modes for MCP transport.

Supported MCP connection config keys (JSON and/or environment):

- `MCP_BASE_URL` (or legacy `mcp_server_url`)
- `VERIFY_SSL_CERTIFICATE` (`true`/`false`, default `true`)
- `OAUTH_ENABLED` (`true`/`false`, default `false`)
- `OAUTH_TOKEN_URL`
- `OAUTH_CLIENT_ID`
- `OAUTH_CLIENT_SECRET`
- `OAUTH_AUDIENCE`
- `OAUTH_SCOPE` (optional)

Environment variable names are the same as above.

Set `VERIFY_SSL_CERTIFICATE` to `false` when the MCP server uses a self-signed or otherwise untrusted certificate.

### No-Auth Mode (default)

Use no-auth mode by setting `OAUTH_ENABLED` to false (or omitting it):

```json
{
   "MCP_BASE_URL": "https://your-mcp-server.example.com:8000/mcp",
   "VERIFY_SSL_CERTIFICATE": false,
   "OAUTH_ENABLED": false
}
```

### OAuth Mode (Client Credentials)

```json
{
   "MCP_BASE_URL": "https://your-mcp-server.example.com:8000/mcp",
   "OAUTH_ENABLED": true,
   "OAUTH_TOKEN_URL": "https://your-issuer.example.com/oauth/token",
   "OAUTH_CLIENT_ID": "your-client-id",
   "OAUTH_CLIENT_SECRET": "your-client-secret",
   "OAUTH_AUDIENCE": "your-api-audience",
   "OAUTH_SCOPE": "mcp.read mcp.write"
}
```

In OAuth mode, the client fetches and caches a bearer token, refreshes near expiry, and retries once on 401 after forcing token refresh.

## Model Provider Switch

Use Ollama:

```json
{
   "model_provider": "ollama",
   "ollama_model": "qwen2.5:14b",
   "mcp_server_url": "https://your-mcp-server.example.com:8000/mcp",
   "temperature": 0.1,
   "assistant_max_sentences": 50,
   "system_prompt": ["..."]
}
```

Use Gemini (Google AI Studio API key):

```json
{
   "model_provider": "gemini",
   "gemini_model": "gemini-1.5-flash",
   "gemini_api_key": "YOUR_GOOGLE_AI_STUDIO_API_KEY",
   "MCP_BASE_URL": "https://your-mcp-server.example.com:8000/mcp",
   "temperature": 0.1,
   "assistant_max_sentences": 50,
   "system_prompt": ["..."]
}
```

Use OpenRouter:

```json
{
   "model_provider": "openrouter",
   "openrouter_model": "openai/gpt-4o-mini",
   "openrouter_api_key": "YOUR_OPENROUTER_API_KEY",
   "OPENROUTER_SITE_URL": "https://example.com",
   "OPENROUTER_APP_NAME": "anan-agent",
   "MCP_BASE_URL": "https://your-mcp-server.example.com:8000/mcp",
   "temperature": 0.1,
   "assistant_max_sentences": 50,
   "system_prompt": ["..."]
}
```

Gemini and OpenRouter API keys can also be provided through environment variables:

- `ANAN_AGENT_GEMINI_API_KEY`
- `GOOGLE_API_KEY`
- `GEMINI_API_KEY`
- `ANAN_AGENT_OPENROUTER_API_KEY`
- `OPENROUTER_API_KEY`
- `OPENROUTER_SITE_URL`
- `OPENROUTER_APP_NAME`

If both config and environment are provided, config value is used.

## Structure

- `src/` — source modules (`anan_agent.py`, `oauth.py`, and helpers)
- `config.json` — runtime configuration
- `logs/` — runtime logs
- `start_anan_agent.sh` — startup script

## Testing

Run tests with:

```bash
pytest
```

## Notes

The startup script sets `PYTHONPATH` so `src/` is importable and launches the agent using `python3 -m anan_agent`.

Example `config.json`:

```json
{
   "model_provider": "openrouter",
   "openrouter_model": "openai/gpt-4o-mini",
   "openrouter_api_key": "YOUR_OPENROUTER_API_KEY",
   "OPENROUTER_SITE_URL": "https://example.com",
   "OPENROUTER_APP_NAME": "anan-agent",
   "MCP_BASE_URL": "https://your-mcp-server.example.com:8000/mcp",
   "OAUTH_ENABLED": false,
   "temperature": 0.8,
   "system_prompt": [
      "You are a helpful security assistant.",
      "Keep responses concise and practical.",
      "Always ask user to provide parameters required for MCP tool calls."
   ]
}
```

## Troubleshooting 401

- Ensure `OAUTH_AUDIENCE` matches the server-expected audience.
- Ensure token issuer configuration on server and IdP align.
- Verify `OAUTH_TOKEN_URL` is correct and reachable from the client.
- Confirm client credentials are valid and token is not expired.
