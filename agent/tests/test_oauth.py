import asyncio

import pytest
from fastmcp.client.transports.http import StreamableHttpTransport

import anan_agent
from oauth import OAuthTokenManager


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeAsyncClient:
    def __init__(self, *, responses, timeout=20.0):
        self._responses = responses
        self.timeout = timeout
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data=None, headers=None):
        self.calls.append({"url": url, "data": data, "headers": headers})
        return self._responses.pop(0)


def test_token_cache_reuse_before_expiry():
    now = [0]
    responses = [FakeResponse({"access_token": "token-1", "expires_in": 120})]
    clients = []

    def client_factory(**kwargs):
        client = FakeAsyncClient(responses=responses, timeout=kwargs.get("timeout", 20.0))
        clients.append(client)
        return client

    manager = OAuthTokenManager(
        token_url="https://issuer.example.com/oauth/token",
        client_id="id",
        client_secret="secret",
        audience="aud",
        scope="scope",
        now_fn=lambda: now[0],
        http_client_factory=client_factory,
    )

    token_a = asyncio.run(manager.get_access_token())
    now[0] = 30
    token_b = asyncio.run(manager.get_access_token())

    assert token_a == "token-1"
    assert token_b == "token-1"
    assert len(clients) == 1
    assert len(clients[0].calls) == 1


def test_proactive_refresh_near_expiry():
    now = [0]
    responses = [
        FakeResponse({"access_token": "token-1", "expires_in": 100}),
        FakeResponse({"access_token": "token-2", "expires_in": 200}),
    ]

    def client_factory(**kwargs):
        return FakeAsyncClient(responses=responses, timeout=kwargs.get("timeout", 20.0))

    manager = OAuthTokenManager(
        token_url="https://issuer.example.com/oauth/token",
        client_id="id",
        client_secret="secret",
        now_fn=lambda: now[0],
        http_client_factory=client_factory,
    )

    first = asyncio.run(manager.get_access_token())
    now[0] = 50
    second = asyncio.run(manager.get_access_token())

    assert first == "token-1"
    assert second == "token-2"


def test_auth_header_added_when_oauth_enabled(monkeypatch):
    seen_auth = []
    seen_headers = []

    class FakeTokenManager:
        async def get_access_token(self, force_refresh=False):
            return "oauth-token"

    class FakeMCPClient:
        def __init__(self, transport):
            assert isinstance(transport, StreamableHttpTransport)
            seen_auth.append(getattr(transport.auth, "token", None).get_secret_value())
            seen_headers.append(dict(transport.headers))

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def operation(_mcp):
        return "ok"

    monkeypatch.setattr(anan_agent, "MCPClient", FakeMCPClient)
    monkeypatch.setattr(anan_agent, "build_oauth_token_manager", lambda _settings: FakeTokenManager())
    monkeypatch.setattr(anan_agent, "build_mcp_identity_headers", lambda: {"X-Agent-Username": "local_user"})

    settings = {"mcp_server_url": "https://example.com/mcp", "oauth_enabled": True}
    result = asyncio.run(anan_agent.with_mcp_retry(settings, operation, operation_name="test_call"))

    assert result == "ok"
    assert seen_auth == ["oauth-token"]
    assert seen_headers == [{"X-Agent-Username": "local_user"}]


def test_no_auth_header_when_oauth_disabled(monkeypatch):
    seen_auth = []
    seen_headers = []

    class FakeMCPClient:
        def __init__(self, transport):
            assert isinstance(transport, StreamableHttpTransport)
            seen_auth.append(transport.auth)
            seen_headers.append(dict(transport.headers))

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def operation(_mcp):
        return "ok"

    monkeypatch.setattr(anan_agent, "MCPClient", FakeMCPClient)
    monkeypatch.setattr(anan_agent, "build_mcp_identity_headers", lambda: {"X-Agent-Username": "local_user"})

    settings = {"mcp_server_url": "https://example.com/mcp", "oauth_enabled": False}
    result = asyncio.run(anan_agent.with_mcp_retry(settings, operation, operation_name="test_call"))

    assert result == "ok"
    assert seen_auth == [None]
    assert seen_headers == [{"X-Agent-Username": "local_user"}]


def test_single_retry_on_401_then_success(monkeypatch):
    seen_auth = []
    seen_headers = []
    refresh_flags = []
    call_counter = {"count": 0}

    class FakeTokenManager:
        async def get_access_token(self, force_refresh=False):
            refresh_flags.append(force_refresh)
            return "oauth-token"

    class FakeMCPClient:
        def __init__(self, transport):
            assert isinstance(transport, StreamableHttpTransport)
            seen_auth.append(getattr(transport.auth, "token", None).get_secret_value())
            seen_headers.append(dict(transport.headers))

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def call_tool(self, tool_name, arguments):
            call_counter["count"] += 1
            if call_counter["count"] == 1:
                raise RuntimeError("401: unauthorized")
            return {"ok": True}

    async def operation(mcp):
        return await mcp.call_tool("firewall_status", {})

    monkeypatch.setattr(anan_agent, "MCPClient", FakeMCPClient)
    monkeypatch.setattr(anan_agent, "build_oauth_token_manager", lambda _settings: FakeTokenManager())
    monkeypatch.setattr(anan_agent, "build_mcp_identity_headers", lambda: {"X-Agent-Username": "local_user"})

    settings = {"mcp_server_url": "https://example.com/mcp", "oauth_enabled": True}
    result = asyncio.run(anan_agent.with_mcp_retry(settings, operation, operation_name="call_tool"))

    assert result == {"ok": True}
    assert call_counter["count"] == 2
    assert refresh_flags == [False, True]
    assert seen_auth == ["oauth-token", "oauth-token"]
    assert seen_headers == [{"X-Agent-Username": "local_user"}, {"X-Agent-Username": "local_user"}]


def test_single_retry_on_401_then_failure(monkeypatch):
    call_counter = {"count": 0}

    class FakeTokenManager:
        async def get_access_token(self, force_refresh=False):
            return "oauth-token"

    class FakeMCPClient:
        def __init__(self, transport):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def call_tool(self, tool_name, arguments):
            call_counter["count"] += 1
            raise RuntimeError("401: unauthorized")

    async def operation(mcp):
        return await mcp.call_tool("firewall_status", {})

    monkeypatch.setattr(anan_agent, "MCPClient", FakeMCPClient)
    monkeypatch.setattr(anan_agent, "build_oauth_token_manager", lambda _settings: FakeTokenManager())
    monkeypatch.setattr(anan_agent, "build_mcp_identity_headers", lambda: {"X-Agent-Username": "local_user"})

    settings = {"mcp_server_url": "https://example.com/mcp", "oauth_enabled": True}
    with pytest.raises(RuntimeError):
        asyncio.run(anan_agent.with_mcp_retry(settings, operation, operation_name="call_tool"))

    assert call_counter["count"] == 2


def test_build_oauth_token_manager_reused_instance(monkeypatch):
    monkeypatch.setattr(anan_agent, "_oauth_token_manager", None)
    monkeypatch.setattr(anan_agent, "_oauth_token_manager_key", None)

    settings = {
        "oauth_enabled": True,
        "oauth_token_url": "https://issuer.example.com/oauth/token",
        "oauth_client_id": "client-id",
        "oauth_client_secret": "client-secret",
        "oauth_audience": "aud",
        "oauth_scope": "scope",
    }

    manager_a = anan_agent.build_oauth_token_manager(settings)
    manager_b = anan_agent.build_oauth_token_manager(settings)

    assert manager_a is manager_b


def test_build_mcp_identity_headers_uses_local_username(monkeypatch):
    monkeypatch.setattr(anan_agent, "get_local_os_username", lambda: "ashu")

    assert anan_agent.build_mcp_identity_headers() == {"X-Agent-Username": "ashu"}


def test_get_local_os_username_sanitizes_logged_in_user(monkeypatch):
    monkeypatch.delenv("ANAN_AGENT_USERNAME", raising=False)
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.setattr(anan_agent.getpass, "getuser", lambda: "Ashutosh Maheshwari\n")

    assert anan_agent.get_local_os_username() == "Ashutosh_Maheshwari"
