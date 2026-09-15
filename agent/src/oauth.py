import asyncio
import time
from collections.abc import Callable

import httpx


class OAuthTokenManager:
    """Client-credentials token manager with in-memory cache and proactive refresh."""

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        audience: str = "",
        scope: str = "",
        refresh_buffer_seconds: int = 60,
        logger=None,
        now_fn: Callable[[], float] | None = None,
        http_client_factory: Callable[..., object] | None = None,
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.scope = scope
        self.refresh_buffer_seconds = refresh_buffer_seconds
        self.logger = logger
        self._now_fn = now_fn or time.time
        self._http_client_factory = http_client_factory or httpx.AsyncClient
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    def _remaining_seconds(self) -> float:
        return self._expires_at - self._now_fn()

    async def get_access_token(self, *, force_refresh: bool = False) -> str:
        """Return a cached token or fetch a new one when expired/nearly expired."""
        async with self._lock:
            if not force_refresh and self._token:
                if self._remaining_seconds() > self.refresh_buffer_seconds:
                    return self._token

            if self.logger:
                if force_refresh:
                    self.logger.debug("OAuth token refresh forced.")
                elif self._token:
                    self.logger.debug("OAuth token is near expiry; refreshing token.")
                else:
                    self.logger.debug("Fetching OAuth access token.")

            token, expires_in = await self._fetch_token()
            self._token = token
            self._expires_at = self._now_fn() + max(int(expires_in), 1)

            if self.logger:
                self.logger.debug("OAuth token refreshed successfully; expires_in=%ss", int(expires_in))

            return self._token

    async def _fetch_token(self) -> tuple[str, int]:
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.audience:
            payload["audience"] = self.audience
        if self.scope:
            payload["scope"] = self.scope

        async with self._http_client_factory(timeout=20.0) as client:
            response = await client.post(
                self.token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            data = response.json()

        access_token = data.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("OAuth token endpoint response missing access_token")

        expires_in = data.get("expires_in", 3600)
        try:
            expires_in_int = int(expires_in)
        except (TypeError, ValueError):
            expires_in_int = 3600

        return access_token, expires_in_int
