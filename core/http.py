"""Shared async HTTP transport with caching, per-host throttling and retries."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from core.errors import IntelError, SourceUnavailable
from config import settings

USER_AGENT = (
    "OSINT-MATRIX/1.0 (self-hosted private research bot; "
    "operator-configured; +https://discord.com/developers/applications)"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Language": "en-GB,en;q=0.9",
}


@dataclass(slots=True)
class Response:
    """A single HTTP exchange, including redirect history and timing."""

    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    history: list[str] = field(default_factory=list)
    bytes_read: int = 0
    http_version: str = ""
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def redirected(self) -> bool:
        return bool(self.history)

    def json(self) -> Any:
        import json as _json

        try:
            return _json.loads(self.text)
        except (ValueError, TypeError) as exc:
            raise IntelError(
                "The upstream service returned a non-JSON body.",
                hint=f"HTTP {self.status} · {self.content_type or 'unknown content type'}",
            ) from exc

    def snippet(self, limit: int = 400) -> str:
        return " ".join(self.text.split())[:limit]


class HTTPClient:
    """One shared session for the whole process."""

    def __init__(self, timeout: float = 15.0, cache_ttl: int = 300) -> None:
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._session: aiohttp.ClientSession | None = None
        self._cache: dict[str, tuple[float, Response]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self.stats = {"requests": 0, "cache_hits": 0, "errors": 0, "bytes": 0, "retries": 0}

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._session and not self._session.closed:
            return
        connector = aiohttp.TCPConnector(limit=60, ttl_dns_cache=300, enable_cleanup_closed=True)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout, connect=8, sock_read=self.timeout),
            headers=DEFAULT_HEADERS,
        )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            raise RuntimeError("HTTP client is not started.")
        return self._session

    # ── requests ─────────────────────────────────────────────────────────

    def _semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._sems:
            self._sems[host] = asyncio.Semaphore(max(1, settings.max_concurrency))
        return self._sems[host]

    @staticmethod
    def _cache_key(method: str, url: str, params: Any, body: Any) -> str:
        return f"{method}:{url}:{sorted(params.items()) if isinstance(params, dict) else params}:{body}"

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        data: Any = None,
        allow_redirects: bool = True,
        cache: bool = True,
        cache_ttl: float | None = None,
        timeout: float | None = None,
        max_redirects: int = 10,
        retry: int = 1,
        read_limit: int = 2_500_000,
    ) -> Response:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        ttl = self.cache_ttl if cache_ttl is None else cache_ttl
        key = self._cache_key(method.upper(), url, params, json_body or data)
        now = time.monotonic()

        if cache and ttl > 0:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                self.stats["cache_hits"] += 1
                return hit[1]

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if cache and ttl > 0:
                hit = self._cache.get(key)
                if hit and hit[0] > time.monotonic():
                    self.stats["cache_hits"] += 1
                    return hit[1]
            response = await self._execute(
                method,
                url,
                params=params,
                headers=headers,
                json_body=json_body,
                data=data,
                allow_redirects=allow_redirects,
                timeout=timeout,
                max_redirects=max_redirects,
                retry=retry,
                read_limit=read_limit,
            )
            if cache and ttl > 0 and response.ok:
                self._cache[key] = (time.monotonic() + ttl, response)
                if len(self._cache) > 800:
                    for stale in sorted(self._cache, key=lambda k: self._cache[k][0])[:200]:
                        self._cache.pop(stale, None)
            return response

    async def _execute(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None,
        headers: dict[str, str] | None,
        json_body: Any,
        data: Any,
        allow_redirects: bool,
        timeout: float | None,
        max_redirects: int,
        retry: int,
        read_limit: int,
    ) -> Response:
        host = urlsplit(url).netloc.lower() or "unknown"
        attempt = 0
        while True:
            attempt += 1
            started = time.perf_counter()
            try:
                async with self._semaphore(host):
                    self.stats["requests"] += 1
                    async with self.session.request(
                        method.upper(),
                        url,
                        params=params,
                        headers=headers,
                        json=json_body,
                        data=data,
                        allow_redirects=allow_redirects,
                        max_redirects=max_redirects,
                        timeout=aiohttp.ClientTimeout(total=timeout or self.timeout),
                    ) as raw:
                        chunks: list[bytes] = []
                        remaining = read_limit
                        while remaining > 0:
                            chunk = await raw.content.read(min(65536, remaining))
                            if not chunk:
                                break
                            chunks.append(chunk)
                            remaining -= len(chunk)
                        body = b"".join(chunks)
                        text = body.decode(raw.charset or "utf-8", errors="replace")
                        elapsed = (time.perf_counter() - started) * 1000
                        self.stats["bytes"] += len(body)
                        response = Response(
                            url=str(raw.url),
                            status=raw.status,
                            headers={k.lower(): v for k, v in raw.headers.items()},
                            text=text,
                            elapsed_ms=elapsed,
                            history=[str(item.url) for item in raw.history],
                            bytes_read=len(body),
                            http_version={10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(raw.version, f"HTTP/{raw.version}"),
                            set_cookies=list(raw.headers.getall("set-cookie", [])),
                            body=body,
                        )
                if response.status in {429, 500, 502, 503, 504} and attempt <= retry:
                    self.stats["retries"] += 1
                    await asyncio.sleep(min(2.0, 0.4 * attempt))
                    continue
                return response
            except asyncio.TimeoutError as exc:
                self.stats["errors"] += 1
                if attempt <= retry:
                    continue
                raise SourceUnavailable(f"`{host}` did not answer within {timeout or self.timeout:.0f}s.") from exc
            except aiohttp.TooManyRedirects as exc:
                self.stats["errors"] += 1
                raise SourceUnavailable(f"`{host}` exceeded the redirect limit.") from exc
            except aiohttp.ClientError as exc:
                self.stats["errors"] += 1
                if attempt <= retry:
                    await asyncio.sleep(0.3)
                    continue
                raise SourceUnavailable(f"Could not reach `{host}` ({type(exc).__name__}).") from exc

    # ── convenience ──────────────────────────────────────────────────────

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        kwargs.setdefault("cache_ttl", 60)
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:
        kwargs.setdefault("cache_ttl", 60)
        return await self.request("OPTIONS", url, **kwargs)

    async def get_text(self, url: str, **kwargs: Any) -> str:
        response = await self.request("GET", url, **kwargs)
        if not response.ok:
            raise SourceUnavailable(f"`{urlsplit(url).netloc}` answered HTTP {response.status}.")
        return response.text

    async def get_json(self, url: str, *, expect: bool = True, **kwargs: Any) -> Any:
        response = await self.request("GET", url, **kwargs)
        if not response.ok:
            raise SourceUnavailable(
                f"`{urlsplit(url).netloc}` answered HTTP {response.status}.",
                hint=response.snippet(160) or None,
            )
        data = response.json()
        if expect and data in (None, [], {}):
            raise IntelError("The source returned an empty result set.")
        return data

    async def discord(self, path: str, *, method: str = "GET", params: dict[str, Any] | None = None, json_body: Any = None) -> Any:
        """Call the Discord REST API with the bot token."""
        response = await self.request(
            method,
            f"https://discord.com/api/v10{path}",
            params=params,
            json_body=json_body,
            headers={"Authorization": f"Bot {settings.token}", "Accept": "application/json"},
            cache=False,
        )
        if response.status == 429:
            raise SourceUnavailable("Discord rate-limited that lookup. Try again shortly.")
        if response.status in {401, 403}:
            raise IntelError(
                "Discord refused that request.",
                hint="The bot cannot see this resource. It only sees guilds it is a member of.",
            )
        if response.status == 404:
            raise IntelError("Discord has no such resource.")
        if not response.ok:
            raise SourceUnavailable(f"Discord API answered HTTP {response.status}.")
        return response.json()

    def cache_size(self) -> int:
        return len(self._cache)

    def clear_cache(self) -> int:
        size = len(self._cache)
        self._cache.clear()
        return size
