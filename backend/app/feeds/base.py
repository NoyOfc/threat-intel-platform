"""Common feed-source interface.

Subclasses declare a fixed ``endpoint`` and implement ``parse``. This base class
owns how the endpoint is fetched, so destination, redirect, timeout, size, and
caching rules live in one place.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar

import httpx

from app.schemas.feed import ThreatCategory, ThreatEventData

DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class FeedFetchError(Exception):
    """Fetch failed. ``status`` maps onto SourceRefreshStatus."""

    def __init__(self, status: str, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


class FeedParseError(Exception):
    """The source answered with content that can't be safely parsed."""


@dataclass(frozen=True)
class FetchResult:
    body: bytes | None  # None when the source answered 304 Not Modified
    etag: str | None
    last_modified: str | None


class FeedSource(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    endpoint: ClassVar[str]
    link_hosts: ClassVar[frozenset[str]]
    category: ClassVar[ThreatCategory]
    refresh_minutes: ClassVar[int] = 15
    timeout_seconds: ClassVar[float] = 15.0
    max_bytes: ClassVar[int] = DEFAULT_MAX_BYTES
    # Set when a source can't be integrated reliably yet. Planned sources are listed
    # with this reason but never fetched.
    planned_reason: ClassVar[str | None] = None

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @abstractmethod
    def parse(self, body: bytes) -> list[ThreatEventData]:
        """Normalize the fetched document. Must not perform any network access."""

    async def fetch(self, etag: str | None = None, last_modified: str | None = None) -> FetchResult:
        url = httpx.URL(self.endpoint)
        if url.scheme != "https" or not url.host:
            raise FeedFetchError("error", "Source endpoint must be https.")
        headers = {"Accept": "application/json, application/rss+xml, application/xml;q=0.9"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        try:
            async with self._client.stream(
                "GET", url, headers=headers, timeout=self.timeout_seconds
            ) as response:
                if response.status_code == 304:
                    return FetchResult(None, etag, last_modified)
                if response.status_code == 429:
                    raise FeedFetchError(
                        "rate_limited", "Source rate limited the request.", _retry_after(response)
                    )
                if 300 <= response.status_code < 400:
                    raise FeedFetchError("error", "Source redirected; redirects are not followed.")
                if response.status_code >= 500:
                    raise FeedFetchError(
                        "unavailable", f"Source outage (HTTP {response.status_code})."
                    )
                if response.status_code != 200:
                    raise FeedFetchError("error", f"Source returned HTTP {response.status_code}.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.max_bytes:
                        raise FeedFetchError("error", "Source response exceeded the size limit.")
                return FetchResult(
                    bytes(body),
                    response.headers.get("etag"),
                    response.headers.get("last-modified"),
                )
        except httpx.TimeoutException:
            raise FeedFetchError("timeout", "Source did not respond in time.") from None
        except httpx.TransportError:
            raise FeedFetchError("unavailable", "Could not reach the source.") from None

    def safe_link(self, value: str | None) -> str | None:
        """Keep a report link only if it is https on one of this source's own hosts.

        The link is shown to analysts as a labeled external link; the backend never
        requests it.
        """
        if not value or len(value) > 2048:
            return None
        try:
            url = httpx.URL(value.strip())
        except httpx.InvalidURL, ValueError:
            return None
        host = url.host or ""
        if url.scheme != "https" or url.userinfo or url.port not in (None, 443):
            return None
        if not any(host == allowed or host.endswith(f".{allowed}") for allowed in self.link_hosts):
            return None
        return str(url)


def _retry_after(response: httpx.Response) -> int | None:
    value = response.headers.get("retry-after", "")
    return int(value) if value.isdigit() else None


def to_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
