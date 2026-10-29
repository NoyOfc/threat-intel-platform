"""Common provider interface.

Subclasses describe *what* to ask (path, params, auth header) and how to
normalize the answer. This base class owns *how* requests are made, so the
destination, redirect, timeout, size, and credential rules live in one place.
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx
from pydantic import SecretStr

from app.schemas.provider import ProviderResult, ProviderStatus
from app.services.ioc import IOC, IOCType

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_COOLDOWN_SECONDS = 60
MAX_COOLDOWN_SECONDS = 3600


class ProviderHTTPError(Exception):
    def __init__(self, status_code: int, retry_after: int | None = None) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code
        self.retry_after = retry_after


class ProviderResponseError(Exception):
    """The provider answered with something unusable (oversized, not JSON, wrong shape)."""


@dataclass
class ProviderHealth:
    """Outcome of the most recent live lookup, kept in memory for the status page."""

    last_status: ProviderStatus | None = None
    last_checked_at: datetime | None = None
    cooldown_until: float = 0.0

    @property
    def cooling_down(self) -> bool:
        return time.monotonic() < self.cooldown_until

    def record(self, status: ProviderStatus, retry_after: int | None = None) -> None:
        self.last_status = status
        self.last_checked_at = datetime.now(UTC)
        if status is ProviderStatus.RATE_LIMITED:
            delay = min(retry_after or DEFAULT_COOLDOWN_SECONDS, MAX_COOLDOWN_SECONDS)
            self.cooldown_until = time.monotonic() + delay


class Provider(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    api_host: ClassVar[str]
    api_key_env: ClassVar[str]
    supported_types: ClassVar[frozenset[IOCType]]

    def __init__(
        self,
        *,
        api_key: SecretStr | None,
        client: httpx.AsyncClient,
        demo_mode: bool,
        timeout: float,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self._timeout = timeout
        self.demo_mode = demo_mode
        self.health = ProviderHealth()

    def __repr__(self) -> str:
        # Never include the key, even masked.
        return f"<{type(self).__name__} configured={self.configured} demo={self.demo_mode}>"

    @property
    def configured(self) -> bool:
        return self._api_key is not None and bool(self._api_key.get_secret_value().strip())

    # --- subclass hooks -------------------------------------------------------

    @abstractmethod
    def build_request(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Return (path, query params). The path must start with "/" and percent-encode IOC data."""

    @abstractmethod
    def auth_headers(self, api_key: str) -> dict[str, str]: ...

    @abstractmethod
    def normalize(self, ioc: IOC, payload: dict[str, Any]) -> ProviderResult: ...

    @abstractmethod
    def simulate(self, ioc: IOC) -> ProviderResult:
        """Deterministic, fictional result for DEMO_MODE. Must set simulated=True."""

    # --- lookup ---------------------------------------------------------------

    def result(
        self, status: ProviderStatus, message: str | None = None, **fields: Any
    ) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            display_name=self.display_name,
            status=status,
            message=message,
            **fields,
        )

    async def lookup(self, ioc: IOC) -> ProviderResult:
        """Look up one IOC. Never raises: every failure becomes a status on the result."""
        if ioc.type not in self.supported_types:
            return self.result(
                ProviderStatus.NOT_SUPPORTED,
                f"{self.display_name} does not support {ioc.type.value} indicators.",
            )
        if ioc.is_internal:
            return self.result(
                ProviderStatus.SKIPPED,
                "Internal address or hostname. Not sent to third-party providers.",
            )
        if self.demo_mode:
            return self.simulate(ioc)
        if not self.configured:
            return self.result(
                ProviderStatus.NOT_CONFIGURED, f"No API key configured ({self.api_key_env})."
            )
        if self.health.cooling_down:
            return self.result(
                ProviderStatus.RATE_LIMITED, "Rate limited by provider. Waiting before retrying."
            )

        retry_after: int | None = None
        try:
            async with asyncio.timeout(self._timeout + 1):
                payload = await self._fetch(ioc)
            if payload is None:
                result = self.result(
                    ProviderStatus.NOT_FOUND, f"{self.display_name} has no record of this IOC."
                )
            else:
                result = self.normalize(ioc, payload)
        except TimeoutError, httpx.TimeoutException:
            result = self.result(ProviderStatus.TIMEOUT, "Provider did not respond in time.")
        except ProviderHTTPError as exc:
            retry_after = exc.retry_after
            result = self._http_error_result(exc)
        except httpx.TransportError:
            result = self.result(ProviderStatus.UNAVAILABLE, "Could not reach the provider.")
        except (ProviderResponseError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # Log the exception class only: messages could contain response content.
            logger.warning("%s returned an unusable response (%s)", self.name, type(exc).__name__)
            result = self.result(ProviderStatus.ERROR, "Provider returned an unexpected response.")

        self.health.record(result.status, retry_after)
        return result

    def _http_error_result(self, exc: ProviderHTTPError) -> ProviderResult:
        code = exc.status_code
        if code in (401, 403):
            return self.result(
                ProviderStatus.AUTH_ERROR, "Authentication failed. Check the configured API key."
            )
        if code == 429:
            return self.result(ProviderStatus.RATE_LIMITED, "Rate limit or quota exceeded.")
        if code >= 500:
            return self.result(ProviderStatus.UNAVAILABLE, f"Provider outage (HTTP {code}).")
        if 300 <= code < 400:
            return self.result(
                ProviderStatus.ERROR, "Provider redirected; redirects are not followed."
            )
        return self.result(ProviderStatus.ERROR, f"Provider rejected the request (HTTP {code}).")

    async def _fetch(self, ioc: IOC) -> dict[str, Any] | None:
        path, params = self.build_request(ioc)
        url = httpx.URL(f"https://{self.api_host}{path}", params=params)
        if url.scheme != "https" or url.host != self.api_host or not path.startswith("/"):
            raise ProviderResponseError("refusing to contact a non-provider destination")
        assert self._api_key is not None  # noqa: S101 - guarded by `configured`
        headers = {
            "Accept": "application/json",
            **self.auth_headers(self._api_key.get_secret_value()),
        }

        async with self._client.stream(
            "GET", url, headers=headers, timeout=self._timeout
        ) as response:
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise ProviderHTTPError(response.status_code, _retry_after(response))
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ProviderResponseError("response too large")

        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ProviderResponseError("expected a JSON object")
        return payload


def _retry_after(response: httpx.Response) -> int | None:
    value = response.headers.get("retry-after", "")
    return int(value) if value.isdigit() else None
