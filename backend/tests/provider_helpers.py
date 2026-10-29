"""Build providers backed by httpx.MockTransport so tests never touch the network."""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import SecretStr

from app.providers.base import Provider
from app.schemas.provider import ProviderResult, ProviderStatus, Reputation
from app.services.ioc import IOC, parse_ioc

FAKE_KEY = "fake-test-key-not-a-real-credential-0000"

Handler = Callable[[httpx.Request], Any]


class RecordingTransport(httpx.MockTransport):
    """MockTransport that remembers every request it receives."""

    def __init__(self, handler: Handler) -> None:
        self.requests: list[httpx.Request] = []

        async def record(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            response = handler(request)
            if asyncio.iscoroutine(response):
                response = await response
            return response

        super().__init__(record)


def make_provider(
    cls: type[Provider],
    handler: Handler | None = None,
    *,
    api_key: str | None = FAKE_KEY,
    demo_mode: bool = False,
    timeout: float = 2.0,
) -> tuple[Provider, RecordingTransport]:
    transport = RecordingTransport(handler or (lambda request: httpx.Response(200, json={})))
    client = httpx.AsyncClient(transport=transport, follow_redirects=False)
    provider = cls(
        api_key=SecretStr(api_key) if api_key is not None else None,
        client=client,
        demo_mode=demo_mode,
        timeout=timeout,
    )
    return provider, transport


def lookup(provider: Provider, raw: str) -> ProviderResult:
    return asyncio.run(provider.lookup(parse_ioc(raw)))


def ioc(raw: str) -> IOC:
    return parse_ioc(raw)


def json_response(payload: Any, status: int = 200, **headers: str) -> Handler:
    return lambda request: httpx.Response(status, json=payload, headers=headers)


def result(
    provider: str = "virustotal", status: ProviderStatus = ProviderStatus.OK, **fields: Any
) -> ProviderResult:
    """Hand-built ProviderResult for risk-engine tests."""
    names = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "otx": "AlienVault OTX"}
    fields.setdefault("reputation", Reputation.UNKNOWN)
    return ProviderResult(provider=provider, display_name=names[provider], status=status, **fields)


NOW = datetime(2026, 10, 1, tzinfo=UTC)
