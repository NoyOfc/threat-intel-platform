import asyncio
import base64
import logging
from datetime import UTC, datetime

import httpx
import pytest

from app.providers import base as provider_base
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.otx import OTXProvider
from app.providers.virustotal import VirusTotalProvider
from app.schemas.provider import ProviderStatus, Reputation
from app.services.enrichment import enrich
from tests.provider_helpers import FAKE_KEY, ioc, json_response, lookup, make_provider

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ALL_PROVIDERS = (VirusTotalProvider, AbuseIPDBProvider, OTXProvider)

VT_IP_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 2,
                "harmless": 50,
                "undetected": 6,
            },
            "reputation": -40,
            "tags": ["c2", "botnet", "c2"],
            "country": "NL",
            "asn": 64500,
            "as_owner": "Example Hosting\x00\x1b[31m",
            "last_analysis_date": 1_790_000_000,
            "whois": "very long registrant details that must not be kept",
        }
    }
}

ABUSE_PAYLOAD = {
    "data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 87,
        "totalReports": 142,
        "numDistinctUsers": 40,
        "lastReportedAt": "2026-09-28T10:00:00+00:00",
        "countryCode": "DE",
        "isp": "Example ISP",
        "usageType": "Data Center",
        "domain": "example.net",
        "isWhitelisted": False,
        "isTor": False,
        "reports": [{"comment": "reporter free text that must not be kept"}],
    }
}

OTX_PAYLOAD = {
    "asn": "AS64501 Example Networks",
    "country_code": "US",
    "pulse_info": {
        "count": 7,
        "pulses": [
            {
                "name": "Campaign A",
                "tags": ["phishing", "credential theft"],
                "malware_families": [{"display_name": "DemoLoader"}],
                "adversary": "EXAMPLE-ACTOR",
                "created": "2026-01-05T00:00:00.000000",
                "modified": "2026-09-20T12:00:00.000000",
            },
            {
                "name": "Campaign B",
                "tags": ["Phishing"],
                "malware_families": ["MockBot"],
                "adversary": "",
                "created": "2025-11-01T00:00:00",
                "modified": "2026-03-01T00:00:00",
            },
        ],
        "related": {"other": {"malware_families": ["MockBot"], "adversary": []}},
    },
}


# --- normalization ----------------------------------------------------------


def test_virustotal_normalizes_ip_report() -> None:
    provider, transport = make_provider(VirusTotalProvider, json_response(VT_IP_PAYLOAD))

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.OK
    assert result.reputation is Reputation.MALICIOUS
    assert (result.malicious_count, result.suspicious_count) == (12, 2)
    assert result.tags == ["c2", "botnet"]
    assert result.country == "NL"
    assert result.asn == 64500
    assert result.organization == "Example Hosting [31m"  # control characters stripped
    assert result.last_seen == datetime.fromtimestamp(1_790_000_000, UTC)
    assert result.raw_metadata_safe_subset["engines_total"] == 70
    assert result.raw_metadata_safe_subset["community_reputation"] == -40
    assert "whois" not in result.model_dump_json()
    assert result.simulated is False

    request = transport.requests[0]
    assert request.url == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    assert request.headers["x-apikey"] == FAKE_KEY


def test_virustotal_file_report_extracts_malware_families() -> None:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "undetected": 60},
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.demoloader",
                    "popular_threat_name": [{"value": "demoloader"}, {"value": "mockbot"}],
                },
            }
        }
    }
    provider, transport = make_provider(VirusTotalProvider, json_response(payload))

    result = lookup(provider, SHA256)

    assert result.malware_families == ["demoloader", "mockbot"]
    assert result.reputation is Reputation.SUSPICIOUS
    assert result.raw_metadata_safe_subset["threat_label"] == "trojan.demoloader"
    assert transport.requests[0].url.path == f"/api/v3/files/{SHA256}"


def test_virustotal_url_ioc_is_encoded_as_identifier_not_fetched() -> None:
    provider, transport = make_provider(
        VirusTotalProvider, json_response({"data": {"attributes": {}}})
    )

    lookup(provider, "http://evil.example.com/path?q=1")

    request = transport.requests[0]
    expected_id = base64.urlsafe_b64encode(b"http://evil.example.com/path?q=1").decode().rstrip("=")
    assert request.url.host == "www.virustotal.com"
    assert request.url.path == f"/api/v3/urls/{expected_id}"


def test_abuseipdb_normalizes_check_response() -> None:
    provider, transport = make_provider(AbuseIPDBProvider, json_response(ABUSE_PAYLOAD))

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.OK
    assert result.reputation is Reputation.MALICIOUS
    assert result.confidence == 87
    assert result.report_count == 142
    assert result.last_seen == datetime(2026, 9, 28, 10, tzinfo=UTC)
    assert result.country == "DE"
    assert result.raw_metadata_safe_subset["distinct_reporters"] == 40
    assert "reporter free text" not in result.model_dump_json()

    request = transport.requests[0]
    assert request.url.host == "api.abuseipdb.com"
    assert request.url.path == "/api/v2/check"
    assert request.url.params["ipAddress"] == "8.8.8.8"
    assert request.headers["Key"] == FAKE_KEY


def test_otx_normalizes_pulses() -> None:
    provider, transport = make_provider(OTXProvider, json_response(OTX_PAYLOAD))

    result = lookup(provider, "example.com")

    assert result.status is ProviderStatus.OK
    assert result.pulse_count == 7
    assert result.reputation is Reputation.MALICIOUS
    assert result.tags == ["phishing", "credential theft"]  # case-insensitive dedupe
    assert result.malware_families == ["DemoLoader", "MockBot"]
    assert result.threat_actors == ["EXAMPLE-ACTOR"]
    assert result.first_seen == datetime(2025, 11, 1, tzinfo=UTC)
    assert result.last_seen == datetime(2026, 9, 20, 12, tzinfo=UTC)
    assert (result.asn, result.organization) == (64501, "Example Networks")
    assert transport.requests[0].headers["X-OTX-API-KEY"] == FAKE_KEY


def test_otx_url_ioc_is_percent_encoded_into_path() -> None:
    provider, transport = make_provider(OTXProvider, json_response({"pulse_info": {"count": 0}}))

    result = lookup(provider, "http://evil.example.com/a/b")

    request = transport.requests[0]
    assert request.url.host == "otx.alienvault.com"
    assert request.url.raw_path.startswith(
        b"/api/v1/indicators/url/http%3A%2F%2Fevil.example.com%2Fa%2Fb/"
    )
    assert result.reputation is Reputation.UNKNOWN


def test_provider_lists_are_bounded() -> None:
    payload = {"data": {"attributes": {"tags": [f"tag-{i}" for i in range(500)] + ["x" * 5000]}}}
    provider, _ = make_provider(VirusTotalProvider, json_response(payload))

    result = lookup(provider, "example.com")

    assert len(result.tags) == 25
    assert all(len(tag) <= 64 for tag in result.tags)


# --- applicability, credentials, internal IOCs ------------------------------


@pytest.mark.parametrize("raw", ["example.com", "http://example.com/", SHA256])
def test_abuseipdb_skips_unsupported_types_without_request(raw: str) -> None:
    provider, transport = make_provider(AbuseIPDBProvider)

    assert lookup(provider, raw).status is ProviderStatus.NOT_SUPPORTED
    assert transport.requests == []


@pytest.mark.parametrize("cls", ALL_PROVIDERS)
def test_missing_credentials_reported_without_request(cls) -> None:
    provider, transport = make_provider(cls, api_key=None)

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.NOT_CONFIGURED
    assert cls.api_key_env in result.message
    assert transport.requests == []


@pytest.mark.parametrize("cls", ALL_PROVIDERS)
def test_blank_credentials_treated_as_missing(cls) -> None:
    provider, transport = make_provider(cls, api_key="   ")

    assert lookup(provider, "8.8.8.8").status is ProviderStatus.NOT_CONFIGURED
    assert transport.requests == []


@pytest.mark.parametrize("cls", ALL_PROVIDERS)
@pytest.mark.parametrize(
    "raw", ["10.0.0.1", "127.0.0.1", "::1", "169.254.169.254", "localhost", "http://192.168.1.1/x"]
)
def test_internal_iocs_never_sent_to_providers(cls, raw: str) -> None:
    provider, transport = make_provider(cls)

    result = lookup(provider, raw)

    assert result.status in (ProviderStatus.SKIPPED, ProviderStatus.NOT_SUPPORTED)
    assert transport.requests == []


# --- failures ---------------------------------------------------------------


def _raise(exc: Exception):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


@pytest.mark.parametrize(
    ("handler", "status"),
    [
        (json_response({"error": "bad key"}, 401), ProviderStatus.AUTH_ERROR),
        (json_response({"error": "forbidden"}, 403), ProviderStatus.AUTH_ERROR),
        (json_response({}, 429), ProviderStatus.RATE_LIMITED),
        (json_response({}, 500), ProviderStatus.UNAVAILABLE),
        (json_response({}, 503), ProviderStatus.UNAVAILABLE),
        (json_response({}, 400), ProviderStatus.ERROR),
        (_raise(httpx.ConnectError("connection refused")), ProviderStatus.UNAVAILABLE),
        (_raise(httpx.ReadTimeout("read timed out")), ProviderStatus.TIMEOUT),
        (_raise(httpx.ConnectTimeout("connect timed out")), ProviderStatus.TIMEOUT),
        (
            lambda request: httpx.Response(200, content=b"<html>not json</html>"),
            ProviderStatus.ERROR,
        ),
        (lambda request: httpx.Response(200, json=["not", "an", "object"]), ProviderStatus.ERROR),
        (json_response({"unexpected": "shape"}), ProviderStatus.ERROR),
        (json_response({}, 404), ProviderStatus.NOT_FOUND),
    ],
)
def test_failures_become_statuses_not_exceptions(handler, status: ProviderStatus) -> None:
    provider, _ = make_provider(VirusTotalProvider, handler)

    result = lookup(provider, "8.8.8.8")

    assert result.status is status
    assert result.simulated is False
    assert provider.health.last_status is status


def test_slow_provider_times_out() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json=VT_IP_PAYLOAD)

    provider, _ = make_provider(VirusTotalProvider, slow, timeout=0.05)

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.TIMEOUT


def test_redirects_are_not_followed() -> None:
    provider, transport = make_provider(
        VirusTotalProvider,
        lambda request: httpx.Response(302, headers={"location": "http://169.254.169.254/"}),
    )

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.ERROR
    assert "redirect" in result.message.lower()
    assert len(transport.requests) == 1
    assert transport.requests[0].url.host == "www.virustotal.com"


def test_oversized_response_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provider_base, "MAX_RESPONSE_BYTES", 1000)
    provider, _ = make_provider(
        VirusTotalProvider, lambda request: httpx.Response(200, content=b"{" + b" " * 5000 + b"}")
    )

    assert lookup(provider, "8.8.8.8").status is ProviderStatus.ERROR


def test_rate_limit_starts_cooldown_and_stops_requests() -> None:
    provider, transport = make_provider(
        VirusTotalProvider, json_response({}, 429, **{"Retry-After": "120"})
    )

    first = lookup(provider, "8.8.8.8")
    second = lookup(provider, "1.1.1.1")

    assert first.status is ProviderStatus.RATE_LIMITED
    assert second.status is ProviderStatus.RATE_LIMITED
    assert len(transport.requests) == 1  # second lookup did not hit the provider
    assert provider.health.cooling_down


def test_destination_guard_blocks_non_provider_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, transport = make_provider(VirusTotalProvider)
    monkeypatch.setattr(provider, "build_request", lambda ioc: ("@evil.example.com/steal", {}))

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.ERROR
    assert transport.requests == []


# --- credential hygiene -----------------------------------------------------


@pytest.mark.parametrize(
    "handler",
    [
        json_response({"error": {"message": "bad key"}}, 401),
        json_response({}, 500),
        _raise(httpx.ConnectError("boom")),
        lambda request: httpx.Response(200, content=b"garbage"),
        json_response(VT_IP_PAYLOAD),
    ],
)
def test_credentials_never_appear_in_results_or_logs(
    handler, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    provider, _ = make_provider(VirusTotalProvider, handler)

    result = lookup(provider, "8.8.8.8")

    assert FAKE_KEY not in result.model_dump_json()
    assert FAKE_KEY not in caplog.text
    assert FAKE_KEY not in repr(provider)


# --- demo mode --------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_PROVIDERS)
def test_demo_mode_is_simulated_deterministic_and_offline(cls) -> None:
    provider, transport = make_provider(cls, demo_mode=True)

    first = lookup(provider, "8.8.8.8")
    second = lookup(provider, "8.8.8.8")

    assert first.status is ProviderStatus.OK
    assert first.simulated is True
    assert "simulated" in first.message.lower()
    assert first == second
    assert transport.requests == []


def test_demo_mode_works_without_credentials() -> None:
    provider, transport = make_provider(VirusTotalProvider, api_key=None, demo_mode=True)

    result = lookup(provider, "example.com")

    assert result.simulated is True
    assert transport.requests == []


def test_demo_results_vary_across_iocs() -> None:
    provider, _ = make_provider(VirusTotalProvider, demo_mode=True)

    reputations = {lookup(provider, f"8.8.8.{i}").reputation for i in range(1, 40)}

    assert len(reputations) >= 2


def test_demo_data_uses_documentation_asns() -> None:
    provider, _ = make_provider(VirusTotalProvider, demo_mode=True)

    result = lookup(provider, "9.9.9.9")

    assert result.asn is None or 64496 <= result.asn <= 64511


def test_live_failure_is_never_replaced_with_demo_data() -> None:
    provider, _ = make_provider(VirusTotalProvider, json_response({}, 503), demo_mode=False)

    result = lookup(provider, "8.8.8.8")

    assert result.status is ProviderStatus.UNAVAILABLE
    assert result.simulated is False
    assert result.malicious_count is None


def test_demo_mode_still_skips_internal_iocs() -> None:
    provider, _ = make_provider(VirusTotalProvider, demo_mode=True)

    assert lookup(provider, "192.168.1.1").status is ProviderStatus.SKIPPED


# --- enrichment fan-out -----------------------------------------------------


def test_one_failing_provider_does_not_fail_enrichment() -> None:
    vt, _ = make_provider(VirusTotalProvider, json_response(VT_IP_PAYLOAD))
    abuse, _ = make_provider(AbuseIPDBProvider, json_response({}, 503))
    otx, _ = make_provider(OTXProvider, _raise(httpx.ConnectError("down")))

    enrichment = asyncio.run(enrich(ioc("8.8.8.8"), [vt, abuse, otx]))

    assert enrichment.status == "partial"
    assert [r.status for r in enrichment.results] == [
        ProviderStatus.OK,
        ProviderStatus.UNAVAILABLE,
        ProviderStatus.UNAVAILABLE,
    ]


def test_unexpected_provider_exception_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    vt, _ = make_provider(VirusTotalProvider, json_response(VT_IP_PAYLOAD))
    broken, _ = make_provider(OTXProvider)

    async def explode(ioc):
        raise RuntimeError("bug")

    monkeypatch.setattr(broken, "lookup", explode)

    enrichment = asyncio.run(enrich(ioc("8.8.8.8"), [vt, broken]))

    assert enrichment.status == "partial"
    assert enrichment.results[1].status is ProviderStatus.ERROR


def test_enrichment_status_values() -> None:
    down, _ = make_provider(VirusTotalProvider, json_response({}, 500))
    unconfigured, _ = make_provider(VirusTotalProvider, api_key=None)

    assert asyncio.run(enrich(ioc("8.8.8.8"), [down])).status == "failed"
    assert asyncio.run(enrich(ioc("8.8.8.8"), [unconfigured])).status == "no_providers"
