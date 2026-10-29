import asyncio
from datetime import UTC, date, datetime

import httpx
import pytest

from app.feeds.base import FeedFetchError, FeedParseError
from app.feeds.cisa import CISAAdvisoriesSource
from app.feeds.cisa_kev import CISAKEVSource
from app.feeds.registry import SOURCE_CLASSES
from app.feeds.research import (
    CiscoTalosSource,
    DFIRReportSource,
    MicrosoftThreatIntelSource,
    SentinelOneLabsSource,
)
from app.schemas.feed import Severity, ThreatCategory
from tests.feed_fixtures import (
    HOSTILE_HTML,
    RICH_CONTENT,
    SHA256,
    body,
    kev,
    kev_entry,
    make_source,
    rss,
    rss_item,
)


def parse(cls, content: bytes):
    source, _ = make_source(cls, body(content))
    return source.parse(content)


def fetch(source, **kwargs):
    return asyncio.run(source.fetch(**kwargs))


# --- registry ---------------------------------------------------------------


@pytest.mark.parametrize("cls", SOURCE_CLASSES)
def test_every_source_has_fixed_https_endpoint_on_its_own_host(cls) -> None:
    url = httpx.URL(cls.endpoint)

    assert url.scheme == "https"
    assert any(url.host == h or url.host.endswith(f".{h}") for h in cls.link_hosts)
    assert cls.timeout_seconds <= 30
    assert cls.refresh_minutes >= 15


# --- CISA KEV ---------------------------------------------------------------


def test_kev_normalization_preserves_catalog_fields() -> None:
    events = parse(CISAKEVSource, kev(kev_entry("CVE-2026-1111", "2026-10-20", "Known")))

    [event] = events
    assert event.source == "cisa_kev"
    assert event.external_id == "CVE-2026-1111"
    assert event.title == "CVE-2026-1111: ExampleSoft Gateway Command Injection Vulnerability"
    assert event.known_exploited is True
    assert event.category is ThreatCategory.EXPLOITED_VULNERABILITY
    assert event.cves == ["CVE-2026-1111"]
    assert event.affected_products == ["ExampleSoft Gateway"]
    assert event.published_at == datetime(2026, 10, 20, tzinfo=UTC)
    assert (
        event.source_url
        == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=CVE-2026-1111"
    )
    assert event.kev.vendor == "ExampleSoft"
    assert event.kev.product == "Gateway"
    assert event.kev.date_added == date(2026, 10, 20)
    assert event.kev.due_date == date(2026, 11, 10)
    assert event.kev.required_action.startswith("Apply mitigations")
    assert event.kev.known_ransomware_campaign_use == "Known"
    assert event.kev.cwes == ["CWE-78"]


def test_kev_severity_is_derived_and_labeled() -> None:
    known, unknown = parse(
        CISAKEVSource,
        kev(
            kev_entry("CVE-2026-1111", "2026-10-20", "Known"),
            kev_entry("CVE-2026-2222", "2026-10-21"),
        ),
    )

    assert known.severity is Severity.CRITICAL
    assert "ransomware" in known.severity_basis and known.severity_basis.startswith("Derived")
    assert known.tags == ["ransomware"]
    assert unknown.severity is Severity.HIGH
    assert unknown.severity_basis.startswith("Derived")
    assert unknown.tags == []
    assert unknown.kev.known_ransomware_campaign_use == "Unknown"


def test_kev_skips_malformed_entries() -> None:
    events = parse(
        CISAKEVSource,
        kev(
            kev_entry("CVE-2026-1111", "2026-10-20"),
            kev_entry("not-a-cve", "2026-10-20"),
            kev_entry("CVE-2026-2222", "not-a-date", vendorProject=123, cwes="CWE-1"),
            "garbage",
            None,
            {"cveID": None},
        ),
    )

    assert [e.external_id for e in events] == ["CVE-2026-1111", "CVE-2026-2222"]
    assert events[1].published_at is None
    assert events[1].kev.vendor is None
    assert events[1].kev.cwes == []


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[]", b'{"vulnerabilities": "nope"}', b"{}", b'{"vulnerabilities": null}'],
)
def test_kev_malformed_document_raises_parse_error(content: bytes) -> None:
    with pytest.raises(FeedParseError):
        parse(CISAKEVSource, content)


def test_kev_html_in_fields_is_not_kept_as_markup() -> None:
    [event] = parse(
        CISAKEVSource,
        kev(
            kev_entry(
                "CVE-2026-1111",
                "2026-10-20",
                shortDescription="Bad\x00\x1b thing <script>x</script>",
            )
        ),
    )

    assert "\x00" not in event.summary and "\x1b" not in event.summary


# --- RSS sources ------------------------------------------------------------


def test_rss_normalization_extracts_literal_entities() -> None:
    [event] = parse(
        CiscoTalosSource,
        rss(
            rss_item(
                title="Volt Typhoon targets gateways",
                description="<p>Summary with <b>markup</b>.</p>" + HOSTILE_HTML,
                content=RICH_CONTENT,
                categories=("Threat Advisory", "APT", "Top Story", "Landing Page Top Story"),
            )
        ),
    )

    assert event.source == "talos"
    assert event.category is ThreatCategory.THREAT_RESEARCH
    assert event.summary == "Summary with markup. click me"
    assert event.source_url == "https://blog.talosintelligence.com/sample-report/"
    assert event.cves == ["CVE-2026-1111", "CVE-2026-3333"]
    assert event.attack_techniques == ["T1059.001", "T1566"]
    assert event.threat_actors == ["Volt Typhoon", "Storm-0940"]
    assert event.malware_families == ["LockBit", "Cobalt Strike"]
    assert [i.value for i in event.iocs] == [
        "https://evil.example.com/payload",
        "45.33.32.156",
        SHA256,
    ]
    assert event.tags == ["Threat Advisory", "APT"]
    assert event.known_exploited is False  # never inferred from mentions
    assert event.severity is None  # research posts publish no severity
    # Fields the source does not provide stay empty rather than invented.
    assert event.campaigns == event.industries == event.countries == event.affected_products == []


@pytest.mark.parametrize(
    "link",
    [
        "javascript:alert(1)",
        "http://blog.talosintelligence.com/insecure/",
        "https://evil.example.com/phish",
        "https://blog.talosintelligence.com.evil.example/",
        "https://user:pass@blog.talosintelligence.com/x",
        "https://blog.talosintelligence.com:8443/x",
        "data:text/html,<script>alert(1)</script>",
        "//blog.talosintelligence.com/x",
        "x" * 3000,
    ],
)
def test_untrusted_report_links_are_dropped(link: str) -> None:
    [event] = parse(CiscoTalosSource, rss(rss_item(link=link)))

    assert event.source_url is None


def test_items_without_title_or_identity_are_skipped() -> None:
    events = parse(
        MicrosoftThreatIntelSource,
        rss(
            rss_item(title=None, guid="a"),
            rss_item(title="   ", guid="b"),
            rss_item(title="No identity", guid=None, link=None),
            rss_item(
                title="Kept", guid=None, link="https://www.microsoft.com/en-us/security/blog/x/"
            ),
        ),
    )

    assert [e.title for e in events] == ["Kept"]
    assert events[0].external_id == "https://www.microsoft.com/en-us/security/blog/x/"


def test_missing_or_bad_dates_are_none_not_guessed() -> None:
    content = (
        rss(rss_item(guid="x"))
        .replace(b"<pubDate>", b"<pubDate>not a date ")
        .replace(b"</pubDate>", b"</pubDate>")
    )

    [event] = parse(SentinelOneLabsSource, content)

    assert event.published_at is None


@pytest.mark.parametrize(
    "content",
    [
        b"<not-xml",
        b"<html><body>Service unavailable</body></html>",
        b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>',
        b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY lol "lol">]><rss><channel></channel></rss>',
        b'<?xml version="1.0"?><!DOCTYPE rss SYSTEM "http://evil.example.com/x.dtd"><rss/>',
        b"",
    ],
)
def test_malformed_or_dangerous_xml_is_rejected(content: bytes) -> None:
    with pytest.raises(FeedParseError):
        parse(DFIRReportSource, content)


def test_entity_expansion_bomb_rejected_before_parsing() -> None:
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        + b"".join(f'<!ENTITY lol{i} "{"&lol;" * 10}">'.encode() for i in range(1, 10))
        + b"]><rss><channel><item><title>&lol9;</title></item></channel></rss>"
    )

    with pytest.raises(FeedParseError, match="DTD"):
        parse(CISAAdvisoriesSource, bomb)


def test_duplicate_items_within_a_feed_are_kept_for_dedupe_by_identity() -> None:
    events = parse(
        CISAAdvisoriesSource,
        rss(rss_item(guid="same"), rss_item(guid="same"), rss_item(guid="other")),
    )

    assert [e.external_id for e in events] == ["same", "same", "other"]  # collapsed on upsert


def test_item_count_is_bounded() -> None:
    events = parse(CiscoTalosSource, rss(*(rss_item(guid=f"g{i}") for i in range(250))))

    assert len(events) == 100


# --- fetching ---------------------------------------------------------------


def test_fetch_contacts_only_the_configured_endpoint() -> None:
    source, transport = make_source(CiscoTalosSource, body(rss(rss_item(content=RICH_CONTENT))))

    result = fetch(source)
    source.parse(result.body)  # links and IOCs in the content must not trigger requests

    assert [str(r.url) for r in transport.requests] == ["https://blog.talosintelligence.com/rss/"]


def test_conditional_request_and_not_modified() -> None:
    source, transport = make_source(CISAKEVSource, body(b"", 304))

    result = fetch(source, etag='"v1"', last_modified="Wed, 28 Oct 2026 00:00:00 GMT")

    assert result.body is None
    request = transport.requests[0]
    assert request.headers["If-None-Match"] == '"v1"'
    assert request.headers["If-Modified-Since"] == "Wed, 28 Oct 2026 00:00:00 GMT"


def test_fetch_returns_cache_validators() -> None:
    source, _ = make_source(
        CISAKEVSource, body(kev(), 200, etag='"abc"', **{"last-modified": "yesterday"})
    )

    result = fetch(source)

    assert (result.etag, result.last_modified) == ('"abc"', "yesterday")


def _raise(exc: Exception):
    def handler(request):
        raise exc

    return handler


@pytest.mark.parametrize(
    ("handler", "status"),
    [
        (_raise(httpx.ReadTimeout("slow")), "timeout"),
        (_raise(httpx.ConnectTimeout("slow")), "timeout"),
        (_raise(httpx.ConnectError("refused")), "unavailable"),
        (body(b"", 500), "unavailable"),
        (body(b"", 503), "unavailable"),
        (body(b"", 429, **{"Retry-After": "120"}), "rate_limited"),
        (body(b"", 403), "error"),
        (body(b"", 404), "error"),
        (body(b"", 301, location="https://evil.example.com/"), "error"),
    ],
)
def test_fetch_failures_are_typed(handler, status: str) -> None:
    source, transport = make_source(CISAAdvisoriesSource, handler)

    with pytest.raises(FeedFetchError) as exc_info:
        fetch(source)

    assert exc_info.value.status == status
    assert len(transport.requests) == 1  # redirects are never followed


def test_rate_limit_carries_retry_after() -> None:
    source, _ = make_source(CISAKEVSource, body(b"", 429, **{"Retry-After": "90"}))

    with pytest.raises(FeedFetchError) as exc_info:
        fetch(source)

    assert exc_info.value.retry_after == 90


def test_oversized_response_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(CiscoTalosSource, "max_bytes", 1000)
    source, _ = make_source(CiscoTalosSource, body(b"x" * 5000))

    with pytest.raises(FeedFetchError, match="size limit"):
        fetch(source)
