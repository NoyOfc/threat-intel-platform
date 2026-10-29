import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.feeds.cisa import CISAAdvisoriesSource
from app.feeds.cisa_kev import CISAKEVSource
from app.feeds.research import CiscoTalosSource, DFIRReportSource, SentinelOneLabsSource
from app.main import create_app
from app.services import feed_refresh
from app.services.threat_feed import event_id
from tests.feed_fixtures import (
    RICH_CONTENT,
    ago,
    body,
    kev,
    kev_entry,
    make_source,
    recent_date,
    rss,
    rss_item,
)

KEV_DOC = kev(
    kev_entry("CVE-2026-1111", recent_date(2), "Known"),
    kev_entry("CVE-2026-2222", recent_date(10), product="Mail Server"),
    kev_entry("CVE-2020-0001", "2020-01-01"),
)
TALOS_DOC = rss(
    rss_item(
        title="Volt Typhoon exploits ExampleSoft gateways",
        guid="talos-1",
        published=ago(hours=3),
        content=RICH_CONTENT,
        categories=("APT",),
    ),
    rss_item(
        title="Weekly roundup", guid="talos-2", published=ago(days=20), description="<p>News.</p>"
    ),
    rss_item(title="Weekly roundup", guid="talos-2", published=ago(days=20)),  # duplicate in feed
)


@pytest.fixture
def sources():
    kev_source, kev_transport = make_source(CISAKEVSource, body(KEV_DOC, etag='"kev-v1"'))
    talos, _ = make_source(CiscoTalosSource, body(TALOS_DOC))
    failing, _ = make_source(SentinelOneLabsSource, body(b"", 503))
    broken, _ = make_source(DFIRReportSource, body(b"<html>not a feed</html>"))
    return {
        "kev": (kev_source, kev_transport),
        "talos": talos,
        "failing": failing,
        "broken": broken,
    }


def build_client(tmp_path: Path, feed_sources, **settings) -> TestClient:
    config = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'test.db'}", **settings)
    return TestClient(create_app(config, feed_sources=feed_sources))


@pytest.fixture
def client(tmp_path: Path, sources) -> Iterator[TestClient]:
    feed_sources = [sources["kev"][0], sources["talos"], sources["failing"], sources["broken"]]
    with build_client(tmp_path, feed_sources) as test_client:
        yield test_client


def refresh(client: TestClient) -> dict:
    response = client.post("/api/feed/refresh")
    assert response.status_code == 200, response.text
    return {s["source"]: s for s in response.json()["sources"]}


# --- refresh ----------------------------------------------------------------


def test_refresh_collects_and_isolates_failures(client: TestClient) -> None:
    results = refresh(client)

    assert results["cisa_kev"]["status"] == "updated"
    assert results["cisa_kev"]["new"] == 3
    assert results["talos"]["status"] == "updated"
    assert (results["talos"]["fetched"], results["talos"]["new"]) == (
        3,
        2,
    )  # in-feed duplicate collapsed
    assert results["sentinelone_labs"]["status"] == "unavailable"
    assert results["dfir_report"]["status"] == "error"
    assert "parsed" in results["dfir_report"]["message"]


def test_second_refresh_is_cached_and_does_not_duplicate(client: TestClient, sources) -> None:
    refresh(client)
    second = refresh(client)

    assert second["cisa_kev"]["status"] == "fresh"
    assert len(sources["kev"][1].requests) == 1  # no second request within the refresh interval
    events = client.get("/api/feed/events", params={"window": "30d"}).json()
    assert events["total"] == 4


def test_refetch_after_interval_uses_conditional_request_and_dedupes(
    tmp_path: Path, sources
) -> None:
    kev_source, transport = sources["kev"]
    with build_client(tmp_path, [kev_source]) as client:
        collector = client.app.state.feed_collector
        first = asyncio.run(collector.refresh())
        later = asyncio.run(collector.refresh(now=datetime.now(UTC) + timedelta(hours=2)))

    assert first.sources[0].new == 3
    assert later.sources[0].status == "updated"
    assert (later.sources[0].new, later.sources[0].updated) == (0, 0)
    assert transport.requests[1].headers["If-None-Match"] == '"kev-v1"'


def test_refresh_rate_limit_starts_cooldown(tmp_path: Path) -> None:
    limited, transport = make_source(CISAKEVSource, body(b"", 429, **{"Retry-After": "600"}))
    with build_client(tmp_path, [limited]) as client:
        first = refresh(client)
        second = refresh(client)

    assert first["cisa_kev"]["status"] == "rate_limited"
    assert second["cisa_kev"]["status"] == "rate_limited"
    assert len(transport.requests) == 1


def test_slow_source_times_out_without_blocking_others(
    tmp_path: Path, monkeypatch, sources
) -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(10)
        return httpx.Response(200, content=TALOS_DOC)

    stalled, _ = make_source(DFIRReportSource, slow)
    monkeypatch.setattr(DFIRReportSource, "timeout_seconds", 0.05)
    monkeypatch.setattr(feed_refresh, "FETCH_GRACE_SECONDS", 0.0)

    with build_client(tmp_path, [stalled, sources["talos"]]) as client:
        results = refresh(client)

    assert results["dfir_report"]["status"] == "timeout"
    assert results["talos"]["status"] == "updated"


def test_refresh_disabled(tmp_path: Path, sources) -> None:
    with build_client(tmp_path, [sources["talos"]], feeds_enabled=False) as client:
        response = client.post("/api/feed/refresh")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


def test_analyst_fields_survive_recollection(tmp_path: Path) -> None:
    v1 = rss(rss_item(title="Original title", guid="post-1", published=ago(hours=1)))
    v2 = rss(rss_item(title="Updated title", guid="post-1", published=ago(hours=1)))
    documents = iter([v1, v2])
    source, _ = make_source(
        CiscoTalosSource, lambda request: httpx.Response(200, content=next(documents))
    )

    with build_client(tmp_path, [source]) as client:
        collector = client.app.state.feed_collector
        asyncio.run(collector.refresh())
        record_id = event_id("talos", "post-1")
        client.patch(f"/api/feed/events/{record_id}/analyst", json={"status": "relevant"})
        client.post(f"/api/feed/events/{record_id}/notes", json={"body": "Track this."})
        result = asyncio.run(collector.refresh(now=datetime.now(UTC) + timedelta(hours=1)))
        event = client.get(f"/api/feed/events/{record_id}").json()

    assert result.sources[0].updated == 1
    assert event["title"] == "Updated title"
    assert event["analyst_status"] == "relevant"
    assert [n["body"] for n in event["notes"]] == ["Track this."]


# --- listing and filters ----------------------------------------------------


def titles(response) -> list[str]:
    return [item["title"] for item in response.json()["items"]]


def test_window_filters(client: TestClient) -> None:
    refresh(client)

    assert titles(client.get("/api/feed/events", params={"window": "24h"})) == [
        "Volt Typhoon exploits ExampleSoft gateways"
    ]
    assert len(titles(client.get("/api/feed/events", params={"window": "7d"}))) == 2
    assert (
        len(titles(client.get("/api/feed/events", params={"window": "30d"}))) == 4
    )  # 2020 KEV excluded


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (
            {"severity": "critical"},
            ["CVE-2026-1111: ExampleSoft Gateway Command Injection Vulnerability"],
        ),
        (
            {"category": "threat_research"},
            ["Volt Typhoon exploits ExampleSoft gateways", "Weekly roundup"],
        ),
        ({"source": "cisa_kev"}, 2),
        ({"threat_actor": "volt typhoon"}, ["Volt Typhoon exploits ExampleSoft gateways"]),
        ({"malware": "LockBit"}, ["Volt Typhoon exploits ExampleSoft gateways"]),
        ({"cve": "CVE-2026-1111"}, 2),
        ({"technique": "T1059"}, ["Volt Typhoon exploits ExampleSoft gateways"]),
        (
            {"q": "mail server"},
            ["CVE-2026-2222: ExampleSoft Gateway Command Injection Vulnerability"],
        ),
        ({"q": "nothing matches this"}, []),
    ],
)
def test_filters(client: TestClient, params: dict, expected) -> None:
    refresh(client)

    result = titles(client.get("/api/feed/events", params={"window": "30d", **params}))

    assert (len(result) if isinstance(expected, int) else result) == expected


def test_facets_list_available_filter_values(client: TestClient) -> None:
    refresh(client)

    facets = client.get("/api/feed/events", params={"window": "30d"}).json()["facets"]

    assert {f["value"] for f in facets["sources"]} == {"cisa_kev", "talos"}
    assert {f["value"]: f["count"] for f in facets["severities"]} == {"critical": 1, "high": 1}
    assert [f["value"] for f in facets["threat_actors"]] == ["Storm-0940", "Volt Typhoon"]


@pytest.mark.parametrize(
    "params",
    [
        {"window": "1y"},
        {"severity": "extreme"},
        {"category": "malware"},
        {"q": "x" * 201},
        {"cve": "x" * 21},
    ],
)
def test_invalid_filters_rejected(client: TestClient, params: dict) -> None:
    response = client.get("/api/feed/events", params=params)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


# --- detail, KEV cross-reference, related -----------------------------------


def test_event_detail_with_related_and_kev_confirmation(client: TestClient) -> None:
    refresh(client)
    talos_id = event_id("talos", "talos-1")

    detail = client.get(f"/api/feed/events/{talos_id}").json()

    assert detail["kev_cves"] == ["CVE-2026-1111"]  # CVE-2026-3333 is mentioned but not in KEV
    assert detail["known_exploited"] is False
    assert [r["title"] for r in detail["related"]] == [
        "CVE-2026-1111: ExampleSoft Gateway Command Injection Vulnerability"
    ]
    assert detail["related"][0]["shared"] == ["CVE-2026-1111"]
    assert [i["value"] for i in detail["iocs"]][:2] == [
        "https://evil.example.com/payload",
        "45.33.32.156",
    ]


def test_kev_event_detail(client: TestClient) -> None:
    refresh(client)

    detail = client.get(f"/api/feed/events/{event_id('cisa_kev', 'CVE-2026-1111')}").json()

    assert detail["known_exploited"] is True
    assert detail["kev"]["known_ransomware_campaign_use"] == "Known"
    assert detail["kev"]["due_date"] == "2026-11-10"
    assert detail["kev_cves"] == ["CVE-2026-1111"]


@pytest.mark.parametrize("bad_id", ["nope", "0" * 31, "G" * 32, "../../etc/passwd"])
def test_event_id_is_validated(client: TestClient, bad_id: str) -> None:
    assert client.get(f"/api/feed/events/{bad_id}").status_code in (404, 422)


def test_unknown_event_404(client: TestClient) -> None:
    response = client.get(f"/api/feed/events/{'0' * 32}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


# --- analyst workflow -------------------------------------------------------


def test_analyst_status(client: TestClient) -> None:
    refresh(client)
    url = f"/api/feed/events/{event_id('talos', 'talos-1')}/analyst"

    monitoring = client.patch(url, json={"status": "monitoring"}).json()
    not_relevant = client.patch(url, json={"status": "not_relevant"}).json()
    filtered = titles(
        client.get("/api/feed/events", params={"window": "30d", "analyst_status": "not_relevant"})
    )
    cleared = client.patch(url, json={"status": None}).json()

    assert monitoring["analyst_status"] == "monitoring"
    assert not_relevant["analyst_status"] == "not_relevant"
    assert not_relevant["analyst_updated_at"] is not None
    assert filtered == ["Volt Typhoon exploits ExampleSoft gateways"]
    assert cleared["analyst_status"] is None


def test_threat_event_notes(client: TestClient) -> None:
    refresh(client)
    base = f"/api/feed/events/{event_id('talos', 'talos-1')}"

    client.post(f"{base}/notes", json={"body": "  <b>Watch</b> this\x00  "})
    event = client.post(f"{base}/notes", json={"body": "Second note"}).json()
    first_id = event["notes"][0]["id"]
    deleted = client.delete(f"{base}/notes/{first_id}")
    after = client.get(base).json()

    assert [n["body"] for n in event["notes"]] == ["<b>Watch</b> this", "Second note"]
    assert deleted.status_code == 204
    assert [n["body"] for n in after["notes"]] == ["Second note"]
    assert client.delete(f"{base}/notes/{first_id}").status_code == 404


@pytest.mark.parametrize(
    "payload",
    [{"status": "maybe"}, {}, {"status": "relevant", "notes": "old field"}],
)
def test_analyst_update_validation(client: TestClient, payload: dict) -> None:
    refresh(client)

    response = client.patch(
        f"/api/feed/events/{event_id('talos', 'talos-1')}/analyst", json=payload
    )

    assert response.status_code == 422


@pytest.mark.parametrize("payload", [{"body": ""}, {"body": "x" * 5001}, {"text": "x"}])
def test_note_validation(client: TestClient, payload: dict) -> None:
    refresh(client)

    response = client.post(f"/api/feed/events/{event_id('talos', 'talos-1')}/notes", json=payload)

    assert response.status_code == 422


def test_analyst_update_unknown_event(client: TestClient) -> None:
    assert (
        client.patch(
            f"/api/feed/events/{'f' * 32}/analyst", json={"status": "relevant"}
        ).status_code
        == 404
    )


# --- trending and sources ---------------------------------------------------


def test_trending_is_scoped_to_collected_data(client: TestClient) -> None:
    refresh(client)

    trending = client.get("/api/feed/trending", params={"window": "30d"}).json()

    assert (
        "collected" in trending["scope"].lower()
        and "not a measure of global" in trending["scope"].lower()
    )
    assert trending["events_considered"] == 4
    assert trending["cves"][0] == {"value": "CVE-2026-1111", "count": 2}
    assert {"value": "ExampleSoft Gateway", "count": 1} in trending["affected_products"]
    assert [t["value"] for t in trending["attack_techniques"]] == ["T1059.001", "T1566"]


def test_sources_status(client: TestClient) -> None:
    refresh(client)

    sources = {s["name"]: s for s in client.get("/api/feed/sources").json()}

    assert sources["cisa_kev"]["event_count"] == 3
    assert sources["cisa_kev"]["last_status"] == "updated"
    assert sources["sentinelone_labs"]["last_status"] == "unavailable"
    assert sources["sentinelone_labs"]["last_success_at"] is None
    assert sources["cisa_kev"]["endpoint"].startswith("https://www.cisa.gov/")


def test_feed_items_never_contain_markup(client: TestClient) -> None:
    refresh(client)

    response = client.get("/api/feed/events", params={"window": "30d"})

    for forbidden in ("<script", "onerror", "javascript:", "<iframe"):
        assert forbidden not in response.text


def test_planned_source_is_listed_but_never_fetched(tmp_path: Path) -> None:
    planned, transport = make_source(CISAAdvisoriesSource, body(rss(rss_item())))

    with build_client(tmp_path, [planned]) as client:
        results = refresh(client)
        listed = client.get("/api/feed/sources").json()

    assert results["cisa_advisories"]["status"] == "planned"
    assert "403" in results["cisa_advisories"]["message"]
    assert transport.requests == []
    assert listed[0]["planned_reason"] == CISAAdvisoriesSource.planned_reason
