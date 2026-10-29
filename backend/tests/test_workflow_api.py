"""Investigation history, watchlist, tags, IOC relationships, and IOC context."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.feeds.research import CiscoTalosSource
from app.main import create_app
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.otx import OTXProvider
from app.providers.virustotal import VirusTotalProvider
from tests.feed_fixtures import ago, body, make_source, rss, rss_item
from tests.provider_helpers import json_response, make_provider

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def investigate(client: TestClient, ioc: str) -> dict:
    response = client.post("/api/investigate", json={"ioc": ioc})
    assert response.status_code == 201, response.text
    return response.json()


def context(client: TestClient, ioc_id: int) -> dict:
    response = client.get(f"/api/iocs/{ioc_id}")
    assert response.status_code == 200, response.text
    return response.json()


def relations(ctx: dict) -> set[tuple]:
    return {
        (r["direction"], r["relation"], r["target_value"], r["origin"])
        for r in ctx["relationships"]
    }


# --- investigation history --------------------------------------------------


def test_investigations_are_saved_and_reopened_unchanged(client: TestClient) -> None:
    created = investigate(client, "hxxp://evil[.]example[.]com/x")

    reopened = client.get(f"/api/investigations/{created['id']}").json()

    assert reopened == created
    assert reopened["ioc"]["original"] == "hxxp://evil[.]example[.]com/x"
    assert reopened["ioc"]["refanged"] is True
    assert reopened["enrichment"]["simulated"] is True


def test_history_search_filters_and_sorting(client: TestClient) -> None:
    for ioc in ("8.8.8.8", "example.com", "evil.example.org", SHA256, "10.0.0.1"):
        investigate(client, ioc)

    def values(**params) -> list[str]:
        response = client.get("/api/investigations", params=params)
        assert response.status_code == 200
        return [item["ioc_value"] for item in response.json()["items"]]

    assert values() == ["10.0.0.1", SHA256, "evil.example.org", "example.com", "8.8.8.8"]
    assert values(sort="oldest")[0] == "8.8.8.8"
    assert values(q="EXAMPLE") == ["evil.example.org", "example.com"]
    assert values(ioc_type="sha256") == [SHA256]
    assert values(risk="unknown") == ["10.0.0.1"]  # internal: never sent to providers
    assert values(limit=2, offset=1) == [SHA256, "evil.example.org"]
    assert client.get("/api/investigations", params={"q": "%"}).json()["total"] == 0  # LIKE escaped
    assert client.get("/api/investigations").json()["total"] == 5


@pytest.mark.parametrize(
    "params", [{"risk": "severe"}, {"ioc_type": "email"}, {"sort": "random"}, {"limit": 1000}]
)
def test_history_rejects_bad_filters(client: TestClient, params: dict) -> None:
    assert client.get("/api/investigations", params=params).status_code == 422


def test_reopen_unknown_or_malformed_investigation(client: TestClient) -> None:
    assert client.get(f"/api/investigations/{'0' * 8}-0000-0000-0000-{'0' * 12}").status_code == 404
    assert client.get("/api/investigations/../../etc/passwd").status_code in (404, 422)


def test_repeat_investigations_share_one_ioc(client: TestClient) -> None:
    first = investigate(client, "8.8.8.8")
    second = investigate(client, " 8.8.8.8 ")

    assert first["ioc"]["id"] == second["ioc"]["id"]
    assert [i["id"] for i in context(client, first["ioc"]["id"])["investigations"]] == [
        second["id"],
        first["id"],
    ]


# --- watchlist --------------------------------------------------------------


def add(client: TestClient, **payload) -> dict:
    response = client.post("/api/watchlist", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_watchlist_add_with_tags_and_note(client: TestClient) -> None:
    entry = add(
        client,
        ioc="Evil[.]Example[.]com",
        tags=["Phishing ", "phishing", "  "],
        note="From ticket 42",
    )

    assert entry["ioc"]["value"] == "evil.example.com"
    assert entry["status"] == "monitoring"
    assert entry["tags"] == [{"name": "phishing", "origin": "analyst"}]
    assert [n["body"] for n in entry["notes"]] == ["From ticket 42"]
    assert entry["latest_investigation"] is None


def test_watchlist_rejects_duplicates_and_invalid_iocs(client: TestClient) -> None:
    add(client, ioc="8.8.8.8")

    duplicate = client.post("/api/watchlist", json={"ioc": "8.8.8.8"})
    invalid = client.post("/api/watchlist", json={"ioc": "not an ioc"})
    bad_status = client.post("/api/watchlist", json={"ioc": "1.1.1.1", "status": "maybe"})

    assert duplicate.status_code == 409
    assert invalid.status_code == 422 and invalid.json()["error"]["code"] == "invalid_characters"
    assert bad_status.status_code == 422


@pytest.mark.parametrize(
    "status", ["monitoring", "investigating", "confirmed_malicious", "false_positive", "closed"]
)
def test_watchlist_status_changes(client: TestClient, status: str) -> None:
    entry = add(client, ioc="8.8.8.8")

    updated = client.patch(f"/api/watchlist/{entry['id']}", json={"status": status})

    assert updated.status_code == 200
    assert updated.json()["status"] == status
    listed = client.get("/api/watchlist", params={"status": status}).json()
    assert [e["id"] for e in listed["items"]] == [entry["id"]]


def test_watchlist_filters_and_latest_investigation(client: TestClient) -> None:
    add(client, ioc="8.8.8.8")
    add(client, ioc="example.com", status="investigating")
    investigation = investigate(client, "example.com")

    listed = client.get("/api/watchlist").json()
    searched = client.get("/api/watchlist", params={"q": "example"}).json()

    assert listed["total"] == 2
    assert [e["ioc"]["value"] for e in searched["items"]] == ["example.com"]
    assert searched["items"][0]["latest_investigation"]["id"] == investigation["id"]


def test_watchlist_notes(client: TestClient) -> None:
    entry = add(client, ioc="8.8.8.8")

    with_note = client.post(
        f"/api/watchlist/{entry['id']}/notes", json={"body": "<script>x</script>"}
    ).json()
    note_id = with_note["notes"][0]["id"]
    deleted = client.delete(f"/api/watchlist/{entry['id']}/notes/{note_id}")

    assert with_note["notes"][0]["body"] == "<script>x</script>"  # stored as text, rendered escaped
    assert deleted.status_code == 204
    assert client.get("/api/watchlist").json()["items"][0]["notes"] == []
    assert client.post(f"/api/watchlist/{entry['id']}/notes", json={"body": ""}).status_code == 422


def test_watchlist_removal_keeps_ioc_history_and_tags(client: TestClient) -> None:
    investigation = investigate(client, "8.8.8.8")
    entry = add(client, ioc="8.8.8.8", tags=["keep-me"], note="gone with entry")

    removed = client.delete(f"/api/watchlist/{entry['id']}")
    ctx = context(client, investigation["ioc"]["id"])

    assert removed.status_code == 204
    assert client.get("/api/watchlist").json()["total"] == 0
    assert ctx["watchlist"] is None
    assert [i["id"] for i in ctx["investigations"]] == [investigation["id"]]
    assert {"name": "keep-me", "origin": "analyst"} in ctx["tags"]
    assert client.delete(f"/api/watchlist/{entry['id']}").status_code == 404


# --- tags -------------------------------------------------------------------


def test_ioc_tags_add_and_remove(client: TestClient) -> None:
    ioc_id = add(client, ioc="8.8.8.8")["ioc"]["id"]

    added = client.post(f"/api/iocs/{ioc_id}/tags", json={"name": "  C2   Server "})
    removed = client.delete(f"/api/iocs/{ioc_id}/tags", params={"name": "c2 server"})
    missing = client.delete(f"/api/iocs/{ioc_id}/tags", params={"name": "c2 server"})

    assert added.json()["tags"] == [{"name": "c2 server", "origin": "analyst"}]
    assert removed.status_code == 204
    assert missing.status_code == 404
    assert client.post(f"/api/iocs/{ioc_id}/tags", json={"name": "x" * 65}).status_code == 422


# --- relationships ----------------------------------------------------------


@pytest.fixture
def live_client(tmp_path: Path) -> Iterator[TestClient]:
    """Live mode with mocked providers that return ASN, tags, malware, and actor data."""
    vt_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 60},
                "tags": ["c2"],
                "asn": 64500,
                "as_owner": "Example Hosting",
                "popular_threat_classification": {"popular_threat_name": [{"value": "demoloader"}]},
            }
        }
    }
    otx_payload = {
        "pulse_info": {"count": 2, "pulses": [{"adversary": "EXAMPLE-ACTOR", "tags": ["botnet"]}]}
    }
    providers = [
        make_provider(VirusTotalProvider, json_response(vt_payload))[0],
        make_provider(AbuseIPDBProvider, json_response({}, 503))[0],
        make_provider(OTXProvider, json_response(otx_payload))[0],
    ]
    settings = Settings(
        _env_file=None, database_url=f"sqlite:///{tmp_path / 'live.db'}", demo_mode=False
    )
    with TestClient(create_app(settings, provider_list=providers)) as client:
        yield client


def test_live_provider_data_creates_supported_relationships_only(live_client: TestClient) -> None:
    ip = investigate(live_client, "8.8.8.8")
    file_hash = investigate(live_client, SHA256)
    domain = investigate(live_client, "evil.example.com")

    ip_ctx = context(live_client, ip["ioc"]["id"])
    hash_ctx = context(live_client, file_hash["ioc"]["id"])
    domain_ctx = context(live_client, domain["ioc"]["id"])

    assert relations(ip_ctx) == {
        ("outgoing", "asn", "AS64500", "virustotal"),
        ("outgoing", "threat_actor", "EXAMPLE-ACTOR", "otx"),
    }
    assert ip_ctx["relationships"][0]["label"] == "Example Hosting"
    assert ip_ctx["relationships"][0]["investigation_id"] == ip["id"]
    assert ("outgoing", "malware", "demoloader", "virustotal") in relations(hash_ctx)
    assert not any(r["relation"] == "asn" for r in hash_ctx["relationships"])  # ASN only for IPs
    # No provider data states domain resolutions, so none are stored.
    assert not any(r["relation"] == "resolves_to" for r in domain_ctx["relationships"])
    assert {"name": "c2", "origin": "virustotal"} in ip_ctx["tags"]
    assert {"name": "botnet", "origin": "otx"} in ip_ctx["tags"]


def test_repeated_live_lookups_do_not_duplicate_relationships(live_client: TestClient) -> None:
    first = investigate(live_client, "8.8.8.8")
    investigate(live_client, "8.8.8.8")

    ctx = context(live_client, first["ioc"]["id"])

    assert len(ctx["relationships"]) == 2
    assert len(ctx["tags"]) == 2


def test_simulated_results_never_create_relationships_or_tags(client: TestClient) -> None:
    for ioc in ("8.8.8.8", "1.1.1.1", "9.9.9.9", SHA256, "example.com"):
        result = investigate(client, ioc)
        assert result["enrichment"]["simulated"] is True
        ctx = context(client, result["ioc"]["id"])
        assert ctx["relationships"] == []
        assert ctx["tags"] == []


def test_failed_provider_results_create_nothing(tmp_path: Path) -> None:
    providers = [make_provider(VirusTotalProvider, json_response({}, 500))[0]]
    settings = Settings(
        _env_file=None, database_url=f"sqlite:///{tmp_path / 'x.db'}", demo_mode=False
    )
    with TestClient(create_app(settings, provider_list=providers)) as client:
        result = investigate(client, "8.8.8.8")
        assert context(client, result["ioc"]["id"])["relationships"] == []


def test_analyst_relationships(client: TestClient) -> None:
    domain_id = add(client, ioc="evil.example.com")["ioc"]["id"]
    ip_id = add(client, ioc="8.8.8.8")["ioc"]["id"]
    hash_id = add(client, ioc=SHA256)["ioc"]["id"]

    def post(ioc_id: int, relation: str, target: str):
        return client.post(
            f"/api/iocs/{ioc_id}/relationships", json={"relation": relation, "target": target}
        )

    resolves = post(domain_id, "resolves_to", "8.8.8[.]8")
    asn = post(ip_id, "asn", "15169")
    malware = post(hash_id, "malware", "DemoLoader")
    actor = post(domain_id, "threat_actor", "Example Actor")
    campaign = post(domain_id, "campaign", "Operation Example")

    assert all(r.status_code == 201 for r in (resolves, asn, malware, actor, campaign))
    assert relations(resolves.json()) >= {("outgoing", "resolves_to", "8.8.8.8", "analyst")}
    assert ("outgoing", "asn", "AS15169", "analyst") in relations(asn.json())
    # The resolved IP shows the incoming link, and was not newly created (shared IOC row).
    ip_ctx = context(client, ip_id)
    assert ("incoming", "resolves_to", "8.8.8.8", "analyst") in relations(ip_ctx)
    assert {r["ioc_value"] for r in ip_ctx["relationships"] if r["direction"] == "incoming"} == {
        "evil.example.com"
    }


@pytest.mark.parametrize(
    ("source", "relation", "target"),
    [
        ("8.8.8.8", "resolves_to", "1.1.1.1"),  # only domains resolve
        ("evil.example.com", "resolves_to", "other.example.com"),  # target must be an IP
        ("evil.example.com", "resolves_to", "not valid"),
        ("evil.example.com", "asn", "AS1"),  # only IPs have ASNs
        ("8.8.8.8", "asn", "Google"),  # malformed ASN
        ("8.8.8.8", "malware", "DemoLoader"),  # only hashes map to malware
        ("evil.example.com", "threat_actor", "   "),
    ],
)
def test_invalid_analyst_relationships_rejected(
    client: TestClient, source: str, relation: str, target: str
) -> None:
    ioc_id = add(client, ioc=source)["ioc"]["id"]

    response = client.post(
        f"/api/iocs/{ioc_id}/relationships", json={"relation": relation, "target": target}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_relationship"
    assert context(client, ioc_id)["relationships"] == []


def test_unknown_relation_type_rejected(client: TestClient) -> None:
    ioc_id = add(client, ioc="evil.example.com")["ioc"]["id"]

    response = client.post(
        f"/api/iocs/{ioc_id}/relationships", json={"relation": "hosts", "target": "x"}
    )

    assert response.status_code == 422


def test_only_analyst_relationships_can_be_deleted(live_client: TestClient) -> None:
    result = investigate(live_client, "8.8.8.8")
    ioc_id = result["ioc"]["id"]
    with_campaign = live_client.post(
        f"/api/iocs/{ioc_id}/relationships", json={"relation": "campaign", "target": "Op X"}
    ).json()
    provider_rel = next(r for r in with_campaign["relationships"] if r["origin"] == "virustotal")
    analyst_rel = next(r for r in with_campaign["relationships"] if r["origin"] == "analyst")

    assert (
        live_client.delete(f"/api/iocs/{ioc_id}/relationships/{provider_rel['id']}").status_code
        == 404
    )
    assert (
        live_client.delete(f"/api/iocs/{ioc_id}/relationships/{analyst_rel['id']}").status_code
        == 204
    )
    assert analyst_rel["id"] not in {r["id"] for r in context(live_client, ioc_id)["relationships"]}


def test_relationship_entry_never_contacts_the_network(client: TestClient, monkeypatch) -> None:
    import socket

    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    ioc_id = add(client, ioc="evil.example.com")["ioc"]["id"]

    response = client.post(
        f"/api/iocs/{ioc_id}/relationships", json={"relation": "resolves_to", "target": "8.8.8.8"}
    )

    assert response.status_code == 201


# --- IOC context ------------------------------------------------------------


def test_ioc_context_links_feed_mentions(tmp_path: Path) -> None:
    content = "<p>Infrastructure: hxxps://evil[.]example[.]com/login</p>"
    source, _ = make_source(
        CiscoTalosSource,
        body(
            rss(rss_item(title="Phishing kit", guid="g1", published=ago(hours=1), content=content))
        ),
    )
    settings = Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'f.db'}")
    with TestClient(create_app(settings, feed_sources=[source])) as client:
        client.post("/api/feed/refresh")
        result = investigate(client, "hxxps://evil[.]example[.]com/login")
        ctx = context(client, result["ioc"]["id"])

    assert [e["title"] for e in ctx["threat_events"]] == ["Phishing kit"]
    assert ctx["threat_events"][0]["source_name"] == "Cisco Talos"


def test_ioc_context_unknown(client: TestClient) -> None:
    assert client.get("/api/iocs/999999").status_code == 404
    assert client.get("/api/iocs/not-a-number").status_code == 422
