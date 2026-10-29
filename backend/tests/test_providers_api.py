from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.otx import OTXProvider
from app.providers.virustotal import VirusTotalProvider
from tests.provider_helpers import FAKE_KEY, json_response, make_provider


def live_settings(tmp_path: Path, **overrides) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        demo_mode=False,
        **overrides,
    )


@pytest.fixture
def keyed_client(tmp_path: Path) -> Iterator[TestClient]:
    settings = live_settings(
        tmp_path,
        virustotal_api_key=FAKE_KEY,
        abuseipdb_api_key=FAKE_KEY,
        otx_api_key=FAKE_KEY,
    )
    with TestClient(create_app(settings)) as client:
        yield client


def test_status_in_demo_mode_without_keys(client: TestClient) -> None:
    response = client.get("/api/providers/status")

    assert response.status_code == 200
    body = response.json()
    assert body["demo_mode"] is True
    assert [p["name"] for p in body["providers"]] == ["virustotal", "abuseipdb", "otx"]
    for provider in body["providers"]:
        assert provider["status"] == "not_configured"
        assert provider["mode"] == "simulated"
        assert provider["api_key_env"] in provider["detail"]
    abuse = body["providers"][1]
    assert abuse["supported_types"] == ["ipv4", "ipv6"]
    assert abuse["api_host"] == "api.abuseipdb.com"


def test_status_with_keys_never_reveals_them(keyed_client: TestClient) -> None:
    response = keyed_client.get("/api/providers/status")

    body = response.json()
    assert {p["status"] for p in body["providers"]} == {"configured"}
    assert {p["mode"] for p in body["providers"]} == {"live"}
    assert FAKE_KEY not in response.text
    assert FAKE_KEY[:6] not in response.text
    assert FAKE_KEY[-4:] not in response.text


def test_failed_provider_shows_unavailable(tmp_path: Path) -> None:
    vt, _ = make_provider(VirusTotalProvider, json_response({}, 401))
    abuse, _ = make_provider(
        AbuseIPDBProvider, json_response({"data": {"abuseConfidenceScore": 0}})
    )
    otx, _ = make_provider(OTXProvider, json_response({}, 503))
    app = create_app(live_settings(tmp_path), provider_list=[vt, abuse, otx])

    with TestClient(app) as client:
        investigation = client.post("/api/investigate", json={"ioc": "8.8.8.8"}).json()
        status = client.get("/api/providers/status").json()

    assert investigation["enrichment"]["status"] == "partial"
    assert investigation["enrichment"]["simulated"] is False
    assert [r["status"] for r in investigation["enrichment"]["results"]] == [
        "auth_error",
        "ok",
        "unavailable",
    ]
    assert [p["status"] for p in status["providers"]] == [
        "unavailable",
        "configured",
        "unavailable",
    ]
    assert "authentication" in status["providers"][0]["detail"].lower()
    assert status["providers"][0]["last_result"] == "auth_error"


def test_live_investigation_scores_real_responses(tmp_path: Path) -> None:
    vt_payload = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 10, "harmless": 60}}}
    }
    abuse_payload = {"data": {"abuseConfidenceScore": 80, "totalReports": 30}}
    vt, _ = make_provider(VirusTotalProvider, json_response(vt_payload))
    abuse, _ = make_provider(AbuseIPDBProvider, json_response(abuse_payload))
    otx, _ = make_provider(OTXProvider, json_response({"pulse_info": {"count": 0, "pulses": []}}))
    app = create_app(live_settings(tmp_path), provider_list=[vt, abuse, otx])

    with TestClient(app) as client:
        body = client.post("/api/investigate", json={"ioc": "8.8.8.8"}).json()

    assert body["enrichment"]["status"] == "completed"
    assert body["risk"]["simulated"] is False
    factors = {f["signal"]: f["points"] for f in body["risk"]["factors"]}
    assert factors == {
        "Malicious vendor detections": 35,
        "Abuse confidence": 24,
        "Abuse reports": 7,
        "Provider agreement": 10,
    }
    assert body["risk"]["score"] == 76
    assert body["risk"]["level"] == "high"


def test_live_mode_without_keys_reports_not_configured(tmp_path: Path) -> None:
    with TestClient(create_app(live_settings(tmp_path))) as client:
        body = client.post("/api/investigate", json={"ioc": "8.8.8.8"}).json()

    assert {r["status"] for r in body["enrichment"]["results"]} == {"not_configured"}
    assert body["enrichment"]["status"] == "no_providers"
    assert body["enrichment"]["simulated"] is False
    assert body["risk"]["level"] == "unknown"


def test_unsupported_methods_on_status(client: TestClient) -> None:
    assert client.post("/api/providers/status", json={}).status_code == 405


def test_http_client_never_follows_redirects_or_uses_env_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.providers.http import create_http_client

    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example:8080")
    client = create_http_client(user_agent="test", timeout=1)

    assert client.follow_redirects is False
    assert client.trust_env is False
    assert isinstance(client, httpx.AsyncClient)
