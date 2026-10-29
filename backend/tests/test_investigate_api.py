from uuid import UUID

from fastapi.testclient import TestClient

from app.api.middleware import MAX_BODY_BYTES
from app.schemas.ioc import MAX_BULK_IOCS
from app.services.ioc import MAX_IOC_LENGTH

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def assert_error(response, status_code: int, code: str) -> dict:
    assert response.status_code == status_code
    body = response.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str)
    return body["error"]


# --- POST /api/investigate --------------------------------------------------


def test_investigate_valid_ioc(client: TestClient) -> None:
    response = client.post("/api/investigate", json={"ioc": " hxxps://Evil[.]example.com/a "})

    assert response.status_code == 201
    body = response.json()
    UUID(body["id"])
    assert body["status"] == "completed"
    assert body["created_at"]
    assert body["ioc"] == {
        "type": "url",
        "value": "https://evil.example.com/a",
        "original": "hxxps://Evil[.]example.com/a",
        "refanged": True,
        "network_scope": "public",
        "is_internal": False,
    }
    # The default test settings run in DEMO_MODE: every result must be labeled simulated.
    assert body["enrichment"]["status"] == "completed"
    assert body["enrichment"]["simulated"] is True
    assert [r["provider"] for r in body["enrichment"]["results"]] == [
        "virustotal",
        "abuseipdb",
        "otx",
    ]
    assert body["enrichment"]["results"][1]["status"] == "not_supported"  # AbuseIPDB: IPs only
    assert all(r["simulated"] for r in body["enrichment"]["results"] if r["status"] == "ok")
    assert body["risk"]["simulated"] is True
    assert 0 <= body["risk"]["score"] <= 100


def test_investigate_private_ip_is_valid_and_flagged(client: TestClient) -> None:
    response = client.post("/api/investigate", json={"ioc": "10.0.0.5"})

    assert response.status_code == 201
    ioc = response.json()["ioc"]
    assert ioc["type"] == "ipv4"
    assert ioc["network_scope"] == "private"
    assert ioc["is_internal"] is True
    # Internal IOCs are never sent to providers, so there is no intelligence to score.
    assert {r["status"] for r in response.json()["enrichment"]["results"]} == {"skipped"}
    assert response.json()["risk"]["level"] == "unknown"
    assert response.json()["risk"]["score"] is None


def test_investigate_hash(client: TestClient) -> None:
    response = client.post("/api/investigate", json={"ioc": SHA256.upper()})

    assert response.status_code == 201
    assert response.json()["ioc"]["type"] == "sha256"
    assert response.json()["ioc"]["value"] == SHA256


def test_investigate_invalid_ioc_returns_error_envelope(client: TestClient) -> None:
    response = client.post("/api/investigate", json={"ioc": "g" + SHA256[1:]})

    error = assert_error(response, 422, "invalid_hash")
    assert error["details"] == {"suspected_type": "sha256"}


def test_investigate_blank_ioc(client: TestClient) -> None:
    assert_error(client.post("/api/investigate", json={"ioc": "   "}), 422, "empty")


def test_investigate_oversized_ioc(client: TestClient) -> None:
    response = client.post("/api/investigate", json={"ioc": "a" * (MAX_IOC_LENGTH + 1)})

    assert_error(response, 422, "too_long")


def test_investigate_missing_field_does_not_echo_input(client: TestClient) -> None:
    response = client.post("/api/investigate", json={"value": "secret-looking-input"})

    error = assert_error(response, 422, "validation_error")
    assert "secret-looking-input" not in response.text
    assert {"loc", "message"} <= set(error["details"]["fields"][0])


def test_investigate_wrong_type(client: TestClient) -> None:
    assert_error(client.post("/api/investigate", json={"ioc": 123}), 422, "validation_error")


def test_investigate_malformed_json(client: TestClient) -> None:
    response = client.post(
        "/api/investigate", content=b"{not json", headers={"content-type": "application/json"}
    )

    assert_error(response, 422, "validation_error")


# --- POST /api/investigate/bulk ---------------------------------------------


def test_bulk_mixed_iocs(client: TestClient) -> None:
    iocs = ["8.8.8.8", "::1", "example.com", "http://evil.com", SHA256, "not an ioc", ""]

    response = client.post("/api/investigate/bulk", json={"iocs": iocs})

    assert response.status_code == 200
    body = response.json()
    assert [item["index"] for item in body["items"]] == list(range(len(iocs)))
    assert [item["valid"] for item in body["items"]] == [True] * 5 + [False] * 2
    assert [item["ioc"]["type"] for item in body["items"][:5]] == [
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "sha256",
    ]
    assert body["items"][5]["error"]["code"] == "invalid_characters"
    assert body["items"][6]["error"]["code"] == "empty"
    assert body["summary"] == {
        "total": 7,
        "valid": 5,
        "invalid": 2,
        "by_type": {"ipv4": 1, "ipv6": 1, "domain": 1, "url": 1, "sha256": 1},
    }


def test_bulk_oversized_item_reported_per_item(client: TestClient) -> None:
    oversized = "a" * (MAX_IOC_LENGTH + 100)

    response = client.post("/api/investigate/bulk", json={"iocs": ["8.8.8.8", oversized]})

    assert response.status_code == 200
    item = response.json()["items"][1]
    assert item["valid"] is False
    assert item["error"]["code"] == "too_long"
    assert len(item["input"]) == MAX_IOC_LENGTH


def test_bulk_at_limit_accepted(client: TestClient) -> None:
    response = client.post("/api/investigate/bulk", json={"iocs": ["8.8.8.8"] * MAX_BULK_IOCS})

    assert response.status_code == 200
    assert response.json()["summary"]["total"] == MAX_BULK_IOCS


def test_bulk_over_limit_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/investigate/bulk", json={"iocs": ["8.8.8.8"] * (MAX_BULK_IOCS + 1)}
    )

    assert_error(response, 422, "validation_error")


def test_bulk_empty_list_rejected(client: TestClient) -> None:
    assert_error(client.post("/api/investigate/bulk", json={"iocs": []}), 422, "validation_error")


# --- Transport limits and generic errors ------------------------------------


def test_oversized_body_rejected_before_parsing(client: TestClient) -> None:
    response = client.post(
        "/api/investigate/bulk",
        content=b"x" * (MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )

    assert_error(response, 413, "payload_too_large")


def test_body_without_content_length_rejected(client: TestClient) -> None:
    def chunks():
        yield b'{"ioc": "8.8.8.8"}'

    response = client.post(
        "/api/investigate", content=chunks(), headers={"content-type": "application/json"}
    )

    assert_error(response, 411, "length_required")


def test_unknown_route_uses_error_envelope(client: TestClient) -> None:
    assert_error(client.get("/api/does-not-exist"), 404, "not_found")


def test_wrong_method_uses_error_envelope(client: TestClient) -> None:
    assert_error(client.get("/api/investigate"), 405, "method_not_allowed")
