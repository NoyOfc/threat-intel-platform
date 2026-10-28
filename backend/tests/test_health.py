from fastapi.testclient import TestClient

from app import __version__
from app.services import health as health_service


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "ThreatScope API",
        "version": __version__,
        "database": "ok",
        "demo_mode": True,
    }


def test_health_degraded_when_database_unreachable(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(health_service, "database_is_reachable", lambda db: False)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["database"] == "error"
