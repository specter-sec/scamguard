"""Flask interface tests."""

import pytest

from scamguard.web import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_home_page_renders_scanner(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert b"ScamGuard" in response.data
    assert b"Message to check" in response.data


def test_api_scans_message_and_returns_explanations(client) -> None:
    response = client.post(
        "/api/scan",
        json={"text": "Send me your OTP or your account will be blocked"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["risk_level"] == "HIGH RISK"
    assert data["score"] >= 60
    assert data["triggered_rules"]
    assert "normalized_text" not in data


def test_api_rejects_missing_or_empty_text(client) -> None:
    missing = client.post("/api/scan", json={})
    empty = client.post("/api/scan", json={"text": "  "})
    assert missing.status_code == 400
    assert empty.status_code == 400


def test_api_rejects_oversized_text(client) -> None:
    response = client.post("/api/scan", json={"text": "x" * 10_001})
    assert response.status_code == 413


def test_form_scans_and_shows_result(client) -> None:
    response = client.post("/", data={"message": "Mubarak, claim your inaam now"})
    assert response.status_code == 200
    assert b"SUSPICIOUS" in response.data
    assert b"Unexpected prize or lottery claim" in response.data


def test_health_check(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
