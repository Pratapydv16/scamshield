import os
from uuid import uuid4

os.environ.setdefault("JWT_SECRET", "test-only-secret-that-is-never-used-outside-tests")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test-scamshield.db")

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.threat_intel import ThreatLookup


def test_scan_endpoint_returns_heuristic_result():
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"scan_type": "sms", "input": "urgent verify your account and share your password via wire transfer"})
    assert response.status_code == 200
    body = response.json()
    assert body["detection_mode"] == "heuristic"
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_level"] == "elevated"
    assert body["findings"]
    assert {"code", "title", "detail", "severity"} <= body["findings"][0].keys()
    assert "scanned_at" in body


def test_scan_endpoint_rejects_empty_content():
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"scan_type": "sms", "input": " \n "})
    assert response.status_code == 422


def test_url_scan_reports_when_live_lookup_is_not_configured(monkeypatch):
    monkeypatch.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"scan_type": "url", "input": "example.com/login", "share_with_google": True})

    assert response.status_code == 200
    body = response.json()
    assert body["threat_intelligence"]["status"] == "not_configured"
    assert body["detection_mode"] == "heuristic"


def test_url_scan_does_not_share_without_explicit_consent(monkeypatch):
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")

    def unexpected_lookup(_url):
        raise AssertionError("URL lookup should require explicit consent")

    monkeypatch.setattr("backend.app.main.lookup_url", unexpected_lookup)
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"scan_type": "url", "input": "example.com"})

    assert response.status_code == 200
    assert response.json()["threat_intelligence"]["status"] == "skipped"


def test_url_scan_combines_google_match_with_local_findings(monkeypatch):
    monkeypatch.setattr(
        "backend.app.main.lookup_url",
        lambda _url: ThreatLookup("google_web_risk", "matched", ["SOCIAL_ENGINEERING"], "Match found."),
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            json={"scan_type": "url", "input": "https://example.com/login", "share_with_google": True},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["detection_mode"] == "hybrid"
    assert body["risk_level"] == "high"
    assert body["risk_score"] >= 90
    assert "google_web_risk_match" in {finding["code"] for finding in body["findings"]}
    assert body["threat_intelligence"]["threat_types"] == ["SOCIAL_ENGINEERING"]


def test_user_history_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/api/v1/scans")
    assert response.status_code == 401


def test_registration_login_and_api_key_lifecycle():
    email = f"test-{uuid4().hex}@example.com"
    password = "a-long-test-password-2026"
    with TestClient(app) as client:
        registration = client.post("/api/v1/auth/register", json={"email": email, "password": password})
        assert registration.status_code == 201
        assert "password_hash" not in registration.json()

        login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

        created = client.post("/api/v1/api-keys", headers=headers, json={"name": "test integration"})
        assert created.status_code == 201
        api_key = created.json()["key"]
        assert api_key.startswith("ss_live_")
        key_headers = {"Authorization": f"Bearer {api_key}"}
        assert client.get("/api/v1/api-keys", headers=key_headers).status_code == 403
        scan = client.post("/api/v1/scans", headers=key_headers, json={"scan_type": "url", "input": "http://192.0.2.1/login"})
        assert scan.status_code == 200
        assert client.delete(f"/api/v1/api-keys/{created.json()['id']}", headers=headers).status_code == 204
        revoked = client.post("/api/v1/scans", headers=key_headers, json={"scan_type": "url", "input": "https://example.test"})
        assert revoked.status_code == 401
