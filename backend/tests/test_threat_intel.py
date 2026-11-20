import json
from urllib.error import HTTPError

import pytest

from backend.app.threat_intel import lookup_url, prepare_url


class FakeResponse:
    def __init__(self, value: dict):
        self.body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _size: int) -> bytes:
        return self.body


class FakeOpener:
    def __init__(self, value: dict | Exception):
        self.value = value
        self.request_url = ""

    def open(self, request, timeout: int):
        self.request_url = request.full_url
        assert timeout == 6
        if isinstance(self.value, Exception):
            raise self.value
        return FakeResponse(self.value)


def test_prepare_url_adds_scheme_and_removes_fragment():
    normalized, lookup, skip_reason = prepare_url("example.com/login#section")

    assert normalized == "https://example.com/login"
    assert lookup == normalized
    assert skip_reason is None


def test_prepare_url_does_not_send_embedded_credentials():
    normalized, lookup, skip_reason = prepare_url("https://user:secret@example.com/login")

    assert normalized == "https://user:secret@example.com/login"
    assert lookup is None
    assert "not sent to Google" in skip_reason


def test_lookup_reports_missing_api_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)

    result = lookup_url("https://example.com/")

    assert result.status == "not_configured"
    assert result.provider == "google_web_risk"


@pytest.mark.parametrize(
    ("response", "expected_status", "expected_threats"),
    [
        ({}, "clear", []),
        ({"threat": {"threatTypes": ["MALWARE"]}}, "matched", ["MALWARE"]),
    ],
)
def test_lookup_parses_google_results(monkeypatch, response, expected_status, expected_threats):
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")
    opener = FakeOpener(response)
    monkeypatch.setattr("backend.app.threat_intel.build_opener", lambda *_args: opener)

    result = lookup_url("https://example.com/")

    assert result.status == expected_status
    assert result.threat_types == expected_threats
    assert "uri=https%3A%2F%2Fexample.com%2F" in opener.request_url
    assert "key=test-key" in opener.request_url


def test_lookup_surfaces_provider_failures_without_leaking_key(monkeypatch):
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")
    error = HTTPError("https://webrisk.googleapis.com", 429, "rate limited", None, None)
    monkeypatch.setattr("backend.app.threat_intel.build_opener", lambda *_args: FakeOpener(error))

    result = lookup_url("https://example.com/")

    assert result.status == "error"
    assert result.message == "Google Web Risk returned HTTP 429; local heuristic results are shown."
    assert "test-key" not in result.message
