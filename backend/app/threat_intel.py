import json
import logging
import os
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

logger = logging.getLogger("scamshield.threat_intel")
WEB_RISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"
THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")


@dataclass(frozen=True)
class ThreatLookup:
    provider: str | None
    status: str
    threat_types: list[str]
    message: str


def prepare_url(value: str) -> tuple[str, str | None, str | None]:
    candidate = value.strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", candidate):
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
    except ValueError as error:
        raise ValueError("Enter a valid website URL.") from error
    if parsed.scheme.lower() not in {"http", "https"}:
        return value, None, "Only HTTP and HTTPS links can be checked against Google Web Risk."
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid website URL.") from error
    if not hostname or any(char.isspace() for char in hostname):
        raise ValueError("Enter a valid website URL.")

    normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
    if parsed.username or parsed.password:
        return normalized, None, "This link contains embedded credentials, so it was not sent to Google."
    if len(normalized) > 2048:
        return normalized, None, "This link is too long for a Google Web Risk lookup."
    return normalized, normalized, None


def lookup_url(url: str) -> ThreatLookup:
    api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
    if not api_key:
        return ThreatLookup(
            provider="google_web_risk",
            status="not_configured",
            threat_types=[],
            message="Google Web Risk is not configured; only local heuristic checks were used.",
        )

    query = [("threatTypes", threat_type) for threat_type in THREAT_TYPES]
    query.extend((("uri", url), ("key", api_key)))
    request = Request(
        f"{WEB_RISK_ENDPOINT}?{urlencode(query)}",
        headers={"Accept": "application/json"},
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=6) as response:
            body = response.read(64 * 1024 + 1)
    except HTTPError as error:
        logger.warning("Google Web Risk lookup failed status=%s", error.code)
        return ThreatLookup(
            provider="google_web_risk",
            status="error",
            threat_types=[],
            message=f"Google Web Risk returned HTTP {error.code}; local heuristic results are shown.",
        )
    except (TimeoutError, URLError):
        logger.warning("Google Web Risk lookup could not be reached")
        return ThreatLookup(
            provider="google_web_risk",
            status="error",
            threat_types=[],
            message="Google Web Risk could not be reached; local heuristic results are shown.",
        )

    if len(body) > 64 * 1024:
        return _invalid_response()
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return _invalid_response()
    if not isinstance(data, dict):
        return _invalid_response()

    threat = data.get("threat", {})
    if not isinstance(threat, dict):
        return _invalid_response()
    threat_types = threat.get("threatTypes", [])
    if not isinstance(threat_types, list) or not all(isinstance(item, str) for item in threat_types):
        return _invalid_response()

    if threat_types:
        return ThreatLookup(
            provider="google_web_risk",
            status="matched",
            threat_types=threat_types,
            message="Google Web Risk matched this link to one or more threat lists.",
        )
    return ThreatLookup(
        provider="google_web_risk",
        status="clear",
        threat_types=[],
        message="No match was found in the checked Google Web Risk lists. This is not a guarantee of safety.",
    )


def _invalid_response() -> ThreatLookup:
    logger.warning("Google Web Risk returned an invalid response")
    return ThreatLookup(
        provider="google_web_risk",
        status="error",
        threat_types=[],
        message="Google Web Risk returned an unreadable response; local heuristic results are shown.",
    )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None
