import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import configured_model
from .text_analysis import analyze_text

MAX_INPUT_LENGTH = 10_000
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    detail: str
    severity: str


@dataclass(frozen=True)
class Analysis:
    risk_score: int
    risk_level: str
    explanation: str
    findings: list[Finding]
    recommendations: list[str]


def _level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "elevated"
    return "low"


def _url_signals(value: str) -> list[Finding]:
    found: list[Finding] = []
    candidates = URL_PATTERN.findall(value)
    if not candidates and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value.strip()):
        candidates = [value.strip()]
    for candidate in candidates[:20]:
        try:
            parsed = urlparse(candidate.rstrip(".,;:!?)"))
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            found.append(Finding("malformed_url", "Malformed URL", "The URL could not be parsed reliably, so its destination cannot be assessed.", "medium"))
            continue
        if parsed.scheme == "http":
            found.append(Finding("unencrypted_transport", "Unencrypted connection", "This link uses HTTP, so the connection is not encrypted in transit.", "medium"))
        if parsed.username or parsed.password:
            found.append(Finding("url_credentials", "Credentials embedded in link", "The URL contains user information before the hostname, a pattern that can obscure the true destination.", "high"))
        if host in SHORTENERS:
            found.append(Finding("shortened_url", "Shortened destination", "The final destination is hidden behind a URL-shortening service.", "medium"))
        if host and any(label.startswith("xn--") for label in host.split(".")):
            found.append(Finding("punycode_host", "Internationalized hostname", "The hostname uses punycode; check carefully for lookalike characters.", "medium"))
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                found.append(Finding("ip_host", "IP address used as hostname", "This URL points directly to an IP address instead of a recognizable domain.", "medium"))
        if host.count("-") >= 3:
            found.append(Finding("hyphenated_host", "Unusually hyphenated hostname", "Several hyphens appear in the hostname. This is a weak signal and not proof of fraud.", "low"))
        if len(parsed.netloc) > 55 or len(candidate) > 180:
            found.append(Finding("long_url", "Unusually long link", "Long links can make the actual destination difficult to inspect.", "low"))
        if parsed.scheme not in {"http", "https"}:
            found.append(Finding("unsupported_scheme", "Unexpected URL scheme", "Only HTTP and HTTPS links can be meaningfully evaluated by these URL checks.", "medium"))
    return found


def _text_signals(value: str) -> list[Finding]:
    return [Finding(signal.code, signal.title, signal.detail, signal.severity) for signal in analyze_text(value)]


def _email_signals(value: str) -> list[Finding]:
    found = _text_signals(value) + _url_signals(value)
    headers: dict[str, str] = {}
    for line in value.splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            key, content = line.split(":", 1)
            if re.fullmatch(r"[A-Za-z-]{1,40}", key.strip()):
                headers[key.strip().lower()] = content.strip()
    from_value = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
    from_domains = set(re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", from_value.lower()))
    reply_domains = set(re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", reply_to.lower()))
    return_domains = set(re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", return_path.lower()))
    if from_domains and reply_domains and from_domains.isdisjoint(reply_domains):
        found.append(Finding("reply_domain_mismatch", "Reply-To domain differs", "The Reply-To address uses a different domain from the visible sender.", "high"))
    if from_domains and return_domains and from_domains.isdisjoint(return_domains):
        found.append(Finding("return_path_mismatch", "Return-Path domain differs", "The Return-Path domain differs from the visible sender. Legitimate services can also do this.", "low"))
    if not any(key in headers for key in ("authentication-results", "received-spf", "dkim-signature")):
        found.append(Finding("no_auth_headers", "No authentication headers supplied", "No SPF, DKIM, or authentication-results headers were included, so sender authentication could not be assessed.", "low"))
    return found


def analyze(scan_type: str, content: str) -> Analysis:
    """Score transparent local heuristics only; no external lookups are performed."""
    text = content.strip()
    if not text:
        raise ValueError("input must not be empty")
    if len(text) > MAX_INPUT_LENGTH:
        raise ValueError(f"input must be no more than {MAX_INPUT_LENGTH} characters")

    findings: list[Finding]
    if scan_type == "url":
        findings = _url_signals(text) + _text_signals(text)
    elif scan_type == "email":
        findings = _email_signals(text)
    elif scan_type in {"sms", "payment"}:
        findings = _text_signals(text) + _url_signals(text)
    else:
        raise ValueError("unsupported scan type")

    # A deliberately simple, inspectable heuristic score. It is not a probability.
    weights = {"high": 27, "medium": 16, "low": 7}
    score = min(100, sum(weights[item.severity] for item in findings))
    model = configured_model()
    if model is not None:
        model_score = model.score(text, scan_type)
        if not 0 <= model_score <= 100:
            raise ValueError("configured model returned a score outside 0-100")
        score = round((score + model_score) / 2)

    level = _level(score)
    if findings:
        explanation = f"Found {len(findings)} signal(s) using local rules. These indicators are not proof that content is fraudulent."
    else:
        explanation = "No configured local rules matched. This is not a guarantee that the content is safe."
    recommendations = [
        "Verify the sender or business using contact details you find independently.",
        "Do not enter passwords, payment information, or one-time codes from a message link.",
        "When in doubt, pause and contact the organization through its official website or app.",
    ]
    return Analysis(score, level, explanation, findings, recommendations)
