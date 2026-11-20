import re
from dataclasses import dataclass

URGENCY_PHRASES = (
    "urgent", "immediately", "act now", "within 24 hours", "suspended",
    "final warning", "verify your account", "unusual activity", "limited time",
)
SENSITIVE_PHRASES = (
    "gift card", "gift cards", "wire transfer", "crypto", "cryptocurrency",
    "bitcoin", "payment app", "one time code", "otp", "password",
    "bank details", "remote access",
)
REWARD_PHRASES = (
    "congratulations", "you've won", "you ve won", "claim your prize", "free reward",
)


@dataclass(frozen=True)
class TextSignal:
    code: str
    title: str
    detail: str
    severity: str


def _contains_phrase(tokens: list[str], phrase: str) -> bool:
    normalized = " " + " ".join(tokens) + " "
    words = re.findall(r"[a-z0-9]+", phrase.casefold())
    return bool(words) and f" {' '.join(words)} " in normalized


def analyze_text(value: str) -> list[TextSignal]:
    """Extract interpretable token and phrase signals; this is not a trained NLP model."""
    tokens = re.findall(r"[a-z0-9]+", value.casefold())
    signals: list[TextSignal] = []
    if any(_contains_phrase(tokens, phrase) for phrase in URGENCY_PHRASES):
        signals.append(TextSignal(
            "urgency_language", "Urgency or account pressure",
            "The text uses time pressure or account-warning language often seen in social-engineering attempts.",
            "medium",
        ))
    if any(_contains_phrase(tokens, phrase) for phrase in SENSITIVE_PHRASES):
        signals.append(TextSignal(
            "sensitive_request", "Sensitive information or unusual payment",
            "The text mentions credentials, verification codes, remote access, or hard-to-reverse payment methods.",
            "high",
        ))
    if any(_contains_phrase(tokens, phrase) for phrase in REWARD_PHRASES):
        signals.append(TextSignal(
            "unexpected_reward", "Unexpected reward language",
            "An unsolicited prize or reward claim can be used to prompt unsafe clicks or disclosure.",
            "medium",
        ))
    if value.count("!") >= 4 or re.search(r"\b[A-Z]{6,}\b", value):
        signals.append(TextSignal(
            "emphatic_formatting", "Unusually emphatic formatting",
            "Excessive punctuation or capitalized words may be intended to pressure a quick response.",
            "low",
        ))
    return signals
