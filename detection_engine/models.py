from typing import Protocol


class RiskModel(Protocol):
    """Optional model interface. No model is bundled or implied by this app."""

    def score(self, content: str, scan_type: str) -> float: ...


def configured_model() -> RiskModel | None:
    """Return a model only after an operator provides a real implementation."""
    return None
