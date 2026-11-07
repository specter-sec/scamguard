"""Typed result objects used by the rule engine and interfaces."""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Coarse user-facing classification for a detected message."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"


@dataclass(frozen=True)
class TriggeredRule:
    """A single rule matched in a message."""

    rule_id: str
    category: str
    title: str
    explanation: str
    weight: int
    matched_text: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    """Full scan output, including score and transparent explanations."""

    risk_level: RiskLevel
    score: int
    explanations: list[str]
    triggered_rules: list[TriggeredRule]
    normalized_text: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "risk_level": self.risk_level.value,
            "score": self.score,
            "explanations": list(self.explanations),
            "triggered_rules": [rule.to_dict() for rule in self.triggered_rules],
        }
