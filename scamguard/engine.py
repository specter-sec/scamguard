"""Explainable weighted rule engine for scam-message screening."""

import logging
from collections import defaultdict

from .models import RiskLevel, ScanResult, TriggeredRule
from .normalization import normalize_text
from .rules import CATEGORY_CAPS, COMPILED_RULES

LOGGER = logging.getLogger(__name__)


class ScamDetector:
    """Apply a transparent rule catalog and produce a bounded 0-100 score."""

    def __init__(self, suspicious_threshold: int = 25, high_risk_threshold: int = 60):
        if not 0 <= suspicious_threshold < high_risk_threshold <= 100:
            raise ValueError("Thresholds must satisfy 0 <= suspicious < high_risk <= 100")
        self.suspicious_threshold = suspicious_threshold
        self.high_risk_threshold = high_risk_threshold

    def scan(self, text: str) -> ScanResult:
        """Scan one message and return its score, risk level, and explanations."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        normalized = normalize_text(text)
        triggered: list[TriggeredRule] = []
        category_points: dict[str, int] = defaultdict(int)

        for rule, patterns in COMPILED_RULES:
            match = None
            for pattern in patterns:
                match = pattern.search(normalized)
                if match:
                    break
            if match is None:
                continue
            matched_text = match.group(0).strip()[:100]
            triggered.append(
                TriggeredRule(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    title=rule.title,
                    explanation=rule.explanation,
                    weight=rule.weight,
                    matched_text=matched_text,
                )
            )
            category_points[rule.category] += rule.weight

        score = min(
            100,
            sum(
                min(points, CATEGORY_CAPS.get(category, 100))
                for category, points in category_points.items()
            ),
        )
        if score >= self.high_risk_threshold:
            risk_level = RiskLevel.HIGH_RISK
        elif score >= self.suspicious_threshold:
            risk_level = RiskLevel.SUSPICIOUS
        else:
            risk_level = RiskLevel.SAFE

        explanations = [rule.explanation for rule in triggered]
        if not explanations:
            explanations = [
                "No configured scam indicators were detected; stay cautious with "
                "unexpected messages."
            ]

        LOGGER.info(
            "Scanned message: risk=%s score=%d matched_rules=%d",
            risk_level.value,
            score,
            len(triggered),
        )
        return ScanResult(
            risk_level=risk_level,
            score=score,
            explanations=explanations,
            triggered_rules=triggered,
            normalized_text=normalized,
        )
