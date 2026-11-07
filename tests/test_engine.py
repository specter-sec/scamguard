"""Rule-engine unit tests."""

import csv
from pathlib import Path

import pytest

from scamguard import RiskLevel, ScamDetector
from scamguard.normalization import normalize_text


@pytest.fixture
def detector() -> ScamDetector:
    return ScamDetector()


def test_safe_message_has_no_triggers(detector: ScamDetector) -> None:
    result = detector.scan("Meeting moved to 3 pm. See you at the office.")
    assert result.risk_level is RiskLevel.SAFE
    assert result.score == 0
    assert result.triggered_rules == []


def test_ordinary_congratulations_are_not_prize_bait(detector: ScamDetector) -> None:
    result = detector.scan("Mubarak on your graduation! You worked hard for this.")
    assert result.risk_level is RiskLevel.SAFE
    assert "prize_or_lottery_bait" not in {rule.rule_id for rule in result.triggered_rules}


def test_legitimate_payment_receipt_is_not_impersonation(detector: ScamDetector) -> None:
    result = detector.scan("JazzCash receipt: your payment of Rs 850 was successful.")
    assert result.risk_level is RiskLevel.SAFE
    assert "financial_brand_impersonation" not in {
        rule.rule_id for rule in result.triggered_rules
    }


def test_roman_urdu_prize_message_is_flagged(detector: ScamDetector) -> None:
    result = detector.scan("Mubarak! Aap ka inam nikla hai, foran claim karein.")
    rule_ids = {rule.rule_id for rule in result.triggered_rules}
    assert result.risk_level is RiskLevel.SUSPICIOUS
    assert "prize_or_lottery_bait" in rule_ids
    assert "urgent_deadline" in rule_ids


def test_credential_and_account_threat_is_high_risk(detector: ScamDetector) -> None:
    result = detector.scan("Apna OTP bhejo warna account block ho jayega.")
    rule_ids = {rule.rule_id for rule in result.triggered_rules}
    assert result.risk_level is RiskLevel.HIGH_RISK
    assert "credential_request" in rule_ids
    assert "threat_account_action" in rule_ids


def test_urdu_script_aliases_are_detected(detector: ScamDetector) -> None:
    result = detector.scan("مبارک! آپ کا انعام، اپنا او ٹی پی بھیجیں")
    rule_ids = {rule.rule_id for rule in result.triggered_rules}
    assert "prize_or_lottery_bait" in rule_ids
    assert "credential_request" in rule_ids


def test_normalization_handles_spelling_variants() -> None:
    assert normalize_text("Furan INAM") == normalize_text("foran inaam")


def test_crypto_airdrop_and_shortened_link_are_flagged(detector: ScamDetector) -> None:
    result = detector.scan("Claim free crypto airdrop: https://bit.ly/claim-token")
    rule_ids = {rule.rule_id for rule in result.triggered_rules}
    assert "crypto_airdrop_bait" in rule_ids
    assert "shortened_link" in rule_ids
    assert result.risk_level is RiskLevel.HIGH_RISK


def test_payment_brand_impersonation_is_flagged(detector: ScamDetector) -> None:
    result = detector.scan("Easypaisa payment blocked. Verify your CNIC through this link.")
    rule_ids = {rule.rule_id for rule in result.triggered_rules}
    assert "financial_brand_impersonation" in rule_ids
    assert "account_verification_phishing" in rule_ids
    assert result.risk_level is RiskLevel.HIGH_RISK


def test_scores_are_bounded_and_thresholds_are_configurable() -> None:
    with pytest.raises(ValueError):
        ScamDetector(suspicious_threshold=60, high_risk_threshold=50)
    result = ScamDetector(suspicious_threshold=10, high_risk_threshold=20).scan("urgent")
    assert result.risk_level is RiskLevel.SUSPICIOUS
    assert 0 <= result.score <= 100


def test_sample_dataset_has_valid_labels_and_nonempty_text() -> None:
    dataset = Path(__file__).resolve().parents[1] / "samples.csv"
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) >= 20
    assert all(row["text"].strip() for row in rows)
    assert {row["label"] for row in rows} <= {"SAFE", "SUSPICIOUS", "HIGH RISK"}
