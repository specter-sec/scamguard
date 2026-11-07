"""ScamGuard: explainable scam-message detection for Urdu and Roman Urdu."""

from .engine import ScamDetector
from .models import RiskLevel, ScanResult, TriggeredRule

__all__ = ["RiskLevel", "ScamDetector", "ScanResult", "TriggeredRule"]
__version__ = "0.1.0"
