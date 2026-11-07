"""Normalization helpers for noisy Urdu, Roman Urdu, and Hinglish text."""

import re
import unicodedata

# Normalize common spellings to one searchable form. Keep this list deliberately
# small and auditable; contributions should include examples and regression tests.
_VARIANTS: tuple[tuple[str, str], ...] = (
    (r"\b(?:furan|faoran|foraan)\b", "foran"),
    (r"\b(?:inam|inaam)\b", "inaam"),
    (r"\b(?:jazz\s+cash)\b", "jazzcash"),
    (r"\b(?:easy\s+paisa|easypaisa)\b", "easypaisa"),
    (r"\b(?:e\s+hsas|ehsaas\s+program)\b", "ehsaas"),
    (r"\b(?:bit\s+ly)\b", "bit.ly"),
)

# A starter transliteration/alias map for frequent Urdu-script scam vocabulary.
_URDU_ALIASES: tuple[tuple[str, str], ...] = (
    ("بے نظیر انکم سپورٹ", "bisp"),
    ("ایزی پیسہ", "easypaisa"),
    ("جاز کیش", "jazzcash"),
    ("شناختی کارڈ", "cnic"),
    ("او ٹی پی", "otp"),
    ("ون ٹائم پاس ورڈ", "otp"),
    ("پاس ورڈ", "password"),
    ("اکاؤنٹ", "account"),
    ("بلاک", "block"),
    ("بند", "band"),
    ("بھیجیں", "bhejein"),
    ("بھیجو", "bhejo"),
    ("اپنا", "apna"),
    ("فوراً", "foran"),
    ("فوری", "foran"),
    ("جلدی", "jaldi"),
    ("انعام", "inaam"),
    ("مبارک", "mubarak"),
    ("لاٹری", "lottery"),
    ("جیت", "jeet"),
    ("رقم", "raqam"),
    ("منافع", "munafa"),
    ("سرمایہ کاری", "investment"),
    ("کرپٹو", "crypto"),
    ("ایئرڈراپ", "airdrop"),
    ("لنک", "link"),
    ("کلک", "click"),
    ("تصدیق", "verify"),
)


def normalize_text(text: str) -> str:
    """Canonicalize Unicode, Urdu aliases, and common Roman Urdu variants.

    The function is intentionally conservative: it normalizes known forms but
    does not remove words or infer meaning. It is suitable for rule matching,
    not as a replacement for the original message in user-facing displays.
    """
    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = normalized.replace("\u200b", " ").replace("\ufeff", " ")
    for source, target in _URDU_ALIASES:
        normalized = normalized.replace(source, f" {target} ")
    for pattern, replacement in _VARIANTS:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()
