"""Auditable rule definitions for common message-based scam signals."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    """A weighted regex rule. Each rule contributes at most once per scan."""

    rule_id: str
    category: str
    title: str
    explanation: str
    weight: int
    patterns: tuple[str, ...]


RULES: tuple[Rule, ...] = (
    Rule(
        "urgent_deadline",
        "urgency",
        "Urgent deadline",
        "The message pressures the recipient to act immediately or before a deadline.",
        14,
        (
            r"\b(?:foran|abhi|jaldi|urgent|immediately|aaj\s+hi|last\s+chance|"
            r"aakhri\s+mauqa|within\s+\d+\s+hours?)\b",
        ),
    ),
    Rule(
        "threat_account_action",
        "account-block threat",
        "Threat of account action",
        "The message threatens blocking, suspension, or loss of account access.",
        26,
        (
            r"\b(?:account|sim|wallet|card)\b.{0,35}\b(?:block(?:ed)?|band|"
            r"suspend(?:ed)?|freeze|close(?:d)?)\b",
            r"\b(?:block(?:ed)?|band|suspend(?:ed)?|freeze)\b.{0,35}"
            r"\b(?:account|sim|wallet|card)\b",
            r"\baccount\s+band\s+ho\s+jayega\b",
        ),
    ),
    Rule(
        "prize_or_lottery_bait",
        "prize / lottery",
        "Unexpected prize or lottery claim",
        "The message claims the recipient won a prize, lottery, gift, or reward.",
        26,
        (
            r"\b(?:inaam|lottery|prize|winner|jeet\s+gaye|gift|reward|"
            r"cash\s+prize|lucky\s+draw|free\s+reward)\b",
        ),
    ),
    Rule(
        "prize_fee_request",
        "prize / lottery",
        "Fee to release a prize",
        "The message asks for a fee, tax, or payment to release a supposed prize.",
        24,
        (
            r"\b(?:prize|inaam|lottery|reward)\b.{0,55}\b(?:fee|tax|charges?|"
            r"payment|send\s+money|processing\s+fee)\b",
            r"\b(?:fee|tax|charges?|payment)\b.{0,55}\b(?:prize|inaam|lottery|reward)\b",
        ),
    ),
    Rule(
        "credential_request",
        "OTP / PIN / CNIC phishing",
        "Request for sensitive credentials",
        "The message asks for an OTP, PIN, CNIC, password, or verification code.",
        34,
        (
            r"\b(?:send|share|bhejo|bhejein|provide|reply\s+with|enter|confirm|"
            r"verify)\b.{0,45}\b(?:otp|pin|cnic|password|verification\s+code|"
            r"security\s+code|card\s+details)\b",
            r"\b(?:otp|pin|cnic|password|verification\s+code|security\s+code)\b"
            r".{0,45}\b(?:send|share|bhejo|bhejein|provide|reply|enter|confirm)\b",
            r"\b(?:apna\s+)?(?:otp|pin|cnic|password)\s+(?:bhejo|bhejein)\b",
        ),
    ),
    Rule(
        "account_verification_phishing",
        "OTP / PIN / CNIC phishing",
        "Credential verification prompt",
        "The message uses account verification language around sensitive details.",
        24,
        (
            r"\b(?:verify|confirm|update)\b.{0,35}\b(?:account|cnic|otp|pin|"
            r"identity|details)\b.{0,35}\b(?:link|website|form)\b",
            r"\b(?:account|cnic|otp|pin)\b.{0,35}\b(?:verify|confirm|update)\b",
        ),
    ),
    Rule(
        "crypto_guaranteed_return",
        "crypto investment fraud",
        "Guaranteed crypto returns",
        "The message promises guaranteed or unusually high returns on crypto investment.",
        28,
        (
            r"\b(?:guaranteed|risk\s*[- ]?free|double\s+your|daily\s+profit|"
            r"100\s*%\s*profit|high\s+return)\b.{0,55}\b(?:crypto|bitcoin|btc|"
            r"ethereum|investment|invest|usdt|coin)\b",
            r"\b(?:crypto|bitcoin|btc|ethereum|usdt)\b.{0,55}\b(?:guaranteed|"
            r"double\s+your|daily\s+profit|100\s*%\s*profit|risk\s*[- ]?free)\b",
        ),
    ),
    Rule(
        "crypto_airdrop_bait",
        "crypto investment fraud",
        "Unsolicited crypto airdrop or wallet claim",
        "The message offers a crypto airdrop or asks the recipient to connect a wallet.",
        33,
        (
            r"\b(?:free\s+)?(?:crypto\s+)?airdrop\b",
            r"\b(?:connect|link|sync)\b.{0,30}\b(?:wallet|metamask)\b",
            r"\b(?:claim|unlock)\b.{0,35}\b(?:token|airdrop|wallet)\b",
        ),
    ),
    Rule(
        "financial_brand_impersonation",
        "financial-service impersonation",
        "Payment or benefits service impersonation",
        "A named Pakistani payment or benefits service appears with a claim or request.",
        26,
        (
            r"\b(?:easypaisa|jazzcash)\b.{0,65}\b(?:verify|claim|update|"
            r"blocked|block|fee|inaam|otp|pin|cnic|click|link|share|send|"
            r"reward|prize)\b",
            r"\b(?:bisp|ehsaas)\b.{0,65}\b(?:grant|payment|benefit|cash|"
            r"verify|claim|update|blocked|fee|inaam|otp|pin|cnic|click|link)\b",
            r"\b(?:grant|payment|benefit|cash|verify|claim|update|blocked|fee|"
            r"otp|pin|cnic)\b.{0,65}\b(?:bisp|ehsaas)\b",
            r"\b(?:verify|claim|update|blocked|block|fee|inaam|otp|pin|cnic|"
            r"click|link|share|send|reward|prize)\b.{0,65}\b(?:easypaisa|jazzcash)\b",
        ),
    ),
    Rule(
        "payment_release_fee",
        "payment / advance-fee fraud",
        "Advance payment requested to release funds",
        "The message asks for a fee or deposit before a payment, grant, or prize is released.",
        26,
        (
            r"\b(?:pay|send|deposit|transfer)\b.{0,45}\b(?:fee|tax|charges?|"
            r"deposit|advance)\b.{0,45}\b(?:release|receive|withdraw|grant|payment|"
            r"prize|funds)\b",
            r"\b(?:release|receive|withdraw)\b.{0,50}\b(?:fee|tax|charges?|"
            r"deposit|advance)\b",
        ),
    ),
    Rule(
        "shortened_link",
        "suspicious links",
        "Shortened link",
        "A URL shortener hides the destination address; inspect it without opening it.",
        27,
        (
            r"\b(?:https?://)?(?:www\.)?(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|"
            r"ow\.ly|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)/?\S*",
        ),
    ),
    Rule(
        "risky_domain_suffix",
        "suspicious links",
        "Unusual or free-hosting domain suffix",
        "The message includes a link using a domain suffix often abused for throwaway sites.",
        22,
        (r"\b(?:https?://)?[a-z0-9.-]+\.(?:tk|ml|ga|cf|gq|top|xyz|buzz)(?:/\S*)?",),
    ),
    Rule(
        "link_action_pressure",
        "suspicious links",
        "Pressure to use a link",
        "The message urges the recipient to click, open, or verify through a link.",
        13,
        (
            r"\b(?:click|open|visit|tap)\b.{0,35}\b(?:link|url|here|below)\b",
            r"\b(?:link|url)\b.{0,35}\b(?:click|open|verify|claim|confirm)\b",
        ),
    ),
)

COMPILED_RULES: tuple[tuple[Rule, tuple[re.Pattern[str], ...]], ...] = tuple(
    (rule, tuple(re.compile(pattern, re.IGNORECASE) for pattern in rule.patterns))
    for rule in RULES
)

CATEGORY_CAPS: dict[str, int] = {
    "urgency": 24,
    "account-block threat": 30,
    "prize / lottery": 35,
    "OTP / PIN / CNIC phishing": 42,
    "crypto investment fraud": 40,
    "financial-service impersonation": 35,
    "payment / advance-fee fraud": 30,
    "suspicious links": 40,
}
