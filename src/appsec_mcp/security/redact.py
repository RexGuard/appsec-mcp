"""Secret detection patterns and masking. Raw secret values never leave the process."""

import re
from dataclasses import dataclass

_MIN_SECRET_LEN = 8
_VISIBLE_SUFFIX = 4
_MAX_PREFIX = 8
_MASK = "****"


@dataclass(frozen=True)
class SecretPattern:
    """A named regex whose group `secret` captures the sensitive value."""

    rule_id: str
    title: str
    regex: re.Pattern[str]


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "secret.stripe-key",
        "Stripe secret key",
        re.compile(r"(?P<secret>\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,})"),
    ),
    SecretPattern(
        "secret.aws-access-key",
        "AWS access key",
        re.compile(r"(?P<secret>\b(?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    ),
    SecretPattern(
        "secret.github-token",
        "GitHub token",
        re.compile(r"(?P<secret>\bgh[pousr]_[0-9A-Za-z]{30,})"),
    ),
    SecretPattern(
        "secret.google-api-key",
        "Google API key",
        re.compile(r"(?P<secret>\bAIza[0-9A-Za-z_\-]{30,})"),
    ),
    SecretPattern(
        "secret.slack-token",
        "Slack token",
        re.compile(r"(?P<secret>\bxox[abpr]-[0-9A-Za-z-]{10,})"),
    ),
    SecretPattern(
        "secret.private-key",
        "Private key",
        re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"),
    ),
    SecretPattern(
        "secret.generic-assignment",
        "Hard-coded password or key",
        re.compile(
            r"(?i)\b[\w-]*(?:secret|passw(?:or)?d|api[_-]?key|access[_-]?key|auth[_-]?token|token)"
            r"[\w-]*\s*[:=]\s*[\"']?(?P<secret>[^\s\"'`;,)]{8,})[\"']?"
        ),
    ),
)

_PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|changeme|your[_-].*|<.*>|\$\{.*\}|process\.env.*|os\.environ.*|"
    r"getenv.*|none|null|undefined|true|false|example.*|\.\.\.)$"
)


def is_placeholder(value: str) -> bool:
    """True for values that are clearly not real secrets (env lookups, placeholders)."""
    return bool(_PLACEHOLDER.match(value)) or len(value) < _MIN_SECRET_LEN


def mask_secret(value: str) -> str:
    """Mask a secret, keeping a short type prefix and the last 4 characters.

    Example: ``sk_live_51abcXYZ...wxyz`` becomes ``sk_live_****wxyz``.
    """
    if len(value) <= _MIN_SECRET_LEN:
        return _MASK
    prefix_match = re.match(r"^[A-Za-z]{2,4}[_-](?:[A-Za-z]{2,4}[_-])?", value)
    prefix = prefix_match.group(0)[:_MAX_PREFIX] if prefix_match else value[:2]
    return f"{prefix}{_MASK}{value[-_VISIBLE_SUFFIX:]}"


def redact_text(text: str) -> str:
    """Replace every secret value found in `text` with its mask."""
    for pattern in SECRET_PATTERNS:
        text = pattern.regex.sub(lambda m: _mask_match(m), text)
    return text


def _mask_match(match: re.Match[str]) -> str:
    whole = match.group(0)
    secret = match.group("secret")
    if is_placeholder(secret) or _MASK in secret:
        return whole
    start = match.start("secret") - match.start(0)
    return f"{whole[:start]}{mask_secret(secret)}{whole[start + len(secret) :]}"
