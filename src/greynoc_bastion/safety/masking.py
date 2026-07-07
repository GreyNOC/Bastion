"""Secret masking and scrubbing.

The one rule this module exists to enforce: **a full secret never leaves the
process.** Discovered credentials are reduced at the point of discovery to a
short masked preview plus a one-way fingerprint. Everything Bastion stores,
logs, or reports goes through here first.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

# Patterns that identify high-confidence secret material. These are used both
# to classify identities and to scrub free text (logs, notes, report bodies).
# Order matters: more specific provider tokens first.
_SECRET_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b", re.IGNORECASE)),
    ("generic_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret)\b\s*[:=]\s*"
        r"['\"]?([A-Za-z0-9/+_\-\.]{12,})['\"]?"
    )),
    ("high_entropy_hex", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
]

_REDACTION = "***REDACTED***"

# Scrub-only patterns: applied by ``scrub_text`` as a defense-in-depth backstop
# but NOT used to classify identities (they would over-flag). Catches long,
# high-entropy tokens (e.g. a bare 40-char AWS secret access key) that carry no
# ``key=`` prefix. Requires both a letter and a digit to avoid redacting plain
# words or prose.
_SCRUB_EXTRA: list[tuple[str, "re.Pattern[str]"]] = [
    ("high_entropy_token", re.compile(
        r"\b(?=[A-Za-z0-9+/_\-]{32,}\b)(?=[A-Za-z0-9+/_\-]*[A-Za-z])"
        r"(?=[A-Za-z0-9+/_\-]*[0-9])[A-Za-z0-9+/_\-]{32,}\b"
    )),
]


def fingerprint_secret(value: str) -> str:
    """Non-reversible short fingerprint of a secret value.

    SHA-256, first 16 hex chars. Used only for de-duplication and correlation.
    Given a fingerprint you cannot recover the secret.
    """
    if value is None:
        value = ""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def mask_secret(value: str, *, keep_start: int = 4, keep_end: int = 2) -> str:
    """Return a masked preview of a secret.

    Keeps a few leading/trailing characters so an operator can recognize a
    known credential, and stars the middle. Short values are fully starred.
    The result always contains ``*`` and never contains the full value.

        mask_secret("ghp_ABCDEFGHIJKLMNOP12")  -> "ghp_************P12"  (approx)
    """
    if value is None:
        return ""
    v = str(value)
    n = len(v)
    if n == 0:
        return ""
    if n <= keep_start + keep_end or n < 8:
        return "*" * max(n, 4)
    middle = max(n - keep_start - keep_end, 4)
    return f"{v[:keep_start]}{'*' * middle}{v[-keep_end:]}"


def looks_like_secret(text: str) -> bool:
    """True if ``text`` contains something that matches a known secret shape."""
    if not text:
        return False
    for _name, pat in _SECRET_PATTERNS:
        if pat.search(text):
            return True
    return False


def iter_secret_matches(text: str) -> Iterable[tuple[str, str]]:
    """Yield ``(pattern_name, matched_substring)`` for each secret found."""
    if not text:
        return
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            # For assignment-style matches, the secret is group(1) when present.
            token = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            yield name, token


def scrub_text(text: str, *, replacement: str = _REDACTION) -> str:
    """Redact any secret-looking substrings in free text.

    Used before writing logs, notes, or report bodies. Redacts the *token*
    portion of assignment-style matches so surrounding context survives:
    ``api_key = sk-abc...``  ->  ``api_key = ***REDACTED***``.
    """
    if not text:
        return text
    result = text
    for name, pat in (_SECRET_PATTERNS + _SCRUB_EXTRA):
        def _sub(m: "re.Match[str]") -> str:
            if m.groups() and m.group(1):
                # Replace only the captured secret, keep the label/operator.
                return m.group(0).replace(m.group(1), replacement)
            return replacement
        result = pat.sub(_sub, result)
    return result
