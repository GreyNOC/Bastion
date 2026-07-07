"""ReDoS guard for externally-sourced rule regexes.

Detection rules and NHI custom rules may carry regex patterns from files we do
not fully control. Catastrophic-backtracking patterns can hang the process, so
every such pattern is screened here before compilation. Modeled on the
NHI engine's ``_REDOS_SHAPES`` approach flagged during the source audit.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

_MAX_PATTERN_LENGTH = 1000

# Shapes associated with catastrophic backtracking. These are heuristics; when
# in doubt the pattern is refused (fail closed).
_REDOS_SHAPES = [
    re.compile(r"\([^)]*[+*]\)[+*]"),          # (a+)+ , (a*)* nested quantifiers
    re.compile(r"\([^)]*\|[^)]*\)[+*]"),       # (a|a)+ alternation under quantifier
    re.compile(r"[+*]\{[0-9]+,\}[+*]"),        # unbounded {n,} adjacent quantifier
    re.compile(r"(\.\*){3,}"),                  # .*.*.* repeated wildcards
]


def is_safe_regex(pattern: str) -> Tuple[bool, str]:
    """Return ``(ok, reason)``. ``ok`` is False for over-long or risky shapes."""
    if pattern is None:
        return False, "pattern is None"
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return False, f"pattern exceeds {_MAX_PATTERN_LENGTH} chars"
    for shape in _REDOS_SHAPES:
        if shape.search(pattern):
            return False, "pattern matches a known catastrophic-backtracking shape"
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    return True, "ok"


def safe_compile(pattern: str, flags: int = 0) -> Optional["re.Pattern[str]"]:
    """Compile ``pattern`` only if it passes the ReDoS screen, else return None."""
    ok, _reason = is_safe_regex(pattern)
    if not ok:
        return None
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None
