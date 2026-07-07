"""ReDoS guard for externally-sourced rule regexes.

Detection rules and NHI custom rules may carry regex patterns from files we do
not fully control. Catastrophic-backtracking patterns can hang the process, so
every such pattern is screened here before compilation. Modeled on the
NHI engine's ``_REDOS_SHAPES`` approach flagged during the source audit.
"""

from __future__ import annotations

import re

_MAX_PATTERN_LENGTH = 1000

# Shapes associated with catastrophic backtracking. These are heuristics; when
# in doubt the pattern is refused (fail closed). The regex shapes catch simple
# adjacent forms; ``_has_dangerous_nesting`` (below) catches the more general
# "quantified group whose body itself contains an unbounded quantifier" family
# (e.g. ``(\w+\s?)*``, ``(a+)+``, ``((a)+)+``) that pure shapes miss.
_REDOS_SHAPES = [
    re.compile(r"\([^)]*[+*]\)[+*]"),          # (a+)+ , (a*)* nested quantifiers
    re.compile(r"\([^)]*[+*][^)]*\)\{\d"),     # (a+){n} , (a+){n,m} bounded outer over unbounded inner
    re.compile(r"\([^)]*\|[^)]*\)[+*]"),       # (a|a)+ alternation under quantifier
    re.compile(r"[+*]\{[0-9]+,\}[+*]"),        # unbounded {n,} adjacent quantifier
    re.compile(r"(\.\*){3,}"),                  # .*.*.* repeated wildcards
]

# An unbounded quantifier: * + or {n,} (with no upper bound).
_UNBOUNDED_QUANT = re.compile(r"[*+]|\{\d*,\}")


def _has_dangerous_nesting(pattern: str) -> bool:
    """True if any quantified group's body contains an unbounded quantifier.

    Walks balanced parentheses; for each group immediately followed by an outer
    quantifier — ``*``, ``+``, or ANY brace repetition ``{n}`` / ``{n,}`` /
    ``{n,m}`` — checks whether the group body itself contains an unbounded
    quantifier. A *bounded* outer quantifier over an unbounded inner group (e.g.
    ``(a+){30}b``) backtracks just as catastrophically as ``(a+)+``, so bounded
    braces count too. This is the structural signature of exponential
    backtracking and is engine-shape-agnostic.
    """
    stack: list[int] = []           # indices of '(' after group-open bookkeeping
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2                  # skip escaped char
            continue
        if c == "[":                # skip character class (parens inside are literal)
            i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
            continue
        if c == "(":
            stack.append(i)
        elif c == ")" and stack:
            start = stack.pop()
            body = pattern[start + 1:i]
            # What immediately follows the closing paren? (Use tuple membership:
            # ``"" in "*+"`` is True in Python, which would false-positive on a
            # group that ends the pattern.)
            nxt = pattern[i + 1:i + 2]
            # Any brace repetition with a leading digit — {n}, {n,}, {n,m} —
            # counts as an outer quantifier (a bounded {n} still backtracks
            # catastrophically over an unbounded inner group). A bare {,m} or a
            # non-numeric brace is treated as a literal, as before.
            outer_quantified = nxt in ("*", "+") or bool(
                re.match(r"\{\d+(?:,\d*)?\}", pattern[i + 1:i + 16]))
            if outer_quantified and _UNBOUNDED_QUANT.search(body):
                return True
        i += 1
    return False


def is_safe_regex(pattern: str) -> tuple[bool, str]:
    """Return ``(ok, reason)``. ``ok`` is False for over-long or risky shapes."""
    if pattern is None:
        return False, "pattern is None"
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return False, f"pattern exceeds {_MAX_PATTERN_LENGTH} chars"
    for shape in _REDOS_SHAPES:
        if shape.search(pattern):
            return False, "pattern matches a known catastrophic-backtracking shape"
    if _has_dangerous_nesting(pattern):
        return False, "pattern nests an unbounded quantifier inside a quantified group"
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    return True, "ok"


def safe_compile(pattern: str, flags: int = 0) -> re.Pattern[str] | None:
    """Compile ``pattern`` only if it passes the ReDoS screen, else return None."""
    ok, _reason = is_safe_regex(pattern)
    if not ok:
        return None
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None
