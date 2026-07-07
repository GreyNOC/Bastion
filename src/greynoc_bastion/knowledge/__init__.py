"""Shared defensive knowledge bases used across Bastion engines.

These are curated, offline data tables (MITRE ATT&CK techniques, AI-abuse
taxonomy, post-quantum primitives). They are pure data + small pure functions —
no network, no offensive content — and are shared so every engine speaks the
same vocabulary (which is what lets the correlation spine join across engines).
"""

from __future__ import annotations

from .attack import (
    ATTACK_TACTICS,
    TECHNIQUES,
    infer_techniques,
    tactic_for_technique,
    technique_name,
    normalize_technique,
)

__all__ = [
    "ATTACK_TACTICS",
    "TECHNIQUES",
    "infer_techniques",
    "tactic_for_technique",
    "technique_name",
    "normalize_technique",
]
