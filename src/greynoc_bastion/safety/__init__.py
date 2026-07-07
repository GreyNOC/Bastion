"""Bastion safety layer.

This package concentrates every hard safety rule in one auditable place:

  * ``masking``  — never emit a full secret; mask + fingerprint instead.
  * ``netguard`` — block private/loopback fetch targets; enforce HTTPS,
                   allowlists, and size/timeout caps when live fetch is on.
  * ``status``   — a single snapshot of the live safety posture for the
                   Safety Status page, ``doctor``, and tests.

Nothing in Bastion should reimplement these rules; import from here.
"""

from __future__ import annotations

from .masking import (
    fingerprint_secret,
    looks_like_secret,
    mask_secret,
    scrub_text,
)
from .netguard import (
    FetchDecision,
    NetGuardError,
    evaluate_fetch_target,
    is_private_host,
)
from .status import SafetyStatus, build_safety_status

__all__ = [
    "fingerprint_secret",
    "looks_like_secret",
    "mask_secret",
    "scrub_text",
    "FetchDecision",
    "NetGuardError",
    "evaluate_fetch_target",
    "is_private_host",
    "SafetyStatus",
    "build_safety_status",
]
