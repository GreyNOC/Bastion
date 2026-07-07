"""BastionIdentity — a non-human identity discovered by Identity Blast Radius.

Safety-critical shape: this record NEVER holds a full secret. Only a masked
preview and a non-reversible fingerprint are retained. Bastion does not
validate, replay, or transmit the underlying credential.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import Confidence, Exposure, IdentityType, Severity


@dataclasses.dataclass
class BastionIdentity(BastionModel):
    """A discovered automation/non-human identity.

    ``masked_preview`` is something like ``ghp_****...**cd`` and
    ``secret_fingerprint`` is a short non-reversible hash used only for
    de-duplication. Neither can reconstruct the credential.
    """

    identity_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("nhi"))
    identity_type: IdentityType = IdentityType.UNKNOWN
    name: str = ""                          # human label, e.g. "GitHub PAT (deploy)"
    provider: str = ""                      # aws, github, gcp, openai, slack, ...

    # --- Masked-only secret representation (never the real value) ---
    masked_preview: str = ""
    secret_fingerprint: str = ""            # sha256[:16] of the value, one-way
    detector: str = ""                      # which pattern/detector matched

    location: str = ""                      # repo-relative path or config source
    line: Optional[int] = None
    repo_path: str = ""

    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    exposure: Exposure = Exposure.UNKNOWN

    # Blast-radius signals.
    scopes: List[str] = dataclasses.field(default_factory=list)     # permissions/scopes
    privileged: bool = False
    reachable_services: List[str] = dataclasses.field(default_factory=list)
    permission_chain: List[str] = dataclasses.field(default_factory=list)  # A -> B -> C
    owasp_refs: List[Dict[str, str]] = dataclasses.field(default_factory=list)  # OWASP NHI Top 10
    is_active_unknown: bool = True          # we never test liveness; always "unknown"

    recommended_action: str = ""
    false_positive_notes: str = ""
    operator_notes: str = ""

    discovered_at: str = dataclasses.field(default_factory=utcnow_iso)
    correlation_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("fnd"))
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        # Hard invariant backstop: a stored preview must actually be masked.
        # A properly masked preview (from safety.masking.mask_secret) is mostly
        # stars. If the value has no stars, or too few to be a real mask, run it
        # back through the sanctioned masking utility rather than store it raw.
        mp = self.masked_preview or ""
        if mp:
            star_ratio = mp.count("*") / len(mp)
            if "*" not in mp or star_ratio < 0.25:
                from ..safety.masking import mask_secret
                self.masked_preview = mask_secret(mp)
