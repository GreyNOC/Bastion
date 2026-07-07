"""BastionEvidence — a single, citable piece of support for a finding."""

from __future__ import annotations

import dataclasses
from typing import Any

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import EvidenceKind


@dataclasses.dataclass
class BastionEvidence(BastionModel):
    """One unit of evidence.

    Evidence is deliberately small and self-describing so it can travel in an
    evidence bundle and be re-verified later. ``content`` is already-masked,
    human-readable text; ``raw_ref`` points at a stored artifact (a bundle
    file, a log offset) without inlining anything sensitive.
    """

    kind: EvidenceKind = EvidenceKind.NOTE
    summary: str = ""
    content: str = ""
    source: str = ""                       # where it came from (feed, file, rule id)
    raw_ref: str | None = None          # pointer to a stored artifact, not the artifact
    location: str | None = None         # file:line, host:port, log offset, etc.
    collected_at: str = dataclasses.field(default_factory=utcnow_iso)
    evidence_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("evd"))
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def short(self) -> str:
        loc = f" @ {self.location}" if self.location else ""
        return f"[{self.kind}] {self.summary}{loc}"
