"""BastionFinding — the universal finding shape every module produces.

The field list is fixed by the product spec: every finding, regardless of
which module raised it, carries the same evidence-first envelope so reports,
the dashboard, and the evidence center can treat them uniformly.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import (
    Confidence,
    FindingCategory,
    Severity,
    ValidationStatus,
)
from .evidence import BastionEvidence


@dataclasses.dataclass
class BastionFinding(BastionModel):
    """A single evidence-backed finding.

    Required narrative fields (spec): title, severity, confidence, evidence,
    source, affected asset/repo path, why it matters, recommended action,
    validation status, false-positive notes, operator notes, timestamp,
    correlation id.
    """

    title: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    category: FindingCategory = FindingCategory.SYSTEM

    evidence: list[BastionEvidence] = dataclasses.field(default_factory=list)
    source: str = ""                       # producing module/adapter/feed
    affected: str = ""                     # asset id, repo path, host:port, rule id

    why_it_matters: str = ""
    recommended_action: str = ""
    validation_status: ValidationStatus = ValidationStatus.NOT_APPLICABLE
    false_positive_notes: str = ""
    operator_notes: str = ""

    # Optional cross-links to the richer typed record behind this finding.
    ref_type: str | None = None         # "threat" | "identity" | "detection" | "asset"
    ref_id: str | None = None

    tags: list[str] = dataclasses.field(default_factory=list)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    timestamp: str = dataclasses.field(default_factory=utcnow_iso)
    correlation_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("fnd"))

    def add_evidence(self, ev: BastionEvidence) -> BastionFinding:
        self.evidence.append(ev)
        return self

    @property
    def priority_score(self) -> int:
        """Coarse sort key: severity dominates, confidence breaks ties."""
        return self.severity.rank * 3 + self.confidence.rank
