"""BastionDetection and BastionValidationResult — detection engineering shapes.

A detection is a rule with expectations. A validation result is what happened
when the Detection Validation Range replayed synthetic telemetry against it.
Generated detections stay ``DRAFT`` until a validation run promotes them.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import Severity, ValidationStatus


@dataclasses.dataclass
class BastionDetection(BastionModel):
    """A detection rule and its metadata.

    ``logic`` is an opaque, engine-specific rule body (e.g. a query or a
    match spec). Bastion treats it as data — it validates behavior, it does
    not execute arbitrary rule code.
    """

    detection_id: str = ""                  # stable id, e.g. GNOC-AUTH-001
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM

    attack_techniques: List[str] = dataclasses.field(default_factory=list)
    data_sources: List[str] = dataclasses.field(default_factory=list)
    logic: Dict[str, Any] = dataclasses.field(default_factory=dict)  # engine-specific
    logic_language: str = "gnoc-match"      # dialect label for the logic body

    expected_true_positives: int = 0
    expected_false_positives: int = 0

    status: ValidationStatus = ValidationStatus.DRAFT
    version: str = "0.1.0"
    author: str = ""
    references: List[str] = dataclasses.field(default_factory=list)

    created_at: str = dataclasses.field(default_factory=utcnow_iso)
    updated_at: str = dataclasses.field(default_factory=utcnow_iso)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class BastionValidationResult(BastionModel):
    """Outcome of replaying a scenario against a detection.

    Records expected vs actual alerts, derived precision/recall, a verdict,
    and a correlation id linking it to an evidence bundle.
    """

    result_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("val"))
    detection_id: str = ""
    scenario: str = ""                      # scenario name or path

    expected_alerts: int = 0
    actual_alerts: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    verdict: ValidationStatus = ValidationStatus.VALIDATING
    passed: bool = False
    notes: str = ""

    precision: Optional[float] = None
    recall: Optional[float] = None

    evidence_bundle_ref: Optional[str] = None
    matched_events: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    missed_events: List[Dict[str, Any]] = dataclasses.field(default_factory=list)

    ran_at: str = dataclasses.field(default_factory=utcnow_iso)
    correlation_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("fnd"))
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def compute_metrics(self) -> "BastionValidationResult":
        """Fill precision/recall/verdict from the raw counts."""
        tp, fp, fn = self.true_positives, self.false_positives, self.false_negatives
        self.precision = tp / (tp + fp) if (tp + fp) else None
        self.recall = tp / (tp + fn) if (tp + fn) else None
        if fn == 0 and fp == 0 and tp > 0:
            self.verdict = ValidationStatus.VALIDATED
            self.passed = True
        elif tp == 0 and self.expected_alerts > 0:
            self.verdict = ValidationStatus.FAILED
            self.passed = False
        else:
            self.verdict = ValidationStatus.NEEDS_TUNING
            self.passed = False
        return self
