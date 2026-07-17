"""Detection Validation service.

Wraps the DMZ + Detections adapters: validates the rule pack or a scenario
against synthetic telemetry, persists validation results, and converts them
into universal findings. Generated detections stay DRAFT until a passing
result promotes them.
"""

from __future__ import annotations

from pathlib import Path

from ..adapters.base import guarded_call
from ..adapters.detections_adapter import DetectionsAdapter
from ..adapters.dmz_adapter import DmzAdapter
from ..db import Database
from ..schemas import (
    BastionEvidence,
    BastionFinding,
    BastionValidationResult,
    Confidence,
    EvidenceKind,
    FindingCategory,
    Severity,
    ValidationStatus,
    stable_correlation_id,
)
from ..utils.logging import get_logger


class DetectionValidationService:
    def __init__(self, db: Database | None = None,
                 dmz: DmzAdapter | None = None,
                 detections: DetectionsAdapter | None = None):
        self.db = db
        self.dmz = dmz or DmzAdapter()
        self.detections = detections or DetectionsAdapter(dmz=self.dmz)
        self.log = get_logger("detection_validation")

    def validate_scenario(self, scenario_path: Path, persist: bool = True) -> BastionValidationResult:
        result = guarded_call(self.dmz, self.dmz.validate_scenario, Path(scenario_path))
        if persist and self.db:
            self.db.save_validation(result)
            self.db.save_finding(self._to_finding(result))
        return result

    def validate_all(self, persist: bool = True) -> list[BastionValidationResult]:
        rules = guarded_call(self.dmz, self.dmz.load_rules)
        results = guarded_call(self.dmz, self.dmz.validate_all_rules)
        if persist and self.db:
            # Derive lifecycle state from these exact results. Re-running the
            # adapter here used to create dangling last_validation references.
            pack = guarded_call(
                self.detections, self.detections.load_validated_pack,
                results=results, rules=rules,
            )
            for det in pack:
                self.db.save_detection(det)
            for r in results:
                self.db.save_validation(r)
            self.db.save_findings([self._to_finding(r) for r in results])
        return results

    def _to_finding(self, r: BastionValidationResult) -> BastionFinding:
        passed = r.passed
        severity = Severity.INFO if passed else (
            Severity.HIGH if r.verdict == ValidationStatus.FAILED else Severity.MEDIUM
        )
        ev = [BastionEvidence(
            kind=EvidenceKind.RULE_RESULT,
            summary=r.notes,
            source="dmz",
            content=(f"expected={r.expected_alerts} actual={r.actual_alerts} "
                     f"tp={r.true_positives} fp={r.false_positives} fn={r.false_negatives}"),
        )]
        return BastionFinding(
            correlation_id=stable_correlation_id(
                "fnd", "validation", r.detection_id, r.scenario,
            ),
            title=f"Validation: {r.detection_id} — {r.verdict.value}",
            severity=severity,
            confidence=Confidence.HIGH,
            category=FindingCategory.DETECTION,
            evidence=ev,
            source="dmz",
            affected=r.detection_id,
            why_it_matters=(
                "Detection passed validation against synthetic telemetry."
                if passed else
                "Detection did not behave as expected against synthetic telemetry; "
                "tune before relying on it."
            ),
            recommended_action=(
                "Promote to production monitoring." if passed
                else "Review rule logic, thresholds, and test coverage; re-validate."
            ),
            validation_status=r.verdict,
            false_positive_notes=(
                f"True-negative set produced {r.false_positives} alert(s) (want 0)."
            ),
            ref_type="validation",
            ref_id=r.result_id,
            tags=["detection", r.verdict.value],
            metadata={"precision": r.precision, "recall": r.recall, "scenario": r.scenario},
        )
