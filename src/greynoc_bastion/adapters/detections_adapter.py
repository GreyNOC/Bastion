"""Detections adapter — detection content lifecycle.

Bridges the two detection sources in Bastion:
  * detector-engine *drafts* (ideas generated from threat intel), which MUST
    stay ``DRAFT`` until proven; and
  * the DMZ-validated GNOC rule pack (the canonical, tested content).

This adapter owns the lifecycle: draft -> validating -> validated / needs_tuning
/ deprecated. Promotion to ``VALIDATED`` requires a *passing*
``BastionValidationResult`` — a generated detection can never self-promote.
This encodes the product rule: "Generated detections must remain drafts until
validated."
"""

from __future__ import annotations

from pathlib import Path

from ..schemas import (
    BastionDetection,
    BastionThreat,
    BastionValidationResult,
    Severity,
    ValidationStatus,
)
from .base import BaseAdapter
from .dmz_adapter import DmzAdapter


class DetectionsAdapter(BaseAdapter):
    source_repo = "GreyNOC/Detections"
    name = "detections"

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        super().__init__()
        self._dmz = DmzAdapter(fixtures_dir)

    # --- canonical validated pack -------------------------------------------
    def load_validated_pack(self) -> list[BastionDetection]:
        """Load the GNOC rule pack and mark it validated *after* it passes.

        We do not trust the pack blindly: each rule is run against its bundled
        test, and only rules whose test passes are marked VALIDATED. Rules that
        fail their own test are surfaced as NEEDS_TUNING.
        """
        results = {r.detection_id: r for r in self._dmz.validate_all_rules()}
        detections: list[BastionDetection] = []
        for rule in self._dmz.load_rules():
            det = self._dmz.rule_to_detection(rule)
            res = results.get(det.detection_id)
            if res and res.passed:
                det.status = ValidationStatus.VALIDATED
                det.metadata["last_validation"] = res.result_id
            elif res:
                det.status = ValidationStatus.NEEDS_TUNING
                det.metadata["last_validation"] = res.result_id
            else:
                det.status = ValidationStatus.DRAFT
            detections.append(det)
        return detections

    # --- drafts from threat intel -------------------------------------------
    def draft_from_threat(self, threat: BastionThreat) -> BastionDetection:
        """Turn a threat's detection idea into a DRAFT detection.

        The result is intentionally minimal and unvalidated — it is a starting
        point for a detection engineer, not a deployable rule.
        """
        det = BastionDetection(
            detection_id=f"DRAFT-{threat.threat_id}",
            name=f"Draft detection for {threat.threat_id}",
            description=threat.draft_detection or f"Draft coverage idea for {threat.title}",
            severity=threat.severity if threat.severity != Severity.INFO else Severity.MEDIUM,
            attack_techniques=list(threat.attack_techniques),
            data_sources=["(specify data sources)"],
            logic={"note": "Unvalidated draft. Define match logic, then validate in the Range."},
            logic_language="draft",
            status=ValidationStatus.DRAFT,
            author="detector-engine (draft)",
            references=list(threat.references),
            metadata={"threat_id": threat.threat_id, "origin": "threat-forecast"},
        )
        return det

    # --- lifecycle transitions ----------------------------------------------
    def promote(self, detection: BastionDetection, result: BastionValidationResult) -> BastionDetection:
        """Promote a detection based on a validation result.

        Only a *passing* result yields VALIDATED. A failing/partial result moves
        the detection to NEEDS_TUNING (or FAILED), never to VALIDATED.
        """
        if result.detection_id and result.detection_id != detection.detection_id:
            self.log.warning(
                "validation result %s is for %s, not %s; refusing to promote",
                result.result_id, result.detection_id, detection.detection_id,
            )
            return detection
        if result.passed and result.verdict == ValidationStatus.VALIDATED:
            detection.status = ValidationStatus.VALIDATED
        elif result.verdict == ValidationStatus.FAILED:
            detection.status = ValidationStatus.FAILED
        else:
            detection.status = ValidationStatus.NEEDS_TUNING
        detection.metadata["last_validation"] = result.result_id
        return detection

    def deprecate(self, detection: BastionDetection, reason: str = "") -> BastionDetection:
        detection.status = ValidationStatus.DEPRECATED
        if reason:
            detection.metadata["deprecation_reason"] = reason
        return detection

    def coverage_summary(self, detections: list[BastionDetection]) -> dict:
        """Rollup by status + ATT&CK technique coverage for the dashboard."""
        by_status: dict = {}
        techniques: set = set()
        for d in detections:
            by_status[d.status.value] = by_status.get(d.status.value, 0) + 1
            techniques.update(d.attack_techniques)
        return {
            "total": len(detections),
            "by_status": by_status,
            "validated": by_status.get(ValidationStatus.VALIDATED.value, 0),
            "drafts": by_status.get(ValidationStatus.DRAFT.value, 0),
            "attack_techniques_covered": sorted(techniques),
        }
