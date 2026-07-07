"""Threat Forecast service.

Wraps the Detector-Engine adapter: builds a ranked threat forecast from offline
fixtures or an ingested feed file, persists the threats, and converts each into
the universal ``BastionFinding`` envelope for reporting.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ..adapters.detector_engine_adapter import DetectorEngineAdapter
from ..db import Database
from ..schemas import (
    BastionEvidence,
    BastionFinding,
    BastionThreat,
    Confidence,
    EvidenceKind,
    FindingCategory,
    Severity,
)
from ..utils.logging import get_logger


class ThreatForecastService:
    def __init__(self, db: Optional[Database] = None, adapter: Optional[DetectorEngineAdapter] = None):
        self.db = db
        self.adapter = adapter or DetectorEngineAdapter()
        self.log = get_logger("threat_forecast")

    def demo(self, sectors: Optional[List[str]] = None, persist: bool = False) -> List[BastionThreat]:
        threats = self.adapter.forecast_from_fixtures(sectors=sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def ingest(self, fixture_path: Path, sectors: Optional[List[str]] = None,
               persist: bool = True) -> List[BastionThreat]:
        threats = self.adapter.forecast_from_path(Path(fixture_path), sectors=sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def to_findings(self, threats: List[BastionThreat]) -> List[BastionFinding]:
        findings: List[BastionFinding] = []
        for t in threats:
            drivers = t.metadata.get("drivers", [])
            evidence = [
                BastionEvidence(kind=EvidenceKind.FEED_RECORD, summary=d, source=t.source)
                for d in drivers
            ]
            why = t.summary or t.title
            if drivers:
                why = f"{why} Key drivers: " + "; ".join(drivers) + "."
            findings.append(BastionFinding(
                title=t.title,
                severity=t.severity,
                confidence=t.confidence,
                category=FindingCategory.THREAT,
                evidence=evidence,
                source=t.source,
                affected=", ".join(t.cve_ids) or t.threat_id,
                why_it_matters=why,
                recommended_action=t.remediation,
                validation_status=t.detection_status,
                false_positive_notes=(
                    "Threat intel reflects population-level risk; confirm the affected "
                    "product/version is present in your environment before prioritizing."
                ),
                ref_type="threat",
                ref_id=t.threat_id,
                tags=[t.category.value] + (["kev"] if t.kev else []) + (["ransomware"] if t.ransomware_used else []),
                metadata={"urgency": t.score.urgency, "epss": t.epss, "cvss": t.cvss},
            ))
        return findings
