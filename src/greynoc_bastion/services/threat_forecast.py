"""Threat Forecast service.

Wraps the Detector-Engine adapter: builds a ranked threat forecast from offline
fixtures, an ingested feed file, or — only when live fetching is explicitly
enabled — a guarded HTTPS fetch. Persists the threats and converts each into the
universal ``BastionFinding`` envelope for reporting.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..adapters.detector_engine_adapter import DetectorEngineAdapter
from ..db import Database
from ..schemas import (
    BastionEvidence,
    BastionFinding,
    BastionThreat,
    EvidenceKind,
    FindingCategory,
)
from ..utils.logging import get_logger


class ThreatForecastService:
    def __init__(self, db: Database | None = None, adapter: DetectorEngineAdapter | None = None,
                 config=None):
        self.db = db
        self.adapter = adapter or DetectorEngineAdapter()
        self.config = config
        self.log = get_logger("threat_forecast")

    def ingest_url(self, url: str, sectors: list[str] | None = None,
                   persist: bool = True) -> list[BastionThreat]:
        """Ingest a CVE feed from a URL via the guarded fetcher (opt-in only).

        Refuses unless live fetching is enabled. Every request (and redirect) is
        evaluated by the network guard: HTTPS-only, allowlisted, SSRF-blocked,
        size/timeout-capped. The fetch is audit-logged.
        """
        if self.config is None or not getattr(self.config, "live_fetch", False):
            raise RuntimeError(
                "live fetching is disabled. Set BASTION_LIVE_FETCH=true and add the host to "
                "BASTION_FETCH_ALLOWLIST to ingest from a URL (HTTPS-only, SSRF-guarded)."
            )
        from ..safety.fetcher import build_fetcher_from_config
        fetcher = build_fetcher_from_config(self.config)

        def _audit(action: str, detail: str) -> None:
            if self.db is not None:
                self.db.audit(action, actor="threat_forecast", detail=detail)

        result = fetcher.fetch(url, audit=_audit)
        try:
            data = json.loads(result.body.decode("utf-8", "replace"))
        except (ValueError, RecursionError) as exc:
            raise RuntimeError(f"fetched feed is not valid JSON: {type(exc).__name__}") from None
        cves = self.adapter.parse_cve_feed(data)
        threats = self.adapter.build_threats(cves, {}, {}, sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def demo(self, sectors: list[str] | None = None, persist: bool = False) -> list[BastionThreat]:
        threats = self.adapter.forecast_from_fixtures(sectors=sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def ingest(self, fixture_path: Path, sectors: list[str] | None = None,
               persist: bool = True) -> list[BastionThreat]:
        threats = self.adapter.forecast_from_path(Path(fixture_path), sectors=sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def to_findings(self, threats: list[BastionThreat]) -> list[BastionFinding]:
        findings: list[BastionFinding] = []
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
                tags=(
                    [t.category.value]
                    + (["kev"] if t.kev else [])
                    + (["ransomware"] if t.ransomware_used else [])
                    + list(t.attack_techniques)
                    + ([f"forecast:{t.forecast.window}"] if t.forecast else [])
                    + [f"ai-abuse:{a['id']}" for a in t.ai_abuse]
                    + (["pqc-hndl"] if t.pqc_risk else [])
                ),
                metadata={
                    "urgency": t.score.urgency, "epss": t.epss, "cvss": t.cvss,
                    "attack_techniques": t.attack_techniques,
                    "forecast": t.forecast.to_dict() if t.forecast else None,
                    "ai_abuse": t.ai_abuse,
                    "pqc_risk": t.pqc_risk,
                },
            ))
        return findings
