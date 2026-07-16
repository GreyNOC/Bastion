"""Live telemetry ingestion — validate detections against real local logs.

Extends the Detection Validation Range beyond synthetic replay: an operator
points Bastion at a **local** log file (JSONL, or a JSON array of events) and
the full rule pack is replayed over it, producing fired-rule results and
multi-stage host incidents exactly like the synthetic range.

Safety boundary:
  * Input is a local file the operator names — Bastion never tails, collects,
    or ships logs anywhere.
  * Reads are size-capped (default 25 MB) and event-capped (default 200k);
    oversized input is refused, not truncated silently.
  * Malformed lines are counted and skipped, never fatal.
  * Events pass through the same secret scrubber as everything else before
    they are stored in findings/evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..adapters.dmz_adapter import DmzAdapter
from ..db import Database
from ..safety.masking import scrub_text
from ..schemas import (
    BastionEvidence,
    BastionFinding,
    Confidence,
    EvidenceKind,
    FindingCategory,
    Severity,
    ValidationStatus,
    utcnow_iso,
)
from ..utils.logging import get_logger

MAX_BYTES_DEFAULT = 25 * 1024 * 1024
MAX_EVENTS_DEFAULT = 200_000


class TelemetryIngestError(ValueError):
    """Raised when a telemetry file cannot be accepted (missing, oversized)."""


class TelemetryIngestService:
    def __init__(self, db: Database | None = None, dmz: DmzAdapter | None = None):
        self.db = db
        self.dmz = dmz or DmzAdapter()
        self.log = get_logger("telemetry_ingest")

    def replay_file(
        self,
        path: Path,
        *,
        max_bytes: int = MAX_BYTES_DEFAULT,
        max_events: int = MAX_EVENTS_DEFAULT,
        persist: bool = True,
        actor: str = "operator",
    ) -> dict[str, Any]:
        """Replay the rule pack over a local log file; return a range report."""
        path = Path(path)
        if not path.is_file():
            raise TelemetryIngestError(f"telemetry file not found: {path}")
        size = path.stat().st_size
        if size > max_bytes:
            raise TelemetryIngestError(
                f"telemetry file is {size} bytes; the cap is {max_bytes}. "
                "Split the log or raise --max-bytes explicitly.")

        events, skipped = self._load_events(path, max_events=max_events)
        rules = self.dmz.load_rules()

        fired: list[dict[str, Any]] = []
        all_alerts: list[dict[str, Any]] = []
        for rule in rules:
            alerts = self.dmz.evaluate_rule(rule, events)
            if alerts:
                fired.append({
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name", ""),
                    "severity": str(rule.get("severity", "medium")),
                    "alerts": len(alerts),
                })
                all_alerts.extend(alerts)
        incidents = self.dmz.correlate_incidents(all_alerts)

        result = {
            "file": str(path),
            "bytes": size,
            "events": len(events),
            "skipped_lines": skipped,
            "rules_evaluated": len(rules),
            "rules_fired": fired,
            "alerts": len(all_alerts),
            "incidents": incidents,
            "ran_at": utcnow_iso(),
        }
        if persist and self.db:
            findings = self._to_findings(result, all_alerts)
            self.db.save_findings(findings)
            self.db.audit(
                "telemetry_replayed", actor=actor,
                detail=f"file={path.name} events={len(events)} alerts={len(all_alerts)} "
                       f"incidents={len(incidents)}")
        return result

    # --- parsing -----------------------------------------------------------------
    def _load_events(self, path: Path, *, max_events: int) -> tuple[list[dict[str, Any]], int]:
        """Parse JSONL (one event per line) or a single JSON array of events."""
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped = text.lstrip()
        events: list[dict[str, Any]] = []
        skipped = 0

        if stripped.startswith("["):
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise TelemetryIngestError(f"not a readable JSON array: {exc}") from None
            if not isinstance(data, list):
                raise TelemetryIngestError("top-level JSON is not an array of events")
            for item in data:
                if len(events) >= max_events:
                    skipped += 1
                    continue
                if isinstance(item, dict):
                    events.append(item)
                else:
                    skipped += 1
            return events, skipped

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if len(events) >= max_events:
                skipped += 1
                continue
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                skipped += 1
                continue
            if isinstance(item, dict):
                events.append(item)
            else:
                skipped += 1
        return events, skipped

    # --- findings ------------------------------------------------------------------
    def _to_findings(self, result: dict[str, Any], alerts: list[dict[str, Any]]) -> list[BastionFinding]:
        """One finding per fired rule, evidence-first and scrubbed."""
        findings: list[BastionFinding] = []
        by_rule: dict[str, list[dict[str, Any]]] = {}
        for a in alerts:
            by_rule.setdefault(str(a.get("rule_id")), []).append(a)

        for entry in result["rules_fired"]:
            rid = str(entry["rule_id"])
            rule_alerts = by_rule.get(rid, [])
            sample = rule_alerts[0] if rule_alerts else {}
            evidence = [BastionEvidence(
                kind=EvidenceKind.TELEMETRY,
                summary=scrub_text(
                    f"rule {rid} fired {len(rule_alerts)} time(s) over live telemetry "
                    f"({result['file']})"),
                source="telemetry-ingest",
                content=scrub_text(json.dumps(
                    {k: sample.get(k) for k in ("host", "user", "count", "first_ts", "last_ts")},
                    ensure_ascii=False)),
            )]
            findings.append(BastionFinding(
                title=f"Live telemetry: {entry['rule_name'] or rid} fired",
                severity=Severity.coerce(entry.get("severity"), Severity.MEDIUM),
                confidence=Confidence.MEDIUM,
                category=FindingCategory.DETECTION,
                evidence=evidence,
                source="telemetry-ingest",
                affected=scrub_text(str(sample.get("host") or "(unknown host)")),
                why_it_matters=(
                    "A validated detection matched REAL telemetry from this environment — "
                    "this is observed activity, not a synthetic test."),
                recommended_action=(
                    "Review the matching events and the rule's runbook; open a case if the "
                    "activity is not expected."),
                validation_status=ValidationStatus.VALIDATED,
                ref_type="detection",
                ref_id=rid,
                tags=["telemetry", "live-log"],
                metadata={"alerts": len(rule_alerts), "file": result["file"]},
            ))
        return findings
