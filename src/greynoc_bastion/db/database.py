"""SQLite persistence for Bastion.

A thin repository over ``sqlite3`` with a JSON-document-plus-indexed-columns
layout (see ``schema.sql``). Deliberately dependency-free and driver-swappable
so the future Postgres path is small.

Safety note: this layer stores whatever the models contain. Because
``BastionIdentity`` only ever holds masked previews and fingerprints, no full
secret can reach the database. The ``audit_log`` table records privileged
actions.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..schemas import (
    BastionAsset,
    BastionDetection,
    BastionEvidence,
    BastionFinding,
    BastionIdentity,
    BastionPlaybook,
    BastionReport,
    BastionThreat,
    BastionValidationResult,
    utcnow_iso,
)

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class Database:
    """A Bastion SQLite database handle."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # --- connection plumbing -------------------------------------------------
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        ddl = _SCHEMA_PATH.read_text(encoding="utf-8")
        with self.connect() as conn:
            conn.executescript(ddl)

    # --- generic helpers -----------------------------------------------------
    @staticmethod
    def _dumps(model) -> str:
        return json.dumps(model.to_dict(), ensure_ascii=False)

    # --- threats -------------------------------------------------------------
    def save_threat(self, t: BastionThreat) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO threats "
                "(threat_id, category, title, severity, urgency, kev, last_updated, data) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    t.threat_id, t.category.value, t.title, t.severity.value,
                    float(t.score.urgency), int(bool(t.kev)), t.last_updated,
                    self._dumps(t),
                ),
            )

    def list_threats(self, limit: int = 100) -> list[BastionThreat]:
        # Order by urgency in SQL; break ties by true severity rank in Python
        # (the severity column is text, so a SQL sort would be alphabetical and
        # rank "medium" above "high"/"critical").
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM threats ORDER BY urgency DESC LIMIT ?", (limit,)
            ).fetchall()
        threats = [BastionThreat.from_dict(json.loads(r["data"])) for r in rows]
        threats.sort(key=lambda t: (t.score.urgency, t.severity.rank), reverse=True)
        return threats

    # --- identities ----------------------------------------------------------
    def save_identity(self, i: BastionIdentity) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identities "
                "(identity_id, identity_type, provider, severity, exposure, repo_path, "
                " secret_fingerprint, discovered_at, data) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    i.identity_id, i.identity_type.value, i.provider, i.severity.value,
                    i.exposure.value, i.repo_path, i.secret_fingerprint,
                    i.discovered_at, self._dumps(i),
                ),
            )

    def list_identities(self, limit: int = 500) -> list[BastionIdentity]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM identities ORDER BY discovered_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [BastionIdentity.from_dict(json.loads(r["data"])) for r in rows]

    # --- detections ----------------------------------------------------------
    def save_detection(self, d: BastionDetection) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO detections "
                "(detection_id, name, severity, status, updated_at, data) VALUES (?,?,?,?,?,?)",
                (d.detection_id, d.name, d.severity.value, d.status.value, d.updated_at, self._dumps(d)),
            )

    def get_detection(self, detection_id: str) -> BastionDetection | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT data FROM detections WHERE detection_id = ?", (detection_id,)
            ).fetchone()
        return BastionDetection.from_dict(json.loads(row["data"])) if row else None

    def list_detections(self, limit: int = 500) -> list[BastionDetection]:
        with self.connect() as conn:
            rows = conn.execute("SELECT data FROM detections LIMIT ?", (limit,)).fetchall()
        return [BastionDetection.from_dict(json.loads(r["data"])) for r in rows]

    # --- validation results --------------------------------------------------
    def save_validation(self, v: BastionValidationResult) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO validation_results "
                "(result_id, detection_id, scenario, verdict, passed, ran_at, data) "
                "VALUES (?,?,?,?,?,?,?)",
                (v.result_id, v.detection_id, v.scenario, v.verdict.value,
                 int(bool(v.passed)), v.ran_at, self._dumps(v)),
            )

    def list_validations(self, limit: int = 500) -> list[BastionValidationResult]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM validation_results ORDER BY ran_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [BastionValidationResult.from_dict(json.loads(r["data"])) for r in rows]

    # --- playbooks -----------------------------------------------------------
    def save_playbook(self, p: BastionPlaybook) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO playbooks "
                "(slug, name, category, severity, updated_at, data) VALUES (?,?,?,?,?,?)",
                (p.slug, p.name, p.category, p.severity.value, p.updated_at, self._dumps(p)),
            )

    def list_playbooks(self, limit: int = 500) -> list[BastionPlaybook]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM playbooks ORDER BY slug LIMIT ?", (limit,)
            ).fetchall()
        return [BastionPlaybook.from_dict(json.loads(r["data"])) for r in rows]

    # --- assets --------------------------------------------------------------
    def save_asset(self, a: BastionAsset) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO assets "
                "(asset_id, kind, host, port, exposure, severity, risky, last_seen, data) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (a.asset_id, a.kind.value, a.host, a.port, a.exposure.value,
                 a.severity.value, int(bool(a.risky)), a.last_seen, self._dumps(a)),
            )

    def list_assets(self, limit: int = 500) -> list[BastionAsset]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM assets ORDER BY risky DESC LIMIT ?", (limit,)
            ).fetchall()
        assets = [BastionAsset.from_dict(json.loads(r["data"])) for r in rows]
        # Re-sort by true severity rank in Python (SQL text sort is alphabetical).
        assets.sort(key=lambda a: (a.risky, a.severity.rank), reverse=True)
        return assets

    # --- findings ------------------------------------------------------------
    def save_finding(self, f: BastionFinding) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO findings "
                "(correlation_id, title, severity, confidence, category, validation_status, "
                " ref_type, ref_id, timestamp, data) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (f.correlation_id, f.title, f.severity.value, f.confidence.value,
                 f.category.value, f.validation_status.value, f.ref_type, f.ref_id,
                 f.timestamp, self._dumps(f)),
            )

    def save_findings(self, findings: Iterable[BastionFinding]) -> int:
        n = 0
        for f in findings:
            self.save_finding(f)
            n += 1
        return n

    def list_findings(self, limit: int = 1000, category: str | None = None) -> list[BastionFinding]:
        with self.connect() as conn:
            if category:
                rows = conn.execute(
                    "SELECT data FROM findings WHERE category = ? ORDER BY timestamp DESC LIMIT ?",
                    (category, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [BastionFinding.from_dict(json.loads(r["data"])) for r in rows]

    # --- reports & evidence --------------------------------------------------
    def save_report(self, r: BastionReport) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports (report_id, title, generated_at, data) "
                "VALUES (?,?,?,?)",
                (r.report_id, r.title, r.generated_at, self._dumps(r)),
            )

    def list_reports(self, limit: int = 100) -> list[BastionReport]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM reports ORDER BY generated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [BastionReport.from_dict(json.loads(r["data"])) for r in rows]

    def save_evidence(self, e: BastionEvidence) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO evidence (evidence_id, kind, source, collected_at, data) "
                "VALUES (?,?,?,?,?)",
                (e.evidence_id, e.kind.value, e.source, e.collected_at, self._dumps(e)),
            )

    # --- audit log -----------------------------------------------------------
    def audit(self, action: str, *, actor: str = "system", detail: str = "",
              correlation_id: str | None = None) -> None:
        """Append a privileged-action record. Detail is scrubbed by callers."""
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, action, actor, detail, correlation_id) VALUES (?,?,?,?,?)",
                (utcnow_iso(), action, actor, detail, correlation_id),
            )

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ts, action, actor, detail, correlation_id FROM audit_log "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # --- meta ----------------------------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)", (key, value))

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def counts(self) -> dict[str, int]:
        """Row counts per table for the Overview page and ``status``."""
        tables = [
            "threats", "identities", "detections", "validation_results",
            "playbooks", "assets", "findings", "reports", "evidence",
        ]
        out: dict[str, int] = {}
        with self.connect() as conn:
            for tbl in tables:
                # tbl is from the fixed internal allowlist above, never user input.
                query = f"SELECT COUNT(*) AS n FROM {tbl}"  # nosec B608
                out[tbl] = conn.execute(query).fetchone()["n"]
        return out
