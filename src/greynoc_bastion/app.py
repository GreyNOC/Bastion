"""BastionApp — the composition root.

Wires config + database + adapters + services together. Everything else (CLI,
web server, tests) constructs a ``BastionApp`` and talks to it, so there is a
single place where wiring and safety defaults live.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .adapters import PlaybooksAdapter
from .config import BastionConfig, load_config
from .db import Database
from .safety.status import SafetyStatus, build_safety_status
from .schemas import (
    BastionFinding,
    BastionPlaybook,
    BastionReport,
    ReportFormat,
    utcnow_iso,
)
from .services import (
    AIAssistantService,
    AssetExposureService,
    DetectionValidationService,
    EvidenceCenter,
    IdentityBlastRadiusService,
    ReportCenter,
    ThreatForecastService,
)
from .services.correlation import CorrelationService
from .services.threat_intel_export import to_attack_navigator_layer, to_stix_bundle
from .utils.logging import get_logger, setup_logging

__all__ = ["BastionApp"]


class BastionApp:
    def __init__(self, config: Optional[BastionConfig] = None):
        self.config = config or load_config()
        setup_logging(self.config.log_level)
        self.log = get_logger("app")
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)

        # Services (constructed lazily-ish; cheap to build).
        self.threat_forecast = ThreatForecastService(self.db)
        self.identity = IdentityBlastRadiusService(self.db)
        self.detection = DetectionValidationService(self.db)
        self.assets = AssetExposureService(self.db)
        self.playbooks = PlaybooksAdapter()
        self.report_center = ReportCenter()
        self.evidence_center = EvidenceCenter()
        self.ai = AIAssistantService(self.config, self.db)
        self.correlation = CorrelationService(self.db)

    # --- status / health -----------------------------------------------------
    def safety_status(self) -> SafetyStatus:
        return build_safety_status(
            self.config,
            last_doctor_result=self.db.get_meta("last_doctor_result"),
            last_doctor_at=self.db.get_meta("last_doctor_at"),
        )

    def status(self) -> Dict[str, Any]:
        return {
            "product": "GreyNOC Bastion",
            "version": "0.1.0",
            "config": self.config.public_dict(),
            "counts": self.db.counts(),
            "safety_posture": self.safety_status().posture,
            "playbooks_available": len(self.playbooks._iter_files()),
            "timestamp": utcnow_iso(),
        }

    def doctor(self) -> Dict[str, Any]:
        """Run self-checks and record the result for the Safety Status page."""
        checks: List[Dict[str, Any]] = []

        def check(name: str, ok: bool, detail: str = "") -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})

        # 1) Loopback binding.
        check("api_loopback_binding", self.config.loopback_only,
              f"host={self.config.host}")
        # 2) Live fetch off (or safely configured).
        check("live_fetch_default_off", not self.config.live_fetch or bool(self.config.fetch_allowlist),
              f"live_fetch={self.config.live_fetch} allowlist={len(self.config.fetch_allowlist)}")
        # 3) DB reachable.
        try:
            self.db.counts()
            check("database_reachable", True, str(self.config.db_path))
        except Exception as exc:  # noqa: BLE001
            check("database_reachable", False, str(exc))
        # 4) Report dir writable.
        try:
            probe = self.config.report_dir / ".doctor_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            check("report_dir_writable", True, str(self.config.report_dir))
        except Exception as exc:  # noqa: BLE001
            check("report_dir_writable", False, str(exc))
        # 5) Playbook corpus present + no offensive playbooks.
        files = self.playbooks._iter_files()
        no_offensive = not any("bugbounty" in f.name.lower() for f in files)
        check("playbooks_present", len(files) > 0, f"{len(files)} playbooks")
        check("no_offensive_playbooks", no_offensive, "bug-bounty playbooks excluded")
        # 6) Detection pack validates.
        try:
            results = self.detection.dmz.validate_all_rules()
            passing = sum(1 for r in results if r.passed)
            check("detection_pack_validates", passing == len(results) and results,
                  f"{passing}/{len(results)} rules pass")
        except Exception as exc:  # noqa: BLE001
            check("detection_pack_validates", False, str(exc))
        # 7) Secret masking active.
        from .safety.masking import mask_secret
        masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
        check("secret_masking_active", "*" in masked and "IOSFODNN7" not in masked, masked)
        # 8) AI command execution disabled.
        check("ai_command_execution_disabled", not self.config.ai_command_execution,
              f"ai_command_execution={self.config.ai_command_execution}")

        ok = all(c["ok"] for c in checks)
        result = "ok" if ok else "issues-found"
        self.db.set_meta("last_doctor_result", result)
        self.db.set_meta("last_doctor_at", utcnow_iso())
        return {"ok": ok, "result": result, "checks": checks, "timestamp": utcnow_iso()}

    # --- playbooks -----------------------------------------------------------
    def list_playbooks(self) -> List[BastionPlaybook]:
        return self.playbooks.load_all()

    def get_playbook(self, slug: str) -> Optional[BastionPlaybook]:
        return self.playbooks.get(slug)

    # --- report building -----------------------------------------------------
    def build_report(
        self,
        *,
        title: str = "GreyNOC Bastion — Consolidated Report",
        out_dir: Optional[Path] = None,
        formats: Optional[List[ReportFormat]] = None,
        include_bundle: bool = True,
    ) -> BastionReport:
        """Assemble all stored findings into a report and write it out."""
        out_dir = Path(out_dir) if out_dir else self.config.report_dir
        formats = formats or [
            ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON,
            ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.PDF,
        ]
        findings: List[BastionFinding] = self.db.list_findings()
        modules = sorted({f.category.value for f in findings})
        report = BastionReport(title=title, modules=modules, findings=findings)
        report.recompute_summary()

        self.report_center.write(report, out_dir, formats)
        if include_bundle:
            self.evidence_center.build_bundle(report, out_dir)
        self.db.save_report(report)
        return report

    # --- full-capacity engine surfaces --------------------------------------
    def correlate(self) -> Dict[str, Any]:
        """Build the cross-engine correlation view (clusters + coverage gaps)."""
        return self.correlation.build()

    def detection_coverage(self) -> Dict[str, Any]:
        """ATT&CK coverage map + tactic gaps for the detection pack."""
        return self.detection.dmz.build_coverage()

    def lint_detections(self) -> Dict[str, Any]:
        """Static-lint every detection rule."""
        return self.detection.dmz.lint_all()

    def identity_risk_paths(self, path: Path) -> List[Dict[str, Any]]:
        """Scan a repo and derive cross-identity blast-radius risk paths."""
        identities = self.identity.scan(path, persist=True)
        return self.identity.adapter.derive_risk_paths(identities)

    def export_threat_intel(self, fmt: str) -> str:
        """Export stored threats as 'stix' or 'navigator'."""
        threats = self.db.list_threats(limit=1000)
        if fmt == "stix":
            return to_stix_bundle(threats)
        if fmt == "navigator":
            return to_attack_navigator_layer(threats)
        raise ValueError(f"unknown intel export format: {fmt}")
