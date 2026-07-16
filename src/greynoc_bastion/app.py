"""BastionApp — the composition root.

Wires config + database + adapters + services together. Everything else (CLI,
web server, tests) constructs a ``BastionApp`` and talks to it, so there is a
single place where wiring and safety defaults live.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters import PlaybooksAdapter
from .adapters.dmz_adapter import DmzAdapter
from .auth import OperatorStore
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
    CaseManagementService,
    DetectionValidationService,
    EvidenceCenter,
    IdentityBlastRadiusService,
    NotificationFabric,
    OrchestratorService,
    ReportCenter,
    SchedulerService,
    TelemetryIngestService,
    ThreatForecastService,
)
from .services.correlation import CorrelationService
from .services.threat_intel_export import to_attack_navigator_layer, to_stix_bundle
from .utils.logging import get_logger, setup_logging

__all__ = ["BastionApp"]


class BastionApp:
    def __init__(self, config: BastionConfig | None = None):
        self.config = config or load_config()
        setup_logging(self.config.log_level)
        self.log = get_logger("app")
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)

        # Services (constructed lazily-ish; cheap to build).
        self.threat_forecast = ThreatForecastService(self.db, config=self.config)
        self.identity = IdentityBlastRadiusService(self.db)
        self.detection = DetectionValidationService(
            self.db, dmz=DmzAdapter(custom_rules_dir=self.config.rules_dir),
        )
        self.assets = AssetExposureService(self.db)
        self.playbooks = PlaybooksAdapter()
        self.report_center = ReportCenter()
        self.evidence_center = EvidenceCenter()
        self.ai = AIAssistantService(self.config, self.db)
        self.correlation = CorrelationService(self.db)

        # Phase 2/3 services: cases, auth, telemetry replay, notifications,
        # workflows, schedules.
        self.cases = CaseManagementService(self.db)
        self.operators = OperatorStore(self.db)
        self.telemetry = TelemetryIngestService(self.db, self.detection.dmz)
        self.notifications = NotificationFabric(self.config, self.db)
        self.orchestrator = OrchestratorService(self)
        self.scheduler = SchedulerService(self)

    # --- status / health -----------------------------------------------------
    def safety_status(self) -> SafetyStatus:
        return build_safety_status(
            self.config,
            last_doctor_result=self.db.get_meta("last_doctor_result"),
            last_doctor_at=self.db.get_meta("last_doctor_at"),
        )

    def status(self) -> dict[str, Any]:
        from . import __product__, __version__
        return {
            "product": __product__,
            "version": __version__,
            "config": self.config.public_dict(),
            "counts": self.db.counts(),
            "safety_posture": self.safety_status().posture,
            "playbooks_available": len(self.playbooks._iter_files()),
            "timestamp": utcnow_iso(),
        }

    def doctor(self) -> dict[str, Any]:
        """Run self-checks and record the result for the Safety Status page."""
        checks: list[dict[str, Any]] = []

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
            check("detection_pack_validates", bool(results) and passing == len(results),
                  f"{passing}/{len(results)} rules pass")
        except Exception as exc:  # noqa: BLE001
            check("detection_pack_validates", False, str(exc))
        # 7) Secret masking active.
        from .safety.masking import mask_secret
        masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
        check("secret_masking_active", "*" in masked and "IOSFODNN7" not in masked, masked)
        # 8) The offline helper has no command runner in this build.
        check("offline_helper_command_runner_absent", True,
              f"legacy_flag={self.config.ai_command_execution}; implemented=false")

        ok = all(c["ok"] for c in checks)
        result = "ok" if ok else "issues-found"
        self.db.set_meta("last_doctor_result", result)
        self.db.set_meta("last_doctor_at", utcnow_iso())
        return {"ok": ok, "result": result, "checks": checks, "timestamp": utcnow_iso()}

    # --- playbooks -----------------------------------------------------------
    def list_playbooks(self) -> list[BastionPlaybook]:
        return self.playbooks.load_all()

    def get_playbook(self, slug: str) -> BastionPlaybook | None:
        return self.playbooks.get(slug)

    # --- report building -----------------------------------------------------
    def build_report(
        self,
        *,
        title: str = "GreyNOC Bastion — Consolidated Report",
        out_dir: Path | None = None,
        formats: list[ReportFormat] | None = None,
        include_bundle: bool = True,
    ) -> BastionReport:
        """Assemble all stored findings into a report and write it out."""
        out_dir = Path(out_dir) if out_dir else self.config.report_dir
        formats = formats or [
            ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON,
            ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.PDF,
        ]
        findings: list[BastionFinding] = self.db.list_findings(limit=None)
        modules = sorted({f.category.value for f in findings})
        report = BastionReport(title=title, modules=modules, findings=findings)
        report.recompute_summary()

        self.report_center.write(report, out_dir, formats)
        if include_bundle:
            self.evidence_center.build_bundle(report, out_dir)
        self.db.save_report(report)
        return report

    # --- full-capacity engine surfaces --------------------------------------
    def correlate(self) -> dict[str, Any]:
        """Build the cross-engine correlation view (clusters + coverage gaps)."""
        return self.correlation.build()

    def detection_coverage(self) -> dict[str, Any]:
        """ATT&CK coverage map + tactic gaps for the detection pack."""
        return self.detection.dmz.build_coverage()

    def lint_detections(self) -> dict[str, Any]:
        """Static-lint every detection rule."""
        return self.detection.dmz.lint_all()

    def load_custom_rules(self, rules_dir: Path | None = None) -> dict[str, Any]:
        """Load user detection rules (ReDoS-screened); persist accepted as DRAFTs.

        Accepted rules are stored as DRAFT detections — user rules are never
        auto-validated; they must pass the Detection Validation Range first.
        """
        target = Path(rules_dir) if rules_dir else self.config.rules_dir
        if not target:
            return {"accepted": [], "rejected": [], "accepted_count": 0, "rejected_count": 0,
                    "note": "no rules directory (set BASTION_RULES_DIR or pass --rules)"}
        self.detection.dmz.custom_rules_dir = Path(target)
        result = self.detection.dmz.load_custom_rules(Path(target))
        for rule in result.get("accepted", []):
            det = self.detection.dmz.rule_to_detection(rule)  # status stays DRAFT
            det.author = "custom"
            self.db.save_detection(det)
        if result.get("accepted") or result.get("rejected"):
            self.db.audit("load_custom_rules", actor="detections",
                          detail=f"accepted={result.get('accepted_count', 0)} "
                                 f"rejected={result.get('rejected_count', 0)}")
        return result

    def identity_risk_paths(self, path: Path) -> list[dict[str, Any]]:
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
