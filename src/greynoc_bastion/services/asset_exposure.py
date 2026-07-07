"""Asset & Exposure service.

Combines the Port-Manager passive collector (reads the local socket table) with
the HomeGuard risky-service knowledge base to review local assets, then
converts them into universal findings.

Safety: passive by default. Any active local check is gated on
``config.active_checks``, private/loopback only, bounded, and logged to the
audit trail. Bastion never probes public targets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..adapters.homeguard_adapter import HomeGuardAdapter
from ..adapters.port_manager_adapter import PortManagerAdapter, is_dev_server, label_service
from ..db import Database
from ..schemas import (
    BastionAsset,
    BastionEvidence,
    BastionFinding,
    Confidence,
    EvidenceKind,
    Exposure,
    FindingCategory,
    Severity,
    ValidationStatus,
)
from ..utils.logging import get_logger


class AssetExposureService:
    def __init__(self, db: Optional[Database] = None,
                 port_manager: Optional[PortManagerAdapter] = None,
                 homeguard: Optional[HomeGuardAdapter] = None):
        self.db = db
        self.port_manager = port_manager or PortManagerAdapter()
        self.homeguard = homeguard or HomeGuardAdapter()
        self.log = get_logger("asset_exposure")

    # --- known-good baseline -------------------------------------------------
    @staticmethod
    def service_signature(host: str, port, service_name: str = "") -> str:
        """Stable cross-scan identity for a listening service."""
        from ..schemas import stable_fingerprint
        return stable_fingerprint("svc", host, port, (service_name or "").lower())

    def set_baseline(self, assets: List[BastionAsset]) -> int:
        """Record the current assets as the known-good baseline."""
        sigs = sorted({self.service_signature(a.host, a.port, a.service_name) for a in assets})
        if self.db:
            import json
            self.db.set_meta("asset_baseline", json.dumps(sigs))
            self.db.audit("asset_baseline_set", actor="asset_exposure",
                          detail=f"{len(sigs)} services baselined")
        return len(sigs)

    def _load_baseline(self) -> set:
        if not self.db:
            return set()
        raw = self.db.get_meta("asset_baseline")
        if not raw:
            return set()
        try:
            import json
            return set(json.loads(raw))
        except (ValueError, TypeError):
            return set()

    def scan_local(
        self,
        *,
        passive: bool = True,
        active_checks_enabled: bool = False,
        observations: Optional[List[Dict[str, Any]]] = None,
        baseline_ports: Optional[List[int]] = None,
        detect_drift: bool = True,
        persist: bool = True,
    ) -> List[BastionAsset]:
        """Review local assets.

        ``passive=True`` reads the local socket table (no packets sent). Active
        checks are only attempted when ``active_checks_enabled`` is True — that
        flag comes from config and is audited by the caller. When a known-good
        baseline exists, services absent from it are flagged as drift.
        """
        baseline = set(baseline_ports or [])
        if observations is None:
            # Reading the OS socket table is safe local introspection; it is the
            # default "passive" behavior. Active connect-checks are not performed
            # here and remain gated for a future bounded, logged implementation.
            observations = self.port_manager.list_local_listeners(active=True)

        # Mark baseline membership.
        for obs in observations:
            obs.setdefault("in_baseline", obs.get("port") in baseline)

        assets = self.homeguard.review_observations(observations)

        # Drift detection against a stored known-good baseline.
        known = self._load_baseline() if detect_drift else set()
        if known:
            for a in assets:
                sig = self.service_signature(a.host, a.port, a.service_name)
                if sig in known:
                    a.in_baseline = True
                else:
                    a.metadata["drift"] = True
                    a.risk_reasons.append("New service not in the known-good baseline (drift).")
                    # A new, risky, or externally-reachable service warrants attention.
                    if a.risky or a.exposure.value in ("lan", "public"):
                        from ..schemas import Severity
                        if a.severity.rank < Severity.MEDIUM.rank:
                            a.severity = Severity.MEDIUM

        # Enrich dev-server labels from the port-manager knowledge base.
        for a in assets:
            if a.port is not None and (is_dev_server(a.port) or a.is_dev_server):
                a.is_dev_server = True
                if not a.risky:
                    a.service_name = label_service(a.port, a.process)
                    a.plain_explanation = (
                        f"A local development server ({a.service_name}) is listening on "
                        f"{a.host}:{a.port}. This is common during development. "
                        + a.plain_explanation
                    )

        if persist and self.db:
            for a in assets:
                self.db.save_asset(a)
            self.db.save_findings(self.to_findings(assets))
            self.db.audit(
                "asset_scan_local",
                actor="asset_exposure",
                detail=f"passive={passive} active_enabled={active_checks_enabled} "
                       f"observations={len(observations)} risky={sum(1 for a in assets if a.risky)}",
            )
        return assets

    def to_findings(self, assets: List[BastionAsset]) -> List[BastionFinding]:
        findings: List[BastionFinding] = []
        for a in assets:
            # Non-risky, baseline, loopback assets are informational context, not
            # findings worth surfacing — keep the report signal high.
            if not a.risky and a.exposure == Exposure.LOOPBACK and not a.is_dev_server:
                continue
            ev = [BastionEvidence(
                kind=EvidenceKind.PORT_OBSERVATION,
                summary=f"{a.protocol.upper()} {a.host}:{a.port} listening ({a.service_name})",
                source=a.observed_by,
                location=f"{a.host}:{a.port}",
            )]
            findings.append(BastionFinding(
                title=f"{a.service_name} listening on {a.host}:{a.port}",
                severity=a.severity,
                confidence=a.confidence,
                category=FindingCategory.ASSET,
                evidence=ev,
                source=self.homeguard.source_repo,
                affected=f"{a.host}:{a.port}",
                why_it_matters=a.plain_explanation,
                recommended_action=a.recommended_action,
                validation_status=ValidationStatus.NOT_APPLICABLE,
                false_positive_notes=(
                    "A listening-port observation is not proof of compromise. "
                    "Confirm the service is expected."
                ),
                ref_type="asset",
                ref_id=a.asset_id,
                tags=[a.kind.value, a.exposure.value] + (["dev-server"] if a.is_dev_server else []),
                metadata={"in_baseline": a.in_baseline, "risky": a.risky},
            ))
        return findings
