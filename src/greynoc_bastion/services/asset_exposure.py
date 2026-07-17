"""Asset & Exposure service.

Combines the Port-Manager passive collector (reads the local socket table) with
the HomeGuard risky-service knowledge base to review local assets, then
converts them into universal findings.

Safety: passive by default. Any active local check is gated on
``config.active_checks``, private/loopback only, bounded, and logged to the
audit trail. Bastion never probes public targets.
"""

from __future__ import annotations

from typing import Any

from ..adapters.base import guarded_call
from ..adapters.homeguard_adapter import HomeGuardAdapter
from ..adapters.port_manager_adapter import PortManagerAdapter, is_dev_server, label_service
from ..db import Database
from ..schemas import (
    BastionAsset,
    BastionEvidence,
    BastionFinding,
    EvidenceKind,
    Exposure,
    FindingCategory,
    ValidationStatus,
    stable_correlation_id,
)
from ..utils.logging import get_logger


class AssetExposureService:
    def __init__(self, db: Database | None = None,
                 port_manager: PortManagerAdapter | None = None,
                 homeguard: HomeGuardAdapter | None = None):
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

    def set_baseline(self, assets: list[BastionAsset]) -> int:
        """Record the current assets as the known-good baseline."""
        sigs = sorted({self.service_signature(a.host, a.port, a.service_name) for a in assets})
        if self.db:
            import json
            self.db.set_meta("asset_baseline", json.dumps(sigs))
            self.db.audit("asset_baseline_set", actor="asset_exposure",
                          detail=f"{len(sigs)} services baselined")
        return len(sigs)

    def _confirm_loopback(self, assets: list[BastionAsset]) -> None:
        """Bounded, loopback-only liveness confirmation for observed services.

        For each service already observed on ``127.0.0.1`` / ``::1``, attempt a
        single short TCP connect to confirm it is actually accepting connections
        on this machine. This is deliberately limited: loopback addresses only
        (never LAN or public — that would be network scanning), only ports we
        already saw in the socket table, and a sub-second timeout. It is a
        defensive check of *your own* local services, opt-in and audit-logged.
        """
        import socket
        _LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::"}  # nosec B104 - set of loopback/any labels for comparison, not a bind
        for a in assets:
            host = a.host
            # 0.0.0.0/:: means "all interfaces"; confirm via loopback.
            connect_host = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host  # nosec B104 - resolving to loopback for a local liveness check
            if connect_host not in {"127.0.0.1", "::1", "localhost"} or a.port is None:
                a.metadata["active_confirmed"] = "skipped (not loopback)"
                continue
            try:
                with socket.create_connection((connect_host, int(a.port)), timeout=0.3):
                    a.metadata["active_confirmed"] = True
            except OSError:
                a.metadata["active_confirmed"] = False
            a.observed_by = "active-local"

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
        active: bool = False,
        active_checks_enabled: bool = False,
        observations: list[dict[str, Any]] | None = None,
        baseline_ports: list[int] | None = None,
        detect_drift: bool = True,
        persist: bool = True,
    ) -> list[BastionAsset]:
        """Review local assets.

        Default (``passive``) reads the local socket table — no packets are sent.
        ``active=True`` additionally performs a bounded, loopback-only liveness
        confirmation (a short connect to each observed ``127.0.0.1``/``::1``
        listener). Active mode is opt-in, private/local only, and audit-logged;
        the caller must have already checked ``config.active_checks``. When a
        known-good baseline exists, services absent from it are flagged as drift.
        """
        baseline = set(baseline_ports or [])
        if observations is None:
            # Reading the OS socket table is safe local introspection.
            observations = guarded_call(
                self.port_manager, self.port_manager.list_local_listeners, active=True,
            )

        # Mark baseline membership.
        for obs in observations:
            obs.setdefault("in_baseline", obs.get("port") in baseline)

        assets = guarded_call(
            self.homeguard, self.homeguard.review_observations, observations,
        )

        # Active mode: bounded, loopback-only liveness confirmation.
        if active:
            self._confirm_loopback(assets)

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
                detail=f"mode={'active-local' if active else 'passive'} "
                       f"observations={len(observations)} risky={sum(1 for a in assets if a.risky)}",
            )
        return assets

    def to_findings(self, assets: list[BastionAsset]) -> list[BastionFinding]:
        findings: list[BastionFinding] = []
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
                correlation_id=stable_correlation_id("fnd", "asset", a.asset_id),
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
