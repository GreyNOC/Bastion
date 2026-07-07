"""Correlation spine — links records across engines into one picture.

This is what makes Bastion a console rather than seven silos. It extracts a
shared join vocabulary (ATT&CK techniques, CVEs, hosts, providers) from every
stored record and builds correlation clusters, plus the highest-value defensive
insight: **which forecasted threats have no validated detection coverage**, and
which playbook applies.

Deterministic and local — pure joins over already-stored records, no network.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from ..db import Database
from ..knowledge.attack import tactic_for_technique, technique_name
from ..schemas import ValidationStatus, stable_fingerprint, utcnow_iso
from ..utils.logging import get_logger


@dataclasses.dataclass
class CorrelationCluster:
    """A set of cross-engine records that share a join entity."""

    cluster_id: str
    entity_type: str                 # "technique" | "host" | "provider"
    entity_value: str
    label: str
    severity: str = "info"
    threats: list[str] = dataclasses.field(default_factory=list)
    detections: list[str] = dataclasses.field(default_factory=list)
    playbooks: list[str] = dataclasses.field(default_factory=list)
    assets: list[str] = dataclasses.field(default_factory=list)
    identities: list[str] = dataclasses.field(default_factory=list)
    narrative: str = ""
    coverage_gap: bool = False       # forecasted/relevant but no validated detection

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @property
    def span(self) -> int:
        """How many distinct engines this cluster spans (1-5)."""
        return sum(bool(x) for x in (self.threats, self.detections, self.playbooks,
                                     self.assets, self.identities))


class CorrelationService:
    def __init__(self, db: Database):
        self.db = db
        self.log = get_logger("correlation")

    def build(self) -> dict[str, Any]:
        """Build correlation clusters from all stored records."""
        threats = self.db.list_threats(limit=1000)
        detections = self.db.list_detections(limit=1000)
        validations = self.db.list_validations(limit=2000)
        playbooks = self.db.list_playbooks(limit=1000)
        if not playbooks:
            # Playbooks are file-backed doctrine; load them if not persisted.
            from ..adapters.playbooks_adapter import PlaybooksAdapter
            playbooks = PlaybooksAdapter().load_all()
        assets = self.db.list_assets(limit=2000)

        # Which detections are validated (covered)?
        validated_ids = {
            v.detection_id for v in validations
            if v.passed or v.verdict == ValidationStatus.VALIDATED
        }

        # --- technique index across engines ---
        tech_threats: dict[str, list] = {}
        tech_detections: dict[str, list] = {}
        tech_playbooks: dict[str, list] = {}
        for t in threats:
            for tech in t.attack_techniques:
                tech_threats.setdefault(tech, []).append(t)
        for d in detections:
            for tech in d.attack_techniques:
                tech_detections.setdefault(tech, []).append(d)
        for p in playbooks:
            for tech in p.attack_techniques:
                tech_playbooks.setdefault(tech, []).append(p)

        clusters: list[CorrelationCluster] = []
        all_techs = set(tech_threats) | set(tech_detections) | set(tech_playbooks)
        for tech in sorted(all_techs):
            t_threats = tech_threats.get(tech, [])
            t_dets = tech_detections.get(tech, [])
            t_pbs = tech_playbooks.get(tech, [])
            # Only surface a cluster that actually links >1 engine, OR a threat
            # with no detection (the coverage-gap case worth flagging).
            has_validated_detection = any(d.detection_id in validated_ids for d in t_dets)
            spans = sum(bool(x) for x in (t_threats, t_dets, t_pbs))
            gap = bool(t_threats) and not has_validated_detection
            if spans < 2 and not gap:
                continue
            sev = _max_sev([t.severity.value for t in t_threats] or ["info"])
            cluster = CorrelationCluster(
                cluster_id=f"cor-{stable_fingerprint('technique', tech)}",
                entity_type="technique",
                entity_value=tech,
                label=f"{tech} — {technique_name(tech)}",
                severity=sev,
                threats=[t.threat_id for t in t_threats],
                detections=[d.detection_id for d in t_dets],
                playbooks=[p.slug for p in t_pbs],
                coverage_gap=gap,
                narrative=self._technique_narrative(tech, t_threats, t_dets, t_pbs,
                                                    has_validated_detection),
            )
            clusters.append(cluster)

        # --- host index (assets <-> detection surface) ---
        host_assets: dict[str, list] = {}
        for a in assets:
            if a.risky or a.exposure.value in ("lan", "public"):
                host_assets.setdefault(a.host, []).append(a)
        for host, a_list in host_assets.items():
            if not host:
                continue
            clusters.append(CorrelationCluster(
                cluster_id=f"cor-{stable_fingerprint('host', host)}",
                entity_type="host",
                entity_value=host,
                label=f"Host {host}",
                severity=_max_sev([a.severity.value for a in a_list]),
                assets=[a.asset_id for a in a_list],
                narrative=(
                    f"{len(a_list)} reviewed service(s) on {host}: "
                    + ", ".join(sorted({a.service_name for a in a_list}))
                    + ". Monitor with network/auth detections."
                ),
            ))

        clusters.sort(key=lambda c: (c.coverage_gap, c.span, _SEV_ORDER.get(c.severity, 0)), reverse=True)
        gaps = [c for c in clusters if c.coverage_gap]

        return {
            "generated_at": utcnow_iso(),
            "cluster_count": len(clusters),
            "cross_engine_clusters": sum(1 for c in clusters if c.span >= 2),
            "coverage_gaps": len(gaps),
            "clusters": [c.to_dict() for c in clusters],
            "summary": self._summary(clusters, gaps),
        }

    def _technique_narrative(self, tech, threats, dets, pbs, has_validated) -> str:
        parts: list[str] = []
        name = technique_name(tech)
        tac = tactic_for_technique(tech)
        if threats:
            cves = sorted({c for t in threats for c in t.cve_ids})[:4]
            parts.append(f"Forecasted via {len(threats)} threat(s)"
                         + (f" ({', '.join(cves)})" if cves else ""))
        if dets:
            status = "validated" if has_validated else "drafted/unvalidated"
            parts.append(f"{len(dets)} detection(s), {status}")
        else:
            parts.append("no detection in the pack")
        if pbs:
            parts.append(f"playbook: {pbs[0].name}")
        lead = f"{tech} ({name}"
        lead += f", {tac})" if tac else ")"
        tail = "."
        if threats and not has_validated:
            tail = " — COVERAGE GAP: a forecasted technique with no validated detection."
        return lead + ": " + "; ".join(parts) + tail

    @staticmethod
    def _summary(clusters, gaps) -> str:
        if not clusters:
            return "No cross-engine correlations yet. Run the modules to populate the console."
        top_gap = gaps[0].label if gaps else None
        s = (f"{len(clusters)} correlation clusters across engines; "
             f"{sum(1 for c in clusters if c.span >= 2)} span multiple engines.")
        if gaps:
            s += (f" {len(gaps)} coverage gap(s): forecasted techniques with no validated "
                  f"detection (e.g. {top_gap}). Prioritize building/validating those detections.")
        else:
            s += " No coverage gaps: every forecasted technique has a validated detection."
        return s


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_sev(values: list[str]) -> str:
    best = "info"
    for v in values:
        if _SEV_ORDER.get(v, 0) > _SEV_ORDER.get(best, 0):
            best = v
    return best
