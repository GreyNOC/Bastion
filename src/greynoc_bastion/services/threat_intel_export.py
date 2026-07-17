"""Threat-intel exporters: STIX 2.1 bundle and ATT&CK Navigator layer.

Zero-dependency, deterministic transforms of ranked ``BastionThreat`` records
into two standard interchange formats so Bastion's forecast can feed other
defensive tooling. No network; pure serialization.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from ..knowledge.attack import tactic_for_technique, technique_name
from ..schemas import BastionThreat, utcnow_iso

# Fixed namespace so STIX ids are stable/reproducible across runs for the same
# input (deterministic uuid5 rather than random uuid4).
_NS = uuid.UUID("6f3c8b2e-0000-4000-8000-a1b2c3d4e5f6")


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + key)}"


def to_stix_bundle(threats: list[BastionThreat]) -> str:
    """Render threats as a STIX 2.1 bundle (vulnerability + attack-pattern SDOs)."""
    now = utcnow_iso().replace("Z", ".000Z")
    objects: list[dict[str, Any]] = []
    seen_patterns: set = set()

    for t in threats:
        vuln_id = _sid("vulnerability", t.threat_id)
        ext_refs = [{"source_name": "cve", "external_id": c} for c in t.cve_ids]
        for url in t.references[:5]:
            ext_refs.append({"source_name": "reference", "url": url})
        vuln = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now,
            "modified": now,
            "name": t.title or (t.cve_ids[0] if t.cve_ids else t.threat_id),
            "description": t.summary,
            "external_references": ext_refs or [{"source_name": "greynoc-bastion", "external_id": t.threat_id}],
            "x_greynoc_severity": t.severity.value,
            "x_greynoc_kev": t.kev,
            "x_greynoc_epss": t.epss,
            "x_greynoc_cvss": t.cvss,
            "x_greynoc_urgency": t.score.urgency,
        }
        if t.forecast:
            vuln["x_greynoc_forecast"] = {
                "epss_probability_30d": t.forecast.exploit_probability,
                "probability_horizon_days": t.forecast.probability_horizon_days,
                "horizon_days_p50": t.forecast.horizon_days_p50,
                "horizon_days_p90": t.forecast.horizon_days_p90,
                "status": t.forecast.status,
                "method": t.forecast.method,
                "assumptions": t.forecast.assumptions,
                "window": t.forecast.window,
            }
        objects.append(vuln)

        # attack-pattern SDOs + relationships to the vulnerability.
        for tech in t.attack_techniques:
            ap_id = _sid("attack-pattern", tech)
            if tech not in seen_patterns:
                seen_patterns.add(tech)
                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "name": technique_name(tech),
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tech,
                        "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/",
                    }],
                })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _sid("relationship", f"{t.threat_id}:{tech}"),
                "created": now,
                "modified": now,
                "relationship_type": "targets",
                "source_ref": ap_id,
                "target_ref": vuln_id,
            })

    bundle = {"type": "bundle", "id": _sid("bundle", "greynoc-forecast"), "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)


def to_attack_navigator_layer(threats: list[BastionThreat],
                              name: str = "GreyNOC Bastion — Threat Forecast") -> str:
    """Render an ATT&CK Navigator layer colored by max urgency per technique."""
    scores: dict[str, float] = {}
    comments: dict[str, list[str]] = {}
    for t in threats:
        urg = t.score.urgency
        for tech in t.attack_techniques:
            if urg > scores.get(tech, -1.0):
                scores[tech] = urg
            comments.setdefault(tech, []).append(
                f"{t.cve_ids[0] if t.cve_ids else t.threat_id} ({t.severity.value})")

    def color_for(u: float) -> str:
        if u >= 0.8:
            return "#ff4d4f"
        if u >= 0.6:
            return "#ff9f43"
        if u >= 0.4:
            return "#ffd93d"
        return "#4dc9ff"

    techniques = [{
        "techniqueID": tech,
        "score": round(u * 100),
        "color": color_for(u),
        "comment": "; ".join(comments.get(tech, [])[:6]),
        "enabled": True,
        "metadata": [{"name": "tactic", "value": tactic_for_technique(tech) or "unknown"}],
    } for tech, u in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)]

    layer = {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques associated with Bastion-forecasted threats, colored by urgency.",
        "techniques": techniques,
        "gradient": {"colors": ["#4dc9ff", "#ffd93d", "#ff4d4f"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "critical urgency", "color": "#ff4d4f"},
            {"label": "high", "color": "#ff9f43"},
            {"label": "medium", "color": "#ffd93d"},
            {"label": "lower", "color": "#4dc9ff"},
        ],
    }
    return json.dumps(layer, indent=2, ensure_ascii=False)
