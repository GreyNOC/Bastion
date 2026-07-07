"""Detector-Engine adapter — the Threat Forecast intelligence brain.

Clean-room port of the defensive scoring/forecasting concepts from
GreyNOC/Detector-Engine: it parses standard feed formats (NVD 2.0 CVE, CISA
KEV, FIRST EPSS) from *fixtures by default* and turns them into ranked
``BastionThreat`` records with an explainable, glass-box score.

Nothing here fetches the network. Live ingestion, if ever enabled, must route
through ``safety.netguard`` — this adapter only parses already-obtained data.

Scoring is additive and explainable (0.0-1.0 per component), mirroring the
source engine's design goal that every number has named drivers.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from ..knowledge.ai_abuse import classify_ai_abuse
from ..knowledge.attack import infer_techniques
from ..knowledge.postquantum import hndl_exposure
from ..schemas import (
    BastionThreat,
    Confidence,
    Severity,
    ThreatCategory,
    ThreatForecast,
    ThreatScore,
    ValidationStatus,
)
from .base import BaseAdapter

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _coerce_float(value, default):
    """Coerce a possibly-string/None feed value to float, else ``default``."""
    if isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

# Product / exposure keywords that raise "public exposure" relevance because
# they typically sit at the network edge.
_EDGE_TERMS = (
    "gateway", "vpn", "firewall", "router", "citrix", "fortinet", "ivanti",
    "exchange", "owa", "adfs", "load balancer", "proxy", "webmail", "rdp",
    "remote", "internet-facing", "public",
)
# Exploit / weaponization signal terms lifted from advisory text.
_EXPLOIT_TERMS = (
    "exploited in the wild", "actively exploited", "public exploit",
    "proof of concept", "poc available", "remote code execution", "rce",
    "unauthenticated", "wormable", "pre-auth",
)


class DetectorEngineAdapter(BaseAdapter):
    source_repo = "GreyNOC/Detector-Engine"
    name = "detector_engine"

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        super().__init__()
        self.fixtures_dir = Path(fixtures_dir) if fixtures_dir else (
            Path(__file__).resolve().parents[1] / "fixtures" / "threat_feeds"
        )

    # --- feed parsing --------------------------------------------------------
    @staticmethod
    def _read_json(path: Path) -> Any:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def parse_cve_feed(self, data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Parse an NVD 2.0-style CVE feed into a dict keyed by CVE id."""
        out: dict[str, dict[str, Any]] = {}
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            cvss = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if arr:
                    cvss = _coerce_float(arr[0].get("cvssData", {}).get("baseScore"), None)
                    break
            cwes: list[str] = []
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    v = d.get("value", "")
                    if v.startswith("CWE-"):
                        cwes.append(v)
            products: list[str] = []
            for conf in cve.get("configurations", []):
                for node in conf.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        crit = m.get("criteria", "")
                        parts = crit.split(":")
                        if len(parts) > 4:
                            products.append(parts[4])
            out[cid.upper()] = {
                "id": cid.upper(),
                "description": desc,
                "cvss": cvss,
                "cwes": cwes,
                "products": sorted({p for p in products if p and p != "*"}),
                "published": cve.get("published", ""),
            }
        return out

    def parse_kev_feed(self, data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Parse a CISA KEV catalog into a dict keyed by CVE id."""
        out: dict[str, dict[str, Any]] = {}
        for v in data.get("vulnerabilities", []):
            cid = (v.get("cveID") or "").upper()
            if not cid:
                continue
            out[cid] = {
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "short_description": v.get("shortDescription", ""),
                "required_action": v.get("requiredAction", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "ransomware": (v.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
            }
        return out

    def parse_epss_feed(self, data: dict[str, Any]) -> dict[str, float]:
        """Parse a FIRST.org EPSS envelope into ``{cve: probability}``."""
        out: dict[str, float] = {}
        for row in data.get("data", []):
            cid = (row.get("cve") or "").upper()
            try:
                out[cid] = min(1.0, max(0.0, float(row.get("epss"))))  # clamp to [0,1]
            except (TypeError, ValueError):
                continue
        return out

    # --- scoring -------------------------------------------------------------
    def score_threat(
        self,
        cve: dict[str, Any],
        *,
        kev: dict[str, Any] | None = None,
        epss: float | None = None,
        sectors: list[str] | None = None,
    ) -> ThreatScore:
        """Compute an explainable multi-signal score for one CVE."""
        text = f"{cve.get('description', '')} {' '.join(cve.get('products', []))}".lower()

        cvss_raw = cve.get("cvss")
        cvss = float(cvss_raw) if isinstance(cvss_raw, (int, float)) else _coerce_float(cvss_raw, 0.0)
        evidence_strength = min(1.0, 0.4 + (0.6 if kev else 0.0) + (0.2 if epss is not None else 0.0))
        epss_clamped = min(1.0, max(0.0, float(epss))) if epss is not None else None
        exploit_likelihood = epss_clamped if epss_clamped is not None else min(1.0, cvss / 10.0 * 0.6)
        if any(t in text for t in _EXPLOIT_TERMS):
            exploit_likelihood = min(1.0, exploit_likelihood + 0.2)

        public_exposure = 0.2
        if any(t in text for t in _EDGE_TERMS):
            public_exposure = 0.85

        ransomware_relevance = 1.0 if (kev and kev.get("ransomware")) else (
            0.4 if "ransomware" in text else 0.0
        )
        sector_relevance = 0.5
        if sectors:
            hits = sum(1 for s in sectors if s.lower() in text)
            sector_relevance = min(1.0, 0.5 + 0.25 * hits)

        # Remediation priority favors edge + high CVSS + KEV due dates.
        remediation_priority = min(
            1.0,
            0.3 + (cvss / 10.0) * 0.4 + (0.3 if kev else 0.0),
        )

        # Fused urgency: KEV is a hard boost; exploit likelihood and exposure
        # dominate; ransomware and remediation priority add weight.
        urgency = (
            0.30 * exploit_likelihood
            + 0.20 * public_exposure
            + 0.15 * (cvss / 10.0)
            + 0.15 * ransomware_relevance
            + 0.10 * remediation_priority
            + 0.10 * evidence_strength
        )
        if kev:
            urgency = min(1.0, urgency + 0.15)
        urgency = round(min(1.0, urgency), 4)

        return ThreatScore(
            urgency=urgency,
            evidence_strength=round(evidence_strength, 4),
            confidence=round(evidence_strength, 4),
            exploit_likelihood=round(exploit_likelihood, 4),
            sector_relevance=round(sector_relevance, 4),
            ransomware_relevance=round(ransomware_relevance, 4),
            public_exposure=round(public_exposure, 4),
            remediation_priority=round(remediation_priority, 4),
            kev_listed=bool(kev),
        )

    @staticmethod
    def _severity_from_score(score: ThreatScore, cvss: float | None) -> Severity:
        u = score.urgency
        if score.kev_listed and u >= 0.6:
            return Severity.CRITICAL
        if u >= 0.8:
            return Severity.CRITICAL
        if u >= 0.6:
            return Severity.HIGH
        if u >= 0.4:
            return Severity.MEDIUM
        if u >= 0.2:
            return Severity.LOW
        return Severity.INFO

    def forecast_exploit_timing(self, score: ThreatScore, *, kev: bool) -> ThreatForecast:
        """Model time-to-exploitation from the scored signals (hazard-style).

        Deterministic and explainable: KEV means already-exploited (horizon 0);
        otherwise a "pressure" blend of exploit likelihood, exposure, CVSS, and
        remediation priority compresses the predicted horizon and raises the
        exploitation probability.
        """
        drivers: list[str] = []
        if kev:
            return ThreatForecast(
                exploit_probability=0.97,
                horizon_days_p50=0,
                horizon_days_p90=0,
                confidence=0.9,
                window="already_exploited",
                drivers=["On CISA KEV — exploitation already observed in the wild"],
            )

        # Pressure in [0,1]: what accelerates exploitation.
        pressure = min(1.0, (
            0.45 * score.exploit_likelihood
            + 0.25 * score.public_exposure
            + 0.20 * (score.exploit_likelihood if score.exploit_likelihood else 0.0)
            + 0.10 * score.remediation_priority
        ))
        # A ransomware-relevant, exposed CVE gets extra pressure.
        if score.ransomware_relevance >= 1.0:
            pressure = min(1.0, pressure + 0.15)
            drivers.append("Known ransomware use accelerates weaponization")
        if score.exploit_likelihood >= 0.5:
            drivers.append(f"High modeled exploit likelihood ({score.exploit_likelihood:.0%})")
        if score.public_exposure >= 0.8:
            drivers.append("Internet-facing / edge product class")

        # Horizon compresses with pressure; probability rises with it.
        p50 = int(round((1.0 - pressure) * 90))
        p90 = int(round((1.0 - pressure) * 180))
        exploit_probability = round(min(0.95, 0.15 + 0.8 * pressure), 3)
        confidence = round(min(0.85, 0.35 + 0.5 * score.evidence_strength), 3)

        if p50 <= 7:
            window = "imminent"
        elif p50 <= 30:
            window = "near_term"
        elif p50 <= 90:
            window = "medium_term"
        else:
            window = "low"
        if not drivers:
            drivers.append(f"Blended exploitation pressure {pressure:.0%}")

        return ThreatForecast(
            exploit_probability=exploit_probability,
            horizon_days_p50=p50,
            horizon_days_p90=p90,
            confidence=confidence,
            window=window,
            drivers=drivers,
        )

    def build_threats(
        self,
        cves: dict[str, dict[str, Any]],
        kev: dict[str, dict[str, Any]] | None = None,
        epss: dict[str, float] | None = None,
        sectors: list[str] | None = None,
    ) -> list[BastionThreat]:
        """Correlate feeds and produce ranked BastionThreat records."""
        kev = kev or {}
        epss = epss or {}
        threats: list[BastionThreat] = []
        for cid, cve in cves.items():
            kev_rec = kev.get(cid)
            epss_val = epss.get(cid)
            score = self.score_threat(cve, kev=kev_rec, epss=epss_val, sectors=sectors)
            sev = self._severity_from_score(score, cve.get("cvss"))

            category = ThreatCategory.KEV if kev_rec else ThreatCategory.CVE
            if score.ransomware_relevance >= 1.0:
                category = ThreatCategory.RANSOMWARE

            drivers: list[str] = []
            if kev_rec:
                drivers.append("Listed on CISA KEV (known exploited)")
            if epss_val is not None:
                drivers.append(f"EPSS exploit probability {epss_val:.0%}")
            if score.public_exposure >= 0.8:
                drivers.append("Affects an internet-facing / edge product class")
            if score.ransomware_relevance >= 1.0:
                drivers.append("Known ransomware campaign use")
            if cve.get("cvss"):
                drivers.append(f"CVSS base score {cve['cvss']}")

            # --- enrichment layers (full capacity) ---
            full_text = f"{cve.get('description', '')} {(kev_rec or {}).get('name', '')}"
            techniques = infer_techniques(full_text)
            ai_abuse = classify_ai_abuse(full_text)
            pqc = hndl_exposure(full_text)
            forecast = self.forecast_exploit_timing(score, kev=bool(kev_rec))

            if ai_abuse:
                category = ThreatCategory.AI_ABUSE
                drivers.append("AI/LLM abuse category: " + ", ".join(a["label"] for a in ai_abuse))
            if pqc:
                drivers.append("Post-quantum exposure: "
                               + ", ".join(cast("list[str]", pqc.get("vulnerable_primitives", []) or [])))
            if forecast.window == "already_exploited":
                drivers.insert(0, "Forecast: exploitation already observed (KEV)")
            elif forecast.horizon_days_p50 is not None:
                drivers.append(
                    f"Forecast: ~{forecast.horizon_days_p50}d to likely exploitation "
                    f"(p={forecast.exploit_probability:.0%}, {forecast.window.replace('_', ' ')})"
                )

            title = (kev_rec or {}).get("name") or f"{cid}: {(cve.get('description') or '')[:80]}"
            threat = BastionThreat(
                threat_id=cid,
                category=category,
                title=title.strip(),
                summary=cve.get("description", ""),
                cve_ids=[cid],
                cwe_ids=cve.get("cwes", []),
                attack_techniques=techniques,
                affected_products=cve.get("products", []),
                severity=sev,
                confidence=Confidence.HIGH if kev_rec else Confidence.MEDIUM,
                score=score,
                epss=epss_val,
                cvss=cve.get("cvss"),
                kev=bool(kev_rec),
                ransomware_used=bool(kev_rec and kev_rec.get("ransomware")),
                sectors=sectors or [],
                remediation=(kev_rec or {}).get("required_action", "")
                or "Prioritize patching per vendor guidance; restrict exposure of affected service.",
                forecast=forecast,
                ai_abuse=ai_abuse,
                pqc_risk=pqc,
                draft_detection=(
                    f"DRAFT: alert on exploitation indicators for {cid} "
                    f"({', '.join(cve.get('products', []) or ['affected product'])})."
                ),
                detection_status=ValidationStatus.DRAFT,
                source=self.source_repo,
                metadata={"drivers": drivers},
            )
            threats.append(threat)
        # Rank by urgency, then by forecast probability, then severity.
        threats.sort(
            key=lambda t: (t.score.urgency,
                           t.forecast.exploit_probability if t.forecast else 0.0,
                           t.severity.rank),
            reverse=True,
        )
        return threats

    # --- high-level entry points --------------------------------------------
    def forecast_from_fixtures(self, sectors: list[str] | None = None) -> list[BastionThreat]:
        """Build a ranked forecast from the bundled offline fixtures."""
        cves = self.parse_cve_feed(self._read_json(self.fixtures_dir / "cve_sample.json"))
        kev = self.parse_kev_feed(self._read_json(self.fixtures_dir / "kev_sample.json"))
        epss = self.parse_epss_feed(self._read_json(self.fixtures_dir / "epss_sample.json"))
        # EPSS carries CVEs not in the CVE fixture; add lightweight stubs so
        # they still get ranked (demonstrates correlation across feeds).
        for cid in epss:
            if cid not in cves:
                cves[cid] = {"id": cid, "description": f"{cid} (EPSS-only record)",
                             "cvss": None, "cwes": [], "products": []}
        return self.build_threats(cves, kev, epss, sectors)

    def forecast_from_path(self, path: Path, sectors: list[str] | None = None) -> list[BastionThreat]:
        """Build a forecast from a single CVE-feed JSON file (offline)."""
        path = Path(path)
        data = self._read_json(path)
        cves = self.parse_cve_feed(data)
        # Opportunistically pick up sibling KEV/EPSS fixtures if present.
        kev: dict[str, dict[str, Any]] = {}
        epss: dict[str, float] = {}
        sib_kev = path.with_name("kev_sample.json")
        sib_epss = path.with_name("epss_sample.json")
        if sib_kev.is_file():
            kev = self.parse_kev_feed(self._read_json(sib_kev))
        if sib_epss.is_file():
            epss = self.parse_epss_feed(self._read_json(sib_epss))
        return self.build_threats(cves, kev, epss, sectors)
