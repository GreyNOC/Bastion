"""BastionThreat — a ranked threat intelligence record (Threat Forecast)."""

from __future__ import annotations

import dataclasses
from typing import Any

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import Confidence, Severity, ThreatCategory, ValidationStatus


@dataclasses.dataclass
class ThreatScore(BastionModel):
    """The multi-signal score behind a threat's ranking.

    Each component is a 0.0-1.0 normalized signal. ``urgency`` is the blended
    result the forecast sorts on; it is computed by the scorer, not fetched.
    """

    urgency: float = 0.0
    evidence_strength: float = 0.0
    confidence: float = 0.0
    exploit_likelihood: float = 0.0        # EPSS-like probability
    sector_relevance: float = 0.0
    ransomware_relevance: float = 0.0
    public_exposure: float = 0.0
    remediation_priority: float = 0.0
    kev_listed: bool = False               # on CISA KEV -> hard urgency boost

    def as_components(self) -> dict[str, float]:
        return {
            "evidence_strength": self.evidence_strength,
            "exploit_likelihood": self.exploit_likelihood,
            "sector_relevance": self.sector_relevance,
            "ransomware_relevance": self.ransomware_relevance,
            "public_exposure": self.public_exposure,
            "remediation_priority": self.remediation_priority,
        }


@dataclasses.dataclass
class ThreatForecast(BastionModel):
    """A time-to-exploitation forecast — the predictive layer of the engine.

    ``exploit_probability`` is the modeled chance of exploitation within the
    horizon; ``horizon_days_p50``/``p90`` are the predicted time-to-exploit
    (0 when already exploited). ``window`` is a plain label for triage.
    """

    exploit_probability: float = 0.0
    horizon_days_p50: int | None = None
    horizon_days_p90: int | None = None
    confidence: float = 0.0
    window: str = "unknown"                 # already_exploited|imminent|near_term|medium_term|low
    drivers: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class BastionThreat(BastionModel):
    """A single threat the forecast ranks and explains."""

    threat_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("thr"))
    category: ThreatCategory = ThreatCategory.OTHER
    title: str = ""
    summary: str = ""

    # Common intel identifiers (any subset may be present).
    cve_ids: list[str] = dataclasses.field(default_factory=list)
    cwe_ids: list[str] = dataclasses.field(default_factory=list)
    attack_techniques: list[str] = dataclasses.field(default_factory=list)  # ATT&CK Txxxx
    affected_products: list[str] = dataclasses.field(default_factory=list)
    references: list[str] = dataclasses.field(default_factory=list)

    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    score: ThreatScore = dataclasses.field(default_factory=ThreatScore)

    epss: float | None = None           # raw EPSS probability if known
    cvss: float | None = None           # raw CVSS base score if known
    kev: bool = False                      # listed on CISA KEV
    ransomware_used: bool = False          # known ransomware use

    sectors: list[str] = dataclasses.field(default_factory=list)
    remediation: str = ""

    # Predictive + enrichment layers (full-capacity forecast).
    forecast: ThreatForecast | None = None
    ai_abuse: list[dict[str, str]] = dataclasses.field(default_factory=list)  # AI-abuse categories
    pqc_risk: dict[str, Any] | None = None                                 # HNDL / PQC assessment
    iocs: list[dict[str, str]] = dataclasses.field(default_factory=list)      # indicators of compromise

    # A generated detection idea stays a DRAFT until validated in the Range.
    draft_detection: str | None = None
    detection_status: ValidationStatus = ValidationStatus.DRAFT

    source: str = ""
    first_seen: str = dataclasses.field(default_factory=utcnow_iso)
    last_updated: str = dataclasses.field(default_factory=utcnow_iso)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
