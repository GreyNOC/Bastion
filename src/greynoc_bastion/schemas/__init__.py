"""Shared Bastion schemas.

One clean vocabulary used by every module, adapter, service, and report. Import
from here rather than the submodules::

    from greynoc_bastion.schemas import BastionFinding, Severity
"""

from __future__ import annotations

from .asset import BastionAsset
from .base import (
    BastionModel,
    new_correlation_id,
    stable_correlation_id,
    stable_fingerprint,
    utcnow_iso,
)
from .case import BastionCase, CaseNote
from .detection import BastionDetection, BastionValidationResult
from .enums import (
    AssetKind,
    CaseStatus,
    Confidence,
    EvidenceKind,
    Exposure,
    FindingCategory,
    IdentityType,
    OperatorRole,
    ReportFormat,
    Severity,
    ThreatCategory,
    ValidationStatus,
)
from .evidence import BastionEvidence
from .finding import BastionFinding
from .identity import BastionIdentity
from .playbook import BastionPlaybook, PlaybookStep
from .report import BastionReport, ReportSummary
from .threat import BastionThreat, ThreatForecast, ThreatScore

__all__ = [
    # base helpers
    "BastionModel",
    "new_correlation_id",
    "stable_correlation_id",
    "stable_fingerprint",
    "utcnow_iso",
    # enums
    "AssetKind",
    "CaseStatus",
    "Confidence",
    "EvidenceKind",
    "Exposure",
    "FindingCategory",
    "IdentityType",
    "OperatorRole",
    "ReportFormat",
    "Severity",
    "ThreatCategory",
    "ValidationStatus",
    # models
    "BastionAsset",
    "BastionCase",
    "CaseNote",
    "BastionDetection",
    "BastionEvidence",
    "BastionFinding",
    "BastionIdentity",
    "BastionPlaybook",
    "PlaybookStep",
    "BastionReport",
    "ReportSummary",
    "BastionThreat",
    "ThreatForecast",
    "ThreatScore",
    "BastionValidationResult",
]
