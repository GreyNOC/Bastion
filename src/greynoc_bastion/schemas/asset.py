"""BastionAsset — a local asset reviewed by Assets & Exposure."""

from __future__ import annotations

import dataclasses
from typing import Any

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import AssetKind, Confidence, Exposure, Severity


@dataclasses.dataclass
class BastionAsset(BastionModel):
    """A local host / port / service / device under review.

    All active checks that populate this record are private/loopback-only,
    opt-in, bounded, and logged. Passive review is the default.
    """

    asset_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("ast"))
    kind: AssetKind = AssetKind.SERVICE
    label: str = ""

    host: str = "127.0.0.1"
    port: int | None = None
    protocol: str = ""                      # tcp/udp
    process: str = ""                       # owning process if known (passive)
    service_name: str = ""                  # http, ssh, rdp, smb, ...

    exposure: Exposure = Exposure.LOOPBACK
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    risky: bool = False
    risk_reasons: list[str] = dataclasses.field(default_factory=list)

    plain_explanation: str = ""             # plain-English "what this is"
    recommended_action: str = ""            # safe, local-only remediation guidance
    in_baseline: bool = False               # matches a known-good baseline entry
    is_dev_server: bool = False

    observed_by: str = "passive"            # passive | active-local
    first_seen: str = dataclasses.field(default_factory=utcnow_iso)
    last_seen: str = dataclasses.field(default_factory=utcnow_iso)
    correlation_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("fnd"))
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
