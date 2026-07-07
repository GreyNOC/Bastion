"""Identity Blast Radius service.

Wraps the NHI adapter: scans a repo/project for non-human identities, persists
the masked results, and converts each into a universal ``BastionFinding``.
Full secrets never enter this pipeline — only masked previews and fingerprints.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ..adapters.nhi_adapter import NhiAdapter
from ..db import Database
from ..schemas import (
    BastionEvidence,
    BastionFinding,
    BastionIdentity,
    EvidenceKind,
    FindingCategory,
    ValidationStatus,
)
from ..utils.logging import get_logger


class IdentityBlastRadiusService:
    def __init__(self, db: Optional[Database] = None, adapter: Optional[NhiAdapter] = None):
        self.db = db
        self.adapter = adapter or NhiAdapter()
        self.log = get_logger("identity_blast_radius")

    def scan(self, path: Path, persist: bool = True) -> List[BastionIdentity]:
        identities = self.adapter.scan_repo(Path(path))
        self.log.info("identity scan of %s found %d non-human identities", path, len(identities))
        if persist and self.db:
            for i in identities:
                self.db.save_identity(i)
            self.db.save_findings(self.to_findings(identities))
        return identities

    def to_findings(self, identities: List[BastionIdentity]) -> List[BastionFinding]:
        findings: List[BastionFinding] = []
        for i in identities:
            ev = [BastionEvidence(
                kind=EvidenceKind.FILE_MATCH,
                summary=f"{i.detector}: {i.masked_preview or '(no value)'}",
                source=i.detector,
                location=f"{i.location}:{i.line}" if i.line else i.location,
            )]
            blast = ""
            if i.reachable_services:
                blast = " Blast radius: " + ", ".join(i.reachable_services) + "."
            if i.permission_chain:
                blast += " Chain: " + " -> ".join(i.permission_chain) + "."
            findings.append(BastionFinding(
                title=f"{i.name} ({i.provider or 'unknown provider'})",
                severity=i.severity,
                confidence=i.confidence,
                category=FindingCategory.IDENTITY,
                evidence=ev,
                source=self.adapter.source_repo,
                affected=f"{i.location}:{i.line}" if i.line else i.location,
                why_it_matters=(
                    f"A {i.identity_type.value.replace('_', ' ')} was found in source. "
                    f"If live, it grants automated access.{blast}"
                ),
                recommended_action=i.recommended_action,
                validation_status=ValidationStatus.NOT_APPLICABLE,
                false_positive_notes=i.false_positive_notes,
                ref_type="identity",
                ref_id=i.identity_id,
                tags=[i.identity_type.value] + (["privileged"] if i.privileged else []),
                metadata={
                    "masked_preview": i.masked_preview,
                    "secret_fingerprint": i.secret_fingerprint,
                    "provider": i.provider,
                    "liveness": "never tested (Bastion does not validate credentials)",
                },
            ))
        return findings
