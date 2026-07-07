"""BastionPlaybook — an operator doctrine document with an execution checklist."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List

from .base import BastionModel, utcnow_iso
from .enums import Severity


@dataclasses.dataclass
class PlaybookStep(BastionModel):
    """One checklist step. Steps are guidance, never auto-executed."""

    order: int = 0
    title: str = ""
    detail: str = ""
    phase: str = ""                         # detect | triage | contain | eradicate | recover
    done: bool = False


@dataclasses.dataclass
class BastionPlaybook(BastionModel):
    """A defensive playbook parsed from the doctrine layer.

    Playbooks are read-only doctrine plus a checklist an operator can work
    through. They describe how to *defend against* a technique — never how to
    perform it.
    """

    slug: str = ""                          # file-stem id, e.g. 01-password-spraying
    name: str = ""
    category: str = ""                      # identity, ransomware, pqc, ...
    summary: str = ""
    severity: Severity = Severity.MEDIUM

    attack_techniques: List[str] = dataclasses.field(default_factory=list)
    data_sources: List[str] = dataclasses.field(default_factory=list)
    related_detections: List[str] = dataclasses.field(default_factory=list)
    related_playbooks: List[str] = dataclasses.field(default_factory=list)

    detection_guidance: str = ""
    response_steps: List[PlaybookStep] = dataclasses.field(default_factory=list)
    references: List[str] = dataclasses.field(default_factory=list)

    source_path: str = ""
    body_markdown: str = ""                 # full doctrine text for the reader
    updated_at: str = dataclasses.field(default_factory=utcnow_iso)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
