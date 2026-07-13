"""Case — a unit of tracked response work in the operator workqueue.

A case wraps one or more findings so a team can assign, annotate, and close
work with an audit trail. Cases never contain secrets: the linked findings
already carry masked evidence only, and case notes are scrubbed on write by
the service layer.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import CaseStatus, Severity


@dataclasses.dataclass
class CaseNote(BastionModel):
    """One timestamped, attributed annotation on a case."""

    author: str = "operator"
    text: str = ""
    at: str = dataclasses.field(default_factory=utcnow_iso)


@dataclasses.dataclass
class BastionCase(BastionModel):
    """A tracked piece of response work built from findings."""

    case_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("case"))
    title: str = ""
    status: CaseStatus = CaseStatus.OPEN
    severity: Severity = Severity.MEDIUM
    assignee: str = ""                      # empty = unassigned (in the workqueue)
    finding_ids: list[str] = dataclasses.field(default_factory=list)
    notes: list[CaseNote] = dataclasses.field(default_factory=list)
    created_by: str = "operator"
    created_at: str = dataclasses.field(default_factory=utcnow_iso)
    updated_at: str = dataclasses.field(default_factory=utcnow_iso)
    closed_at: str = ""
    close_reason: str = ""
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return self.status != CaseStatus.CLOSED

    def touch(self) -> None:
        self.updated_at = utcnow_iso()
