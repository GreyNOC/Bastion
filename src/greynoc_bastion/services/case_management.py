"""Case management — assign, track, and close response work.

Turns findings into cases an operator team can work: a persistent workqueue
(open, unassigned cases first), assignment, timestamped notes, and closure
with a reason. Every mutation is written to the audit log with the acting
operator, and every note is scrubbed of secrets before it is stored.
"""

from __future__ import annotations

from ..db import Database
from ..safety.masking import scrub_text
from ..schemas import BastionCase, CaseNote, CaseStatus, Severity, utcnow_iso
from ..utils.logging import get_logger

_MAX_TITLE = 200
_MAX_NOTE = 4000


class CaseError(ValueError):
    """Raised for invalid case operations (unknown case, bad transition)."""


class CaseManagementService:
    def __init__(self, db: Database):
        self.db = db
        self.log = get_logger("cases")

    # --- creation -------------------------------------------------------------
    def open_case(
        self,
        title: str,
        *,
        finding_ids: list[str] | None = None,
        severity: Severity | str | None = None,
        assignee: str = "",
        actor: str = "operator",
    ) -> BastionCase:
        title = scrub_text(str(title or "").strip())[:_MAX_TITLE]
        if not title:
            raise CaseError("a case needs a non-empty title")
        finding_ids = [str(f) for f in (finding_ids or []) if str(f).strip()]

        sev = Severity.coerce(severity, None)
        if sev is None:
            sev = self._severity_from_findings(finding_ids)

        case = BastionCase(
            title=title,
            severity=sev,
            assignee=scrub_text(assignee.strip())[:80],
            finding_ids=finding_ids,
            created_by=actor,
        )
        if case.assignee:
            case.status = CaseStatus.IN_PROGRESS
        self.db.save_case(case)
        self.db.audit("case_opened", actor=actor,
                      detail=f"title={title[:60]!r} findings={len(finding_ids)}",
                      correlation_id=case.case_id)
        return case

    def open_from_findings(self, *, category: str | None = None, min_severity: str = "high",
                           actor: str = "operator") -> list[BastionCase]:
        """Open one case per stored finding at/above a severity (the triage sweep).

        Findings already tracked by an open case are skipped, so repeated sweeps
        never duplicate work.
        """
        floor = Severity.coerce(min_severity, Severity.HIGH)
        tracked: set[str] = set()
        for c in self.db.list_cases(limit=1000):
            if c.is_open:
                tracked.update(c.finding_ids)
        opened: list[BastionCase] = []
        for f in self.db.list_findings(limit=1000, category=category):
            if f.severity.rank < floor.rank or f.correlation_id in tracked:
                continue
            opened.append(self.open_case(
                f.title, finding_ids=[f.correlation_id], severity=f.severity, actor=actor))
        return opened

    # --- lifecycle -------------------------------------------------------------
    def assign(self, case_id: str, assignee: str, *, actor: str = "operator") -> BastionCase:
        case = self._require(case_id)
        if case.status == CaseStatus.CLOSED:
            raise CaseError(f"case {case_id} is closed; reopen it before assigning")
        case.assignee = scrub_text(str(assignee or "").strip())[:80]
        case.status = CaseStatus.IN_PROGRESS if case.assignee else CaseStatus.OPEN
        case.touch()
        self.db.save_case(case)
        self.db.audit("case_assigned", actor=actor,
                      detail=f"assignee={case.assignee or '(unassigned)'}",
                      correlation_id=case.case_id)
        return case

    def add_note(self, case_id: str, text: str, *, actor: str = "operator") -> BastionCase:
        case = self._require(case_id)
        text = scrub_text(str(text or "").strip())[:_MAX_NOTE]
        if not text:
            raise CaseError("a note needs non-empty text")
        case.notes.append(CaseNote(author=actor, text=text))
        case.touch()
        self.db.save_case(case)
        self.db.audit("case_note_added", actor=actor,
                      detail=f"note_chars={len(text)}", correlation_id=case.case_id)
        return case

    def link_finding(self, case_id: str, finding_id: str, *, actor: str = "operator") -> BastionCase:
        case = self._require(case_id)
        fid = str(finding_id or "").strip()
        if not fid:
            raise CaseError("a finding id is required")
        if fid not in case.finding_ids:
            case.finding_ids.append(fid)
            case.touch()
            self.db.save_case(case)
            self.db.audit("case_finding_linked", actor=actor,
                          detail=f"finding={fid}", correlation_id=case.case_id)
        return case

    def close(self, case_id: str, *, reason: str = "resolved", actor: str = "operator") -> BastionCase:
        case = self._require(case_id)
        if case.status == CaseStatus.CLOSED:
            raise CaseError(f"case {case_id} is already closed")
        case.status = CaseStatus.CLOSED
        case.close_reason = scrub_text(str(reason or "resolved").strip())[:_MAX_NOTE]
        case.closed_at = utcnow_iso()
        case.touch()
        self.db.save_case(case)
        self.db.audit("case_closed", actor=actor,
                      detail=f"reason={case.close_reason[:60]!r}", correlation_id=case.case_id)
        return case

    def reopen(self, case_id: str, *, actor: str = "operator") -> BastionCase:
        case = self._require(case_id)
        if case.status != CaseStatus.CLOSED:
            raise CaseError(f"case {case_id} is not closed")
        case.status = CaseStatus.IN_PROGRESS if case.assignee else CaseStatus.OPEN
        case.closed_at = ""
        case.close_reason = ""
        case.touch()
        self.db.save_case(case)
        self.db.audit("case_reopened", actor=actor, correlation_id=case.case_id)
        return case

    # --- queries ---------------------------------------------------------------
    def get(self, case_id: str) -> BastionCase | None:
        return self.db.get_case(str(case_id or "").strip())

    def list_cases(self, *, status: str | None = None,
                   assignee: str | None = None) -> list[BastionCase]:
        return self.db.list_cases(status=status, assignee=assignee)

    def workqueue(self) -> list[BastionCase]:
        """Open cases ordered: unassigned first, then by severity, then age."""
        cases = [c for c in self.db.list_cases(limit=1000) if c.is_open]
        cases.sort(key=lambda c: (bool(c.assignee), -c.severity.rank, c.created_at))
        return cases

    def summary(self) -> dict[str, int]:
        cases = self.db.list_cases(limit=1000)
        return {
            "total": len(cases),
            "open": sum(1 for c in cases if c.status == CaseStatus.OPEN),
            "in_progress": sum(1 for c in cases if c.status == CaseStatus.IN_PROGRESS),
            "closed": sum(1 for c in cases if c.status == CaseStatus.CLOSED),
            "unassigned": sum(1 for c in cases if c.is_open and not c.assignee),
        }

    # --- internals ---------------------------------------------------------------
    def _require(self, case_id: str) -> BastionCase:
        case = self.db.get_case(str(case_id or "").strip())
        if not case:
            raise CaseError(f"case not found: {case_id}")
        return case

    def _severity_from_findings(self, finding_ids: list[str]) -> Severity:
        if not finding_ids:
            return Severity.MEDIUM
        wanted: set[str] = set(finding_ids)
        top = Severity.MEDIUM
        for f in self.db.list_findings(limit=1000):
            if f.correlation_id in wanted and f.severity.rank > top.rank:
                top = f.severity
        return top
