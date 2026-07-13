"""Case management: lifecycle, workqueue ordering, scrubbing, audit trail."""

from __future__ import annotations

import pytest

from greynoc_bastion.schemas import (
    BastionFinding,
    CaseStatus,
    FindingCategory,
    Severity,
)
from greynoc_bastion.services.case_management import CaseError


def _store_finding(app, title="Stored finding", severity=Severity.CRITICAL):
    f = BastionFinding(title=title, severity=severity, category=FindingCategory.THREAT)
    app.db.save_finding(f)
    return f


def test_open_assign_note_close_reopen_lifecycle(app):
    case = app.cases.open_case("Rotate exposed CI token", actor="tester")
    assert case.status == CaseStatus.OPEN
    assert case.is_open and not case.assignee

    case = app.cases.assign(case.case_id, "alice", actor="tester")
    assert case.status == CaseStatus.IN_PROGRESS
    assert case.assignee == "alice"

    case = app.cases.add_note(case.case_id, "token rotated in vault", actor="alice")
    assert len(case.notes) == 1
    assert case.notes[0].author == "alice"

    case = app.cases.close(case.case_id, reason="rotated + revoked", actor="alice")
    assert case.status == CaseStatus.CLOSED
    assert case.closed_at and case.close_reason == "rotated + revoked"

    # Closing again is an error; assigning a closed case is an error.
    with pytest.raises(CaseError):
        app.cases.close(case.case_id)
    with pytest.raises(CaseError):
        app.cases.assign(case.case_id, "bob")

    case = app.cases.reopen(case.case_id, actor="alice")
    assert case.status == CaseStatus.IN_PROGRESS  # assignee kept -> in_progress
    assert case.closed_at == "" and case.close_reason == ""


def test_open_requires_title_and_persists(app):
    with pytest.raises(CaseError):
        app.cases.open_case("   ")
    case = app.cases.open_case("Valid", actor="t")
    assert app.cases.get(case.case_id) is not None
    assert app.db.counts()["cases"] == 1


def test_case_severity_derived_from_linked_findings(app):
    f = _store_finding(app, severity=Severity.CRITICAL)
    case = app.cases.open_case("From finding", finding_ids=[f.correlation_id])
    assert case.severity == Severity.CRITICAL


def test_notes_and_titles_are_scrubbed(app):
    case = app.cases.open_case("Key AKIAIOSFODNN7EXAMPLE leaked")
    assert "AKIAIOSFODNN7EXAMPLE" not in case.title
    case = app.cases.add_note(case.case_id, "found token AKIAIOSFODNN7EXAMPLE in repo")
    assert "AKIAIOSFODNN7EXAMPLE" not in case.notes[0].text
    # And nothing in the persisted row leaks it either.
    stored = app.db.get_case(case.case_id)
    assert "AKIAIOSFODNN7EXAMPLE" not in stored.to_json()


def test_workqueue_orders_unassigned_first_then_severity(app):
    low = app.cases.open_case("low", severity="low")
    crit = app.cases.open_case("crit", severity="critical")
    assigned = app.cases.open_case("assigned-high", severity="high", assignee="bob")
    closed = app.cases.open_case("closed", severity="critical")
    app.cases.close(closed.case_id)

    queue = app.cases.workqueue()
    ids = [c.case_id for c in queue]
    assert closed.case_id not in ids
    assert ids[0] == crit.case_id          # unassigned critical first
    assert ids[1] == low.case_id           # unassigned low before any assigned
    assert ids[2] == assigned.case_id      # assigned last


def test_triage_sweep_opens_and_deduplicates(app):
    _store_finding(app, title="crit-1", severity=Severity.CRITICAL)
    _store_finding(app, title="med-1", severity=Severity.MEDIUM)

    opened = app.cases.open_from_findings(min_severity="high")
    assert len(opened) == 1
    assert opened[0].title == "crit-1"

    # A second sweep must not duplicate the tracked finding.
    assert app.cases.open_from_findings(min_severity="high") == []
    # Closing the case frees the finding for re-triage.
    app.cases.close(opened[0].case_id)
    assert len(app.cases.open_from_findings(min_severity="high")) == 1


def test_case_mutations_are_audited(app):
    case = app.cases.open_case("Audited", actor="tester")
    app.cases.assign(case.case_id, "alice", actor="tester")
    app.cases.close(case.case_id, actor="tester")
    actions = [e["action"] for e in app.db.recent_audit(limit=20)]
    for expected in ("case_opened", "case_assigned", "case_closed"):
        assert expected in actions


def test_unknown_case_operations_raise(app):
    for op in (lambda: app.cases.assign("case-nope", "x"),
               lambda: app.cases.add_note("case-nope", "hi"),
               lambda: app.cases.close("case-nope"),
               lambda: app.cases.reopen("case-nope")):
        with pytest.raises(CaseError):
            op()


def test_summary_counts(app):
    a = app.cases.open_case("a")
    app.cases.open_case("b", assignee="alice")
    app.cases.close(a.case_id)
    s = app.cases.summary()
    assert s == {"total": 2, "open": 0, "in_progress": 1, "closed": 1, "unassigned": 0}
