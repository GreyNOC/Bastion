"""Report/workflow scheduling and the cross-module orchestrator."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from greynoc_bastion.services.scheduler import ScheduleError


# --- schedule definitions -------------------------------------------------------
def test_add_and_list_schedule(app):
    record = app.scheduler.add("nightly", kind="report", interval_hours=24)
    assert record["schedule_id"].startswith("sched-")
    assert record["enabled"] is True
    assert record["next_run_at"]                       # due immediately
    assert len(app.scheduler.list_schedules()) == 1


def test_schedule_validation(app):
    with pytest.raises(ScheduleError):
        app.scheduler.add("", kind="report")
    with pytest.raises(ScheduleError):
        app.scheduler.add("x", kind="cron-bomb")
    with pytest.raises(ScheduleError):
        app.scheduler.add("x", interval_hours=0.01)     # below the floor
    with pytest.raises(ScheduleError):
        app.scheduler.add("x", interval_hours="nan-ish")
    with pytest.raises(ScheduleError):
        app.scheduler.add("x", kind="workflow", workflow="does-not-exist")


def test_run_due_builds_report_and_advances(app, tmp_path):
    dest = tmp_path / "delivery"
    app.scheduler.add("daily", kind="report", interval_hours=24, deliver_to=str(dest))
    outcomes = app.scheduler.run_due()
    assert len(outcomes) == 1 and outcomes[0]["ok"]
    # Delivered local copies of the report outputs.
    assert dest.is_dir() and list(dest.iterdir())
    # next_run_at advanced ~24h into the future; nothing due anymore.
    record = app.scheduler.list_schedules()[0]
    nxt = datetime.fromisoformat(record["next_run_at"].replace("Z", "+00:00"))
    assert nxt > datetime.now(timezone.utc) + timedelta(hours=23)
    assert record["last_result"] == "ok"
    assert app.scheduler.run_due() == []


def test_delivery_restricted_to_base_for_web(app, tmp_path):
    # Regression: a web operator must not deliver report files outside the
    # Bastion home. The restrict_base guard (used by the dashboard route)
    # rejects an out-of-tree destination but allows one inside it.
    outside = tmp_path / "escape"
    with pytest.raises(ScheduleError):
        app.scheduler.add("evil", kind="report", deliver_to=str(outside),
                          restrict_base=app.config.home)
    # Also catches traversal that resolves outside the base.
    with pytest.raises(ScheduleError):
        app.scheduler.add("evil2", kind="report",
                          deliver_to=str(app.config.home / ".." / "escape"),
                          restrict_base=app.config.home)
    # A destination inside the home tree is accepted.
    inside = app.config.home / "drops"
    record = app.scheduler.add("ok", kind="report", deliver_to=str(inside),
                               restrict_base=app.config.home)
    assert record["deliver_to"]
    # The trusted CLI path (no restrict_base) can still deliver anywhere.
    record2 = app.scheduler.add("cli", kind="report", deliver_to=str(outside))
    assert record2["deliver_to"] == str(outside)


def test_disabled_schedule_is_skipped(app):
    record = app.scheduler.add("paused", kind="report")
    app.scheduler.set_enabled(record["schedule_id"], False)
    assert app.scheduler.due() == []
    app.scheduler.set_enabled(record["schedule_id"], True)
    assert len(app.scheduler.due()) == 1


def test_remove_schedule(app):
    record = app.scheduler.add("gone", kind="report")
    assert app.scheduler.remove(record["schedule_id"]) is True
    assert app.scheduler.remove(record["schedule_id"]) is False
    assert app.scheduler.list_schedules() == []


def test_workflow_schedule_runs_workflow(app):
    app.scheduler.add("wf", kind="workflow", workflow="validate-and-report")
    outcomes = app.scheduler.run_due()
    assert outcomes[0]["ok"]
    assert "validate-and-report" in outcomes[0]["detail"]
    # The workflow really ran: validations + a report exist now.
    counts = app.db.counts()
    assert counts["validation_results"] > 0
    assert counts["reports"] == 1


def test_scheduler_actions_are_audited(app):
    record = app.scheduler.add("aud", kind="report")
    app.scheduler.run_due()
    app.scheduler.remove(record["schedule_id"])
    actions = [e["action"] for e in app.db.recent_audit(limit=30)]
    for expected in ("schedule_added", "schedule_run", "schedule_removed"):
        assert expected in actions


# --- orchestrator ------------------------------------------------------------------
def test_list_workflows(app):
    names = {wf["name"] for wf in app.orchestrator.list_workflows()}
    assert {"full-sweep", "validate-and-report", "morning-check"} <= names


def test_unknown_workflow_raises(app):
    with pytest.raises(ValueError):
        app.orchestrator.run("does-not-exist")


def test_full_sweep_populates_every_store(app):
    result = app.orchestrator.run("full-sweep", actor="tester")
    assert result["ok"], result
    assert [s["step"] for s in result["steps"]] == [
        "forecast", "detections", "assets", "correlate", "triage", "report"]
    counts = app.db.counts()
    assert counts["threats"] > 0
    assert counts["validation_results"] > 0
    assert counts["findings"] > 0
    assert counts["reports"] == 1
    actions = [e["action"] for e in app.db.recent_audit(limit=50)]
    assert "workflow_started" in actions and "workflow_finished" in actions


def test_one_failed_step_does_not_abort_the_rest(app, monkeypatch):
    def boom(_app):
        raise RuntimeError("engine offline")
    monkeypatch.setitem(
        __import__("greynoc_bastion.services.orchestrator", fromlist=["STEPS"]).STEPS,
        "forecast", boom)
    result = app.orchestrator.run("morning-check")
    assert result["ok"] is False
    steps = {s["step"]: s for s in result["steps"]}
    assert steps["forecast"]["ok"] is False
    assert steps["correlate"]["ok"] is True            # later steps still ran
