"""Report / workflow scheduling with a local, explicit runner.

Local-first by design: Bastion installs no daemon and phones nothing home.
A schedule is a persisted intent — *what* to run, *how often*, and *where*
to deliver the output. ``bastion schedule run-due`` (typically wired to cron
or a systemd timer by the operator) executes everything whose ``next_run_at``
has passed.

Kinds:
  * ``report``   — build the consolidated report; deliver copies to a local
                   destination directory (optional).
  * ``workflow`` — run a named orchestrator workflow (see
                   :mod:`greynoc_bastion.services.orchestrator`).

Delivery is local-first: a destination is a local directory the report files
are copied into. Anything beyond local delivery (the webhook sink) is the
notification fabric's job and stays behind its own opt-in + egress guard.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..schemas import utcnow_iso
from ..utils.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - import cycle guard (app builds us)
    from ..app import BastionApp

_KINDS = {"report", "workflow"}
_MIN_INTERVAL_HOURS = 0.25   # 15 minutes; schedules are not a realtime engine
_MAX_INTERVAL_HOURS = 24 * 90


class ScheduleError(ValueError):
    """Raised for invalid schedule definitions or operations."""


def _parse_iso(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


class SchedulerService:
    def __init__(self, app: BastionApp):
        self.app = app
        self.db = app.db
        self.log = get_logger("scheduler")

    # --- definition -----------------------------------------------------------
    def add(self, name: str, *, kind: str = "report", interval_hours: float = 24.0,
            workflow: str = "", deliver_to: str = "", actor: str = "operator",
            restrict_base: Path | None = None) -> dict[str, Any]:
        """Create a schedule.

        ``restrict_base`` confines the delivery directory to a subtree (used by
        the web dashboard, where a merely-``operator`` role must not be able to
        drop report files anywhere the service account can write). The trusted
        local CLI passes no restriction.
        """
        name = str(name or "").strip()[:120]
        if not name:
            raise ScheduleError("a schedule needs a name")
        kind = str(kind or "report").strip().lower()
        if kind not in _KINDS:
            raise ScheduleError(f"unknown schedule kind: {kind!r} (report, workflow)")
        try:
            interval_hours = float(interval_hours)
        except (TypeError, ValueError):
            raise ScheduleError(f"interval must be a number of hours, got {interval_hours!r}") from None
        if not (_MIN_INTERVAL_HOURS <= interval_hours <= _MAX_INTERVAL_HOURS):
            raise ScheduleError(
                f"interval must be between {_MIN_INTERVAL_HOURS} and {_MAX_INTERVAL_HOURS} hours")
        if kind == "workflow":
            from .orchestrator import WORKFLOWS
            if workflow not in WORKFLOWS:
                raise ScheduleError(
                    f"unknown workflow: {workflow!r} (available: {', '.join(sorted(WORKFLOWS))})")
        if deliver_to:
            dest = Path(deliver_to).expanduser()
            if dest.exists() and not dest.is_dir():
                raise ScheduleError(f"delivery destination is not a directory: {dest}")
            if restrict_base is not None:
                base = Path(restrict_base).expanduser().resolve()
                resolved = dest.resolve()
                if resolved != base and base not in resolved.parents:
                    raise ScheduleError(
                        f"delivery destination must be inside {base} "
                        "(the dashboard confines delivery to the Bastion home)")

        record: dict[str, Any] = {
            "schedule_id": f"sched-{uuid.uuid4().hex[:12]}",
            "name": name,
            "kind": kind,
            "workflow": workflow,
            "deliver_to": str(Path(deliver_to).expanduser()) if deliver_to else "",
            "interval_hours": interval_hours,
            "enabled": True,
            "created_at": utcnow_iso(),
            "last_run_at": "",
            "last_result": "",
            # First run is due immediately: an operator adding a schedule wants
            # the first artifact now, not interval_hours from now.
            "next_run_at": utcnow_iso(),
        }
        self.db.save_schedule(record)
        self.db.audit("schedule_added", actor=actor,
                      detail=f"name={name!r} kind={kind} every={interval_hours}h",
                      correlation_id=record["schedule_id"])
        return record

    def remove(self, schedule_id: str, *, actor: str = "operator") -> bool:
        removed = self.db.delete_schedule(str(schedule_id or "").strip())
        if removed:
            self.db.audit("schedule_removed", actor=actor, correlation_id=schedule_id)
        return removed

    def set_enabled(self, schedule_id: str, enabled: bool, *, actor: str = "operator") -> dict[str, Any]:
        record = self.db.get_schedule(str(schedule_id or "").strip())
        if not record:
            raise ScheduleError(f"schedule not found: {schedule_id}")
        record["enabled"] = bool(enabled)
        self.db.save_schedule(record)
        self.db.audit("schedule_enabled" if enabled else "schedule_disabled",
                      actor=actor, correlation_id=schedule_id)
        return record

    def list_schedules(self) -> list[dict[str, Any]]:
        return self.db.list_schedules()

    # --- execution -------------------------------------------------------------
    def due(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or datetime.now(timezone.utc)
        return [s for s in self.db.list_schedules()
                if s.get("enabled") and _parse_iso(s.get("next_run_at", "")) <= now]

    def run_due(self, *, now: datetime | None = None, actor: str = "scheduler") -> list[dict[str, Any]]:
        """Execute every due schedule; advance ``next_run_at``; report results."""
        now = now or datetime.now(timezone.utc)
        outcomes: list[dict[str, Any]] = []
        for record in self.due(now=now):
            outcome = self._run_one(record, actor=actor)
            # Advance from *now*, not from the stale next_run_at, so a missed
            # window (machine asleep) doesn't cause a burst of catch-up runs.
            record["last_run_at"] = utcnow_iso()
            record["last_result"] = "ok" if outcome["ok"] else f"failed: {outcome.get('error', '')[:200]}"
            next_at = now + timedelta(hours=float(record.get("interval_hours", 24.0)))
            record["next_run_at"] = next_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.db.save_schedule(record)
            outcomes.append(outcome)
        return outcomes

    def _run_one(self, record: dict[str, Any], *, actor: str) -> dict[str, Any]:
        sid = str(record["schedule_id"])
        kind = str(record.get("kind", "report"))
        self.db.audit("schedule_run", actor=actor,
                      detail=f"name={record.get('name', '')!r} kind={kind}", correlation_id=sid)
        try:
            if kind == "workflow":
                run = self.app.orchestrator.run(record.get("workflow", ""), actor=actor)
                return {"schedule_id": sid, "kind": kind, "ok": run["ok"],
                        "detail": f"workflow {record.get('workflow')}: "
                                  f"{sum(1 for s in run['steps'] if s['ok'])}/{len(run['steps'])} steps ok"}
            report = self.app.build_report()
            delivered = self._deliver(record, report)
            self.app.notifications.notify(
                "scheduled-report", f"Scheduled report '{record.get('name', '')}' built",
                detail=report.summary.headline, severity="info")
            return {"schedule_id": sid, "kind": kind, "ok": True,
                    "detail": f"report {report.report_id} built"
                              + (f"; delivered {delivered} file(s)" if delivered else "")}
        except Exception as exc:  # noqa: BLE001 - a failed schedule must not stop the rest
            self.log.warning("schedule %s failed: %s", sid, exc)
            self.db.audit("schedule_failed", actor=actor, detail=str(exc)[:300], correlation_id=sid)
            return {"schedule_id": sid, "kind": kind, "ok": False, "error": str(exc)}

    def _deliver(self, record: dict[str, Any], report) -> int:
        """Copy the report's output files into the local destination directory."""
        deliver_to = record.get("deliver_to", "")
        if not deliver_to:
            return 0
        dest = Path(deliver_to)
        dest.mkdir(parents=True, exist_ok=True)
        n = 0
        for _fmt, path in (report.output_paths or {}).items():
            src = Path(path)
            if src.is_file():
                shutil.copy2(src, dest / src.name)
                n += 1
        self.db.audit("report_delivered", actor="scheduler",
                      detail=f"{n} file(s) -> {dest}", correlation_id=record["schedule_id"])
        return n
