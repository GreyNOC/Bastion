"""Cross-module orchestrator — named, combined defensive workflows.

A workflow is a fixed sequence of module steps run against the local data
store (forecast, validate, passive asset review, correlate, report). Steps
are all local and safe; the orchestrator adds nothing a user could not run
by hand — it removes the toil of running them in order.

Runs are audited, summarized per step, and (when the fabric is enabled)
announced through the notification fabric.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..schemas import utcnow_iso
from ..utils.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - import cycle guard (app builds us)
    from ..app import BastionApp

StepFn = Callable[["BastionApp"], str]


def _step_forecast(app: BastionApp) -> str:
    threats = app.threat_forecast.demo(persist=True)
    return f"{len(threats)} threats ranked"


def _step_detections(app: BastionApp) -> str:
    results = app.detection.validate_all(persist=True)
    passed = sum(1 for r in results if r.passed)
    return f"{passed}/{len(results)} detections passed validation"


def _step_assets(app: BastionApp) -> str:
    assets = app.assets.scan_local(passive=True, persist=True)
    return f"{len(assets)} local services reviewed (passive)"


def _step_correlate(app: BastionApp) -> str:
    result = app.correlate()
    gaps = sum(1 for c in result.get("clusters", []) if c.get("coverage_gap"))
    return f"{len(result.get('clusters', []))} clusters, {gaps} coverage gaps"


def _step_report(app: BastionApp) -> str:
    report = app.build_report()
    return f"report {report.report_id}: {report.summary.total_findings} findings"


def _step_triage(app: BastionApp) -> str:
    opened = app.cases.open_from_findings(min_severity="high", actor="orchestrator")
    return f"{len(opened)} new cases opened for high+ findings"


STEPS: dict[str, StepFn] = {
    "forecast": _step_forecast,
    "detections": _step_detections,
    "assets": _step_assets,
    "correlate": _step_correlate,
    "report": _step_report,
    "triage": _step_triage,
}

WORKFLOWS: dict[str, dict[str, Any]] = {
    "full-sweep": {
        "description": "Run every engine, correlate, triage high findings into cases, build a report.",
        "steps": ["forecast", "detections", "assets", "correlate", "triage", "report"],
    },
    "validate-and-report": {
        "description": "Validate the detection pack and build a consolidated report.",
        "steps": ["detections", "report"],
    },
    "morning-check": {
        "description": "Refresh the forecast and correlation view; open cases for new high findings.",
        "steps": ["forecast", "correlate", "triage"],
    },
}


class OrchestratorService:
    def __init__(self, app: BastionApp):
        self.app = app
        self.log = get_logger("orchestrator")

    def list_workflows(self) -> list[dict[str, Any]]:
        return [{"name": name, "description": wf["description"], "steps": list(wf["steps"])}
                for name, wf in WORKFLOWS.items()]

    def run(self, name: str, *, actor: str = "operator") -> dict[str, Any]:
        wf = WORKFLOWS.get(str(name or "").strip())
        if not wf:
            known = ", ".join(sorted(WORKFLOWS))
            raise ValueError(f"unknown workflow: {name!r} (available: {known})")

        self.app.db.audit("workflow_started", actor=actor, detail=f"workflow={name}")
        step_results: list[dict[str, Any]] = []
        ok = True
        started = utcnow_iso()
        for step_name in wf["steps"]:
            fn = STEPS[step_name]
            t0 = time.monotonic()
            try:
                summary = fn(self.app)
                step_results.append({
                    "step": step_name, "ok": True, "summary": summary,
                    "seconds": round(time.monotonic() - t0, 2),
                })
            except Exception as exc:  # noqa: BLE001 - one failed step must not hide the rest
                ok = False
                self.log.warning("workflow %s step %s failed: %s", name, step_name, exc)
                step_results.append({
                    "step": step_name, "ok": False, "summary": f"failed: {exc}",
                    "seconds": round(time.monotonic() - t0, 2),
                })

        result = {
            "workflow": name,
            "ok": ok,
            "started_at": started,
            "finished_at": utcnow_iso(),
            "steps": step_results,
        }
        self.app.db.audit(
            "workflow_finished", actor=actor,
            detail=f"workflow={name} ok={ok} steps={len(step_results)}")
        self.app.notifications.notify(
            "workflow", f"Workflow '{name}' {'completed' if ok else 'finished with failures'}",
            detail="; ".join(f"{s['step']}: {s['summary']}" for s in step_results),
            severity="info" if ok else "high",
        )
        return result
