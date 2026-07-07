"""Local dashboard server.

A Flask app bound to loopback by default. Read (GET) routes render stored data
and live-derived views; a small set of POST actions run a module on demand
(all local, all safe, no destructive operations). ``/healthz`` is a JSON health
route used by tests and monitoring.
"""

from __future__ import annotations

from pathlib import Path
import os
import secrets
from typing import Optional

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ..app import BastionApp
from ..schemas import ReportFormat


def create_app(bastion: BastionApp) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).with_name("templates")),
        static_folder=str(Path(__file__).with_name("static")),
    )
    # Per-process random key (flash messages only; the dashboard is loopback and
    # unauthenticated). Override via BASTION_WEB_SECRET only if you need sessions
    # to survive a restart. Never a committed constant.
    app.config["SECRET_KEY"] = os.environ.get("BASTION_WEB_SECRET") or secrets.token_hex(16)

    def ctx():
        posture = bastion.safety_status().posture
        return {"posture": posture, "config": bastion.config}

    # --- health --------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        return jsonify({
            "status": "ok",
            "product": "GreyNOC Bastion",
            "version": "0.1.0",
            "safety_posture": bastion.safety_status().posture,
        })

    # --- pages ---------------------------------------------------------------
    @app.get("/")
    def overview():
        status = bastion.status()
        findings = bastion.db.list_findings(limit=10)
        findings.sort(key=lambda f: f.priority_score, reverse=True)
        return render_template(
            "overview.html", active_page="overview",
            status=status, counts=status["counts"], top_findings=findings[:10], **ctx())

    @app.get("/forecast")
    def forecast():
        return render_template("forecast.html", active_page="forecast",
                               threats=bastion.db.list_threats(limit=200), **ctx())

    @app.get("/identities")
    def identities():
        default_path = str(Path(__file__).resolve().parents[1] / "fixtures" / "sample_project")
        return render_template("identities.html", active_page="identities",
                               identities=bastion.db.list_identities(limit=500),
                               default_path=default_path, **ctx())

    @app.get("/detections")
    def detections():
        results = bastion.db.list_validations(limit=500)
        pack = bastion.detection.detections.load_validated_pack()
        coverage = bastion.detection.detections.coverage_summary(pack)
        return render_template("detections.html", active_page="detections",
                               results=results, coverage=coverage, **ctx())

    @app.get("/playbooks")
    def playbooks():
        pbs = sorted(bastion.list_playbooks(), key=lambda p: (p.category, p.slug))
        return render_template("playbooks.html", active_page="playbooks", playbooks=pbs, **ctx())

    @app.get("/playbooks/<slug>")
    def playbook_detail(slug):
        pb = bastion.get_playbook(slug)
        if not pb:
            abort(404)
        return render_template("playbook_detail.html", active_page="playbooks", playbook=pb, **ctx())

    @app.get("/assets")
    def assets():
        return render_template("assets.html", active_page="assets",
                               assets=bastion.db.list_assets(limit=500), **ctx())

    @app.get("/correlation")
    def correlation():
        return render_template("correlation.html", active_page="correlation",
                               result=bastion.correlate(), **ctx())

    @app.get("/reports")
    def reports():
        return render_template("reports.html", active_page="reports",
                               reports=bastion.db.list_reports(limit=100), **ctx())

    @app.get("/settings")
    def settings():
        return render_template("settings.html", active_page="settings", **ctx())

    @app.get("/safety")
    def safety():
        return render_template("safety.html", active_page="safety",
                               safety=bastion.safety_status(), **ctx())

    # --- actions (POST; safe, local, non-destructive) ------------------------
    @app.post("/run/seed")
    def run_seed():
        bastion.threat_forecast.demo(sectors=["healthcare", "public-sector"], persist=True)
        bastion.detection.validate_all(persist=True)
        sample = Path(__file__).resolve().parents[1] / "fixtures" / "sample_project"
        bastion.identity.scan(sample, persist=True)
        bastion.assets.scan_local(passive=True, persist=True)
        flash("Ran all modules against offline fixtures and local passive review.")
        return redirect(url_for("overview"))

    @app.post("/run/forecast")
    def run_forecast():
        sectors = [s.strip() for s in (request.form.get("sectors") or "").split(",") if s.strip()]
        threats = bastion.threat_forecast.demo(sectors=sectors or None, persist=True)
        flash(f"Threat forecast complete — {len(threats)} threats ranked.")
        return redirect(url_for("forecast"))

    @app.post("/run/identities")
    def run_identities():
        path = (request.form.get("path") or "").strip()
        target = Path(path)
        if not path or not target.exists():
            flash("Path not found; scan skipped.")
            return redirect(url_for("identities"))
        ids = bastion.identity.scan(target, persist=True)
        flash(f"Identity scan complete — {len(ids)} non-human identities (secrets masked).")
        return redirect(url_for("identities"))

    @app.post("/run/detections")
    def run_detections():
        results = bastion.detection.validate_all(persist=True)
        passed = sum(1 for r in results if r.passed)
        flash(f"Validated rule pack — {passed}/{len(results)} rules passed.")
        return redirect(url_for("detections"))

    @app.post("/run/assets")
    def run_assets():
        assets_list = bastion.assets.scan_local(passive=True, persist=True)
        flash(f"Local passive review complete — {len(assets_list)} services reviewed.")
        return redirect(url_for("assets"))

    @app.post("/run/report")
    def run_report():
        report = bastion.build_report(
            formats=[ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON,
                     ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.PDF],
            include_bundle=True,
        )
        flash(f"Report built ({report.summary.total_findings} findings) → {bastion.config.report_dir}")
        return redirect(url_for("reports"))

    @app.post("/run/doctor")
    def run_doctor():
        result = bastion.doctor()
        flash(f"Doctor result: {result['result'].upper()}")
        return redirect(url_for("safety"))

    return app


def serve(bastion: BastionApp, host: str = "127.0.0.1", port: int = 8788) -> None:
    app = create_app(bastion)
    if host not in ("127.0.0.1", "::1", "localhost"):
        bastion.log.warning(
            "serving on non-loopback host %s — the dashboard has no authentication; "
            "exposing it beyond localhost is strongly discouraged.", host
        )
    bastion.log.info("GreyNOC Bastion dashboard on http://%s:%s (Ctrl+C to stop)", host, port)
    app.run(host=host, port=port, debug=False, use_reloader=False)
