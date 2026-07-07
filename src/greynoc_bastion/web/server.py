"""Local dashboard server.

A Flask app bound to loopback (``127.0.0.1``) by default. Read (GET) routes
render stored data; a small set of POST actions run a module on demand (all
local, all safe, no destructive operations). ``/healthz`` is a JSON health route.

Safety posture of the dashboard:
  * **Loopback only by default.** Binding to a non-loopback host is refused
    unless ``BASTION_ALLOW_REMOTE_DASHBOARD=1`` *and* ``BASTION_DASHBOARD_TOKEN``
    are both set (:func:`ensure_bind_allowed`).
  * **Token auth.** If ``BASTION_DASHBOARD_TOKEN`` is set, every request (except
    the health check) must carry ``Authorization: Bearer <token>`` (or, for
    local development, ``?token=<token>``).
  * **CSRF.** POST actions require a per-session CSRF token; Bearer-authenticated
    API clients are exempt (the header is not sent cross-site by browsers).
"""

from __future__ import annotations

import hmac
import secrets
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..app import BastionApp
from ..schemas import ReportFormat

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def ensure_bind_allowed(host: str, *, allow_remote: bool = False, has_token: bool = False) -> None:
    """Fail closed before binding the dashboard to a non-loopback host.

    Raises :class:`SystemExit` with a clear message if a remote bind is
    requested without the explicit override (``allow_remote``) and an auth token
    (``has_token``). Loopback binds always pass. The two flags come from the
    resolved config so ``.env`` values are honored, not only real env vars.
    """
    if host in _LOOPBACK_HOSTS:
        return
    if not allow_remote:
        raise SystemExit(
            f"Refusing to bind the dashboard to non-loopback host '{host}'. "
            "The dashboard is loopback-only by default. To expose it deliberately, set "
            "BASTION_ALLOW_REMOTE_DASHBOARD=1 AND BASTION_DASHBOARD_TOKEN=<strong-token>."
        )
    if not has_token:
        raise SystemExit(
            f"Refusing remote dashboard bind on '{host}' without BASTION_DASHBOARD_TOKEN set — "
            "that would expose an unauthenticated dashboard. Set a strong token and retry."
        )


def _request_authed(req, token: str) -> bool:
    """True if the request is authorized for the token-protected dashboard.

    Accepts an ``Authorization: Bearer`` header, a ``?token=`` query (which then
    bootstraps an authenticated session so subsequent navigation/POSTs work
    without re-supplying the token), or a previously-established session.
    """
    header = req.headers.get("Authorization", "")
    if header.startswith("Bearer ") and hmac.compare_digest(header[7:], token):
        return True
    query = req.args.get("token", "")
    if query and hmac.compare_digest(query, token):
        session["_authed"] = True  # bootstrap a session from the query token
        return True
    return bool(session.get("_authed"))


def _has_valid_bearer(req, token: str | None) -> bool:
    header = req.headers.get("Authorization", "")
    return bool(token) and header.startswith("Bearer ") and hmac.compare_digest(header[7:], token)


def create_app(bastion: BastionApp) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).with_name("templates")),
        static_folder=str(Path(__file__).with_name("static")),
    )
    # Per-process random key signs the session cookie (CSRF token + flash).
    # Resolved from config (honors .env); set BASTION_WEB_SECRET only if sessions
    # must survive a restart.
    app.config["SECRET_KEY"] = bastion.config.web_secret or secrets.token_hex(16)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Optional token auth, resolved from config (so a token in .env is honored).
    # When set, required on every request except /healthz.
    dashboard_token = bastion.config.dashboard_token or None

    @app.context_processor
    def _inject_csrf():
        token = session.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf"] = token
        return {"csrf_token": token}

    @app.before_request
    def _security_gate():
        # Health check and static assets stay open (monitoring; no data).
        if request.endpoint in ("healthz", "static"):
            return None
        # 1) Token auth (only enforced when a token is configured).
        if dashboard_token and not _request_authed(request, dashboard_token):
            return Response("unauthorized: provide Authorization: Bearer <token>\n", 401)
        # 2) CSRF on state-changing requests. Bearer-authenticated API clients
        #    are exempt (the header is never auto-sent cross-site).
        if request.method == "POST" and not _has_valid_bearer(request, dashboard_token):
            form_token = request.form.get("csrf_token", "")
            sess_token = session.get("_csrf", "")
            if not sess_token or not hmac.compare_digest(str(form_token), str(sess_token)):
                return Response("invalid or missing CSRF token\n", 403)
        return None

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
    # Fail closed: refuse a non-loopback bind unless explicitly overridden and
    # protected by a token. Settings come from resolved config (honors .env).
    ensure_bind_allowed(
        host,
        allow_remote=bastion.config.allow_remote_dashboard,
        has_token=bool(bastion.config.dashboard_token),
    )
    remote = host not in _LOOPBACK_HOSTS
    app = create_app(bastion)
    mode = "remote (token auth required)" if remote else "loopback only"
    bastion.log.info("GreyNOC Bastion dashboard on http://%s:%s — %s — Ctrl+C to stop",
                     host, port, mode)
    app.run(host=host, port=port, debug=False, use_reloader=False)
