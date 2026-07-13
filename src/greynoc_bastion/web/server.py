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
  * **Operator login + RBAC.** With no operator accounts, the dashboard runs in
    the original single-operator local-trust mode. Once accounts exist
    (``bastion users add``), every request requires a login; roles gate what a
    session can do (viewer: read; operator: run modules + work cases;
    admin: manage accounts). Login attempts are throttled and audited.
  * **CSRF.** POST actions require a per-session CSRF token; Bearer-authenticated
    API clients are exempt (the header is not sent cross-site by browsers).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

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
from ..auth import AuthError
from ..schemas import OperatorRole, ReportFormat
from ..services.case_management import CaseError
from ..services.scheduler import ScheduleError

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

# Login throttling: after this many failures for a (client, username) pair
# within the window, further attempts are refused for the window's remainder.
_THROTTLE_MAX_FAILURES = 5
_THROTTLE_WINDOW_SECONDS = 15 * 60
# Hard cap on distinct tracked keys so an unauthenticated attacker spraying the
# login form with many usernames/source IPs cannot grow the map without bound
# (the login page is reachable pre-auth in multi-operator mode).
_THROTTLE_MAX_KEYS = 4096


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


def _token_fingerprint(token: str) -> str:
    """Non-reversible, current-token-bound marker stored in a bootstrapped session."""
    return hashlib.sha256(b"bastion-dash-token:" + token.encode("utf-8")).hexdigest()


def _request_authed(req, token: str) -> bool:
    """True if the request is authorized for the token-protected dashboard.

    Accepts an ``Authorization: Bearer`` header, a ``?token=`` query (which then
    bootstraps an authenticated session so subsequent navigation/POSTs work
    without re-supplying the token), or a previously-established session. A
    bootstrapped session is bound to a fingerprint of the CURRENT token, so
    rotating ``BASTION_DASHBOARD_TOKEN`` immediately revokes sessions
    bootstrapped from the old token (even when the session cookie is persistent
    via ``BASTION_WEB_SECRET``).
    """
    header = req.headers.get("Authorization", "")
    if header.startswith("Bearer ") and hmac.compare_digest(header[7:], token):
        return True
    query = req.args.get("token", "")
    if query and hmac.compare_digest(query, token):
        session["_token_fp"] = _token_fingerprint(token)  # bootstrap, token-bound
        return True
    fp = session.get("_token_fp")
    return bool(fp and hmac.compare_digest(str(fp), _token_fingerprint(token)))


def _safe_next(target: str | None) -> str:
    """Resolve a post-login redirect target, refusing any off-site destination.

    Rejects absolute URLs, protocol-relative ``//host`` and ``/\\host`` (browsers
    fold ``\\`` to ``/``), and anything carrying a scheme or netloc. Falls back
    to the overview page. Prevents an open redirect via the ``next`` parameter.
    """
    if not target:
        return url_for("overview")
    if "\\" in target or not target.startswith("/") or target.startswith("//"):
        return url_for("overview")
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return url_for("overview")
    return target


def _has_valid_bearer(req, token: str | None) -> bool:
    header = req.headers.get("Authorization", "")
    return bool(token) and header.startswith("Bearer ") and hmac.compare_digest(header[7:], token)


class _LoginThrottle:
    """In-process failure throttle for the login form (per client+username)."""

    def __init__(self, max_failures: int = _THROTTLE_MAX_FAILURES,
                 window_seconds: int = _THROTTLE_WINDOW_SECONDS):
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> None:
        self._failures[key] = [t for t in self._failures.get(key, []) if now - t < self.window]
        if not self._failures[key]:
            self._failures.pop(key, None)

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        self._prune(key, now)
        return len(self._failures.get(key, [])) >= self.max_failures

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        # Bound the map: if we're at the cap and this is a new key, drop the
        # keys whose most-recent failure is oldest to make room. Under an
        # attack the churn only costs the attacker their own throttle history.
        if key not in self._failures and len(self._failures) >= _THROTTLE_MAX_KEYS:
            for stale in sorted(self._failures, key=lambda k: self._failures[k][-1])[:64]:
                self._failures.pop(stale, None)
        self._prune(key, now)
        self._failures.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


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
    throttle = _LoginThrottle()

    @app.context_processor
    def _inject_csrf():
        token = session.get("_csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf"] = token
        return {"csrf_token": token}

    # --- identity & RBAC helpers ---------------------------------------------
    def _login_required() -> bool:
        """Login is required only once operator accounts exist."""
        return bastion.operators.multi_operator_mode()

    def _session_role() -> OperatorRole | None:
        """The logged-in operator's CURRENT role (re-checked every request so a
        role change or disable takes effect immediately, not at next login)."""
        username = session.get("_user")
        if not username:
            return None
        record = bastion.db.get_operator(str(username))
        if not record or record.get("disabled"):
            session.pop("_user", None)
            return None
        return OperatorRole.coerce(record.get("role"), OperatorRole.VIEWER)

    def _effective_role() -> OperatorRole | None:
        """Role for this request: operator session > bearer/query token > legacy.

        The static token authenticates the *machine channel* (remote exposure,
        API clients) and maps to OPERATOR; account management always needs a
        real admin login. With no accounts defined at all, local requests get
        OPERATOR (the original single-operator trust model).
        """
        role = _session_role()
        if role is not None:
            return role
        if dashboard_token and _request_authed(request, dashboard_token):
            return OperatorRole.OPERATOR
        if not _login_required():
            return OperatorRole.OPERATOR
        return None

    def _actor() -> str:
        username = session.get("_user")
        if username:
            return f"web:{username}"
        if dashboard_token and _request_authed(request, dashboard_token):
            return "web:token"
        return "web:local"

    def _require(role: OperatorRole) -> None:
        current = _effective_role()
        if current is None or not current.allows(role):
            abort(403)

    @app.before_request
    def _security_gate():
        # Health check and static assets stay open (monitoring; no data).
        if request.endpoint in ("healthz", "static"):
            return None
        # 1) Token auth. When a token is configured but NO operator accounts
        #    exist, the token is the sole authenticator (the machine channel)
        #    and is required on every request. Once accounts exist, the login
        #    gate (step 3) governs and the token becomes an alternative
        #    operator-level channel (bearer header / ?token=). We must NOT
        #    hard-401 here in that combined mode, or the login page itself
        #    becomes unreachable and remote multi-operator login is impossible.
        if (dashboard_token and not _login_required()
                and not _request_authed(request, dashboard_token)):
            return Response("unauthorized: provide Authorization: Bearer <token>\n", 401)
        # 2) CSRF on state-changing requests. Bearer-authenticated API clients
        #    are exempt (the header is never auto-sent cross-site).
        if request.method == "POST" and not _has_valid_bearer(request, dashboard_token):
            form_token = request.form.get("csrf_token", "")
            sess_token = session.get("_csrf", "")
            if not sess_token or not hmac.compare_digest(str(form_token), str(sess_token)):
                return Response("invalid or missing CSRF token\n", 403)
        # 3) Operator login (only once accounts exist). The login page itself
        #    stays reachable, or nobody could ever log in.
        if request.endpoint in ("login", "login_post"):
            return None
        if _login_required() and _effective_role() is None:
            if request.method == "GET":
                return redirect(url_for("login", next=request.path))
            return Response("login required\n", 401)
        # 4) RBAC floor for state-changing requests: account management is
        #    admin-only; every other POST action needs operator. Reads are
        #    viewer-level and enforced per-route where needed. Logout is exempt
        #    from the operator floor — any authenticated session (viewer
        #    included) must always be able to end itself; step 3 already proved
        #    the request is authenticated.
        if request.method == "POST" and request.endpoint != "logout":
            needed = OperatorRole.ADMIN if request.path.startswith("/users") else OperatorRole.OPERATOR
            current = _effective_role()
            if current is None or not current.allows(needed):
                return Response("forbidden: your role does not allow this action\n", 403)
        return None

    def ctx():
        posture = bastion.safety_status().posture
        return {
            "posture": posture,
            "config": bastion.config,
            "current_user": session.get("_user"),
            "current_role": (_effective_role().value if _effective_role() else None),
            "login_mode": _login_required(),
        }

    # --- health --------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        return jsonify({
            "status": "ok",
            "product": "GreyNOC Bastion",
            "version": "0.1.0",
            "safety_posture": bastion.safety_status().posture,
        })

    # --- login / logout --------------------------------------------------------
    @app.get("/login")
    def login():
        if not _login_required():
            return redirect(url_for("overview"))
        return render_template("login.html", active_page=None, next=request.args.get("next", "/"),
                               posture=bastion.safety_status().posture, config=bastion.config,
                               current_user=None, current_role=None, login_mode=True)

    @app.post("/login")
    def login_post():
        if not _login_required():
            return redirect(url_for("overview"))
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        key = f"{request.remote_addr}|{username}"
        if throttle.blocked(key):
            bastion.db.audit("login_throttled", actor=username or "(empty)",
                             detail="too many failures; temporarily blocked")
            return Response("too many failed logins; try again later\n", 429)
        role = bastion.operators.verify(username, password)
        if role is None:
            throttle.record_failure(key)
            flash("Login failed.")
            return redirect(url_for("login"))
        throttle.reset(key)
        session["_user"] = username
        # Rotate the CSRF token on privilege change (login).
        session["_csrf"] = secrets.token_urlsafe(32)
        return redirect(_safe_next(request.form.get("next")))

    @app.post("/logout")
    def logout():
        actor = _actor()
        session.pop("_user", None)
        session.pop("_token_fp", None)
        session["_csrf"] = secrets.token_urlsafe(32)
        bastion.db.audit("logout", actor=actor)
        return redirect(url_for("login") if _login_required() else url_for("overview"))

    # --- pages ---------------------------------------------------------------
    @app.get("/")
    def overview():
        status = bastion.status()
        findings = bastion.db.list_findings(limit=10)
        findings.sort(key=lambda f: f.priority_score, reverse=True)
        return render_template(
            "overview.html", active_page="overview",
            status=status, counts=status["counts"], top_findings=findings[:10],
            case_summary=bastion.cases.summary(), **ctx())

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

    @app.get("/cases")
    def cases():
        return render_template("cases.html", active_page="cases",
                               queue=bastion.cases.workqueue(),
                               all_cases=bastion.cases.list_cases(),
                               summary=bastion.cases.summary(), **ctx())

    @app.get("/schedules")
    def schedules():
        return render_template("schedules.html", active_page="schedules",
                               schedules=bastion.scheduler.list_schedules(),
                               workflows=bastion.orchestrator.list_workflows(), **ctx())

    @app.get("/audit")
    def audit():
        _require(OperatorRole.OPERATOR)
        return render_template("audit.html", active_page="audit",
                               entries=bastion.db.recent_audit(limit=200), **ctx())

    @app.get("/users")
    def users():
        _require(OperatorRole.ADMIN)
        return render_template("users.html", active_page="users",
                               operators=bastion.operators.list_operators(), **ctx())

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

    @app.post("/run/workflow")
    def run_workflow():
        name = (request.form.get("name") or "").strip()
        try:
            result = bastion.orchestrator.run(name, actor=_actor())
        except ValueError as exc:
            flash(f"Workflow refused: {exc}")
            return redirect(url_for("schedules"))
        ok = sum(1 for s in result["steps"] if s["ok"])
        flash(f"Workflow '{name}': {ok}/{len(result['steps'])} steps ok.")
        return redirect(url_for("schedules"))

    # --- case actions -----------------------------------------------------------
    @app.post("/cases/open")
    def cases_open():
        try:
            case = bastion.cases.open_case(
                request.form.get("title", ""),
                severity=request.form.get("severity") or None,
                assignee=request.form.get("assignee", ""),
                actor=_actor())
            flash(f"Opened {case.case_id}.")
        except CaseError as exc:
            flash(f"Case refused: {exc}")
        return redirect(url_for("cases"))

    @app.post("/cases/triage")
    def cases_triage():
        opened = bastion.cases.open_from_findings(actor=_actor())
        flash(f"Triage sweep opened {len(opened)} case(s) for untracked high+ findings.")
        return redirect(url_for("cases"))

    @app.post("/cases/<case_id>/assign")
    def cases_assign(case_id):
        try:
            case = bastion.cases.assign(case_id, request.form.get("assignee", ""), actor=_actor())
            flash(f"{case.case_id} → {case.assignee or '(unassigned)'}.")
        except CaseError as exc:
            flash(f"Assign refused: {exc}")
        return redirect(url_for("cases"))

    @app.post("/cases/<case_id>/note")
    def cases_note(case_id):
        try:
            bastion.cases.add_note(case_id, request.form.get("text", ""), actor=_actor())
            flash("Note added.")
        except CaseError as exc:
            flash(f"Note refused: {exc}")
        return redirect(url_for("cases"))

    @app.post("/cases/<case_id>/close")
    def cases_close(case_id):
        try:
            bastion.cases.close(case_id, reason=request.form.get("reason", "resolved"), actor=_actor())
            flash(f"Case {case_id} closed.")
        except CaseError as exc:
            flash(f"Close refused: {exc}")
        return redirect(url_for("cases"))

    @app.post("/cases/<case_id>/reopen")
    def cases_reopen(case_id):
        try:
            bastion.cases.reopen(case_id, actor=_actor())
            flash(f"Case {case_id} reopened.")
        except CaseError as exc:
            flash(f"Reopen refused: {exc}")
        return redirect(url_for("cases"))

    # --- schedule actions ---------------------------------------------------------
    @app.post("/schedules/add")
    def schedules_add():
        try:
            record = bastion.scheduler.add(
                request.form.get("name", ""),
                kind=request.form.get("kind", "report"),
                interval_hours=float(request.form.get("every") or 24.0),
                workflow=request.form.get("workflow", ""),
                deliver_to=request.form.get("deliver_to", ""),
                actor=_actor(),
                # A web operator must not deliver report files outside the
                # Bastion home; the trusted local CLI has no such limit.
                restrict_base=bastion.config.home)
            flash(f"Schedule {record['schedule_id']} added (run it via `bastion schedule run-due`).")
        except (ScheduleError, ValueError) as exc:
            flash(f"Schedule refused: {exc}")
        return redirect(url_for("schedules"))

    @app.post("/schedules/<schedule_id>/toggle")
    def schedules_toggle(schedule_id):
        try:
            record = bastion.scheduler.set_enabled(
                schedule_id, request.form.get("enabled") == "1", actor=_actor())
            flash(f"Schedule {'enabled' if record['enabled'] else 'disabled'}.")
        except ScheduleError as exc:
            flash(f"Toggle refused: {exc}")
        return redirect(url_for("schedules"))

    @app.post("/schedules/<schedule_id>/remove")
    def schedules_remove(schedule_id):
        removed = bastion.scheduler.remove(schedule_id, actor=_actor())
        flash("Schedule removed." if removed else "Nothing removed (unknown id).")
        return redirect(url_for("schedules"))

    @app.post("/schedules/run-due")
    def schedules_run_due():
        outcomes = bastion.scheduler.run_due(actor=_actor())
        ok = sum(1 for o in outcomes if o["ok"])
        flash(f"Ran {len(outcomes)} due schedule(s); {ok} ok." if outcomes else "Nothing due.")
        return redirect(url_for("schedules"))

    # --- account management (admin) --------------------------------------------
    @app.post("/users/add")
    def users_add():
        try:
            info = bastion.operators.add(
                request.form.get("username", ""),
                request.form.get("password", ""),
                request.form.get("role", "operator"),
                actor=_actor())
            flash(f"Operator '{info['username']}' added ({info['role']}).")
        except AuthError as exc:
            flash(f"Refused: {exc}")
        return redirect(url_for("users"))

    @app.post("/users/<username>/role")
    def users_role(username):
        try:
            bastion.operators.set_role(username, request.form.get("role", ""), actor=_actor())
            flash(f"Role updated for '{username}'.")
        except AuthError as exc:
            flash(f"Refused: {exc}")
        return redirect(url_for("users"))

    @app.post("/users/<username>/state")
    def users_state(username):
        try:
            disable = request.form.get("disabled") == "1"
            bastion.operators.set_disabled(username, disable, actor=_actor())
            flash(f"Operator '{username}' {'disabled' if disable else 'enabled'}.")
        except AuthError as exc:
            flash(f"Refused: {exc}")
        return redirect(url_for("users"))

    @app.post("/users/<username>/password")
    def users_password(username):
        try:
            bastion.operators.set_password(username, request.form.get("password", ""), actor=_actor())
            flash(f"Password updated for '{username}'.")
        except AuthError as exc:
            flash(f"Refused: {exc}")
        return redirect(url_for("users"))

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
