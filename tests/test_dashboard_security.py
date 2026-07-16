"""Hardening tests: dashboard bind/auth/CSRF, active-check gating, evidence verify."""

from __future__ import annotations

import json

import pytest

from greynoc_bastion.cli import main
from greynoc_bastion.web.server import create_app, ensure_bind_allowed


# --- fail-closed binding -----------------------------------------------------
def test_loopback_bind_allowed():
    for host in ("127.0.0.1", "::1", "localhost"):
        ensure_bind_allowed(host)  # no raise


def test_non_loopback_bind_refused_by_default():
    for host in ("0.0.0.0", "192.168.1.10"):
        with pytest.raises(SystemExit):
            ensure_bind_allowed(host)  # allow_remote defaults False


def test_builtin_server_remote_bind_cannot_be_overridden():
    with pytest.raises(SystemExit):
        ensure_bind_allowed("0.0.0.0", allow_remote=True, has_token=False)
    with pytest.raises(SystemExit):
        ensure_bind_allowed("0.0.0.0", allow_remote=True, has_token=True)


def test_dashboard_auth_settings_resolved_from_config_not_only_env(monkeypatch, home):
    # A token placed in the environment (or .env) must land in the resolved
    # config so the dashboard actually enforces it — see the .env regression.
    from greynoc_bastion.config import load_config
    monkeypatch.setenv("BASTION_HOME", str(home))
    monkeypatch.setenv("BASTION_DASHBOARD_TOKEN", "from-env")
    monkeypatch.setenv("BASTION_ALLOW_REMOTE_DASHBOARD", "1")
    cfg = load_config()
    assert cfg.dashboard_token == "from-env"
    assert cfg.allow_remote_dashboard is True
    assert cfg.public_dict()["dashboard_token_set"] is True
    # public view must never expose the token value itself
    assert "from-env" not in str(cfg.public_dict())


# --- token auth --------------------------------------------------------------
def test_loopback_no_token_needs_no_auth(app):
    app.config.dashboard_token = ""
    client = create_app(app).test_client()
    assert client.get("/").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_token_auth_required_when_configured(app):
    app.config.dashboard_token = "tkn-xyz"  # simulate resolved config (.env or env)
    client = create_app(app).test_client()
    assert client.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/healthz").status_code == 200                # health stays open
    assert client.get("/", headers={"Authorization": "Bearer tkn-xyz"}).status_code == 200


def test_query_token_bootstraps_session(app):
    # ?token= authorizes the first request AND establishes a session so later
    # navigation/POSTs work without re-supplying the token (Codex :72).
    app.config.dashboard_token = "qt-123"
    client = create_app(app).test_client()
    assert client.get("/").status_code == 401                       # no token yet
    assert client.get("/?token=qt-123").status_code == 200          # bootstrap
    assert client.get("/forecast").status_code == 200               # session carries auth
    # a CSRF-token POST also works now that the session is authed
    client.get("/")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    assert client.post("/run/doctor", data={"csrf_token": csrf},
                       follow_redirects=True).status_code == 200


def test_query_token_is_refused_for_non_loopback_client(app):
    app.config.dashboard_token = "qt-123"
    client = create_app(app).test_client()
    assert client.get("/?token=qt-123", environ_base={"REMOTE_ADDR": "192.0.2.10"}).status_code == 401


# --- CSRF --------------------------------------------------------------------
def test_csrf_rejects_missing_or_bad_token(app):
    app.config.dashboard_token = ""
    client = create_app(app).test_client()
    # No token at all -> 403
    assert client.post("/run/doctor").status_code == 403
    # Wrong token -> 403
    client.get("/")  # establish a session token
    assert client.post("/run/doctor", data={"csrf_token": "nope"}).status_code == 403


def test_csrf_accepts_valid_token(app):
    app.config.dashboard_token = ""
    client = create_app(app).test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess["_csrf"]
    r = client.post("/run/doctor", data={"csrf_token": token}, follow_redirects=True)
    assert r.status_code == 200


def test_bearer_post_is_csrf_exempt(app):
    app.config.dashboard_token = "tkn-abc"
    client = create_app(app).test_client()
    r = client.post("/run/doctor", headers={"Authorization": "Bearer tkn-abc"}, follow_redirects=True)
    assert r.status_code == 200


# --- CLI active-check gating -------------------------------------------------
def test_cli_active_refused_without_config(monkeypatch, home):
    monkeypatch.setenv("BASTION_HOME", str(home))
    monkeypatch.delenv("BASTION_ACTIVE_CHECKS", raising=False)
    rc = main(["assets", "scan-local", "--active"])
    assert rc == 2  # safe refusal


def test_cli_active_allowed_with_config(monkeypatch, home):
    monkeypatch.setenv("BASTION_HOME", str(home))
    monkeypatch.setenv("BASTION_ACTIVE_CHECKS", "true")
    rc = main(["assets", "scan-local", "--active"])
    assert rc == 0


def test_cli_passive_is_default(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    rc = main(["assets", "scan-local"])
    out = capsys.readouterr().out
    assert rc == 0 and "passive" in out


# --- evidence verify CLI -----------------------------------------------------
def _build_bundle(app, tmp_path):
    from greynoc_bastion.schemas import BastionFinding, BastionReport, Severity
    f = BastionFinding(title="x", severity=Severity.LOW)
    rep = BastionReport(title="t", findings=[f]).recompute_summary()
    return app.evidence_center.build_bundle(rep, tmp_path)


def test_cli_evidence_verify_ok(app, tmp_path, monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    bundle = _build_bundle(app, tmp_path)
    rc = main(["evidence", "verify", bundle])
    out = capsys.readouterr().out
    assert rc == 0
    assert "OK" in out and "Problems: 0" in out


def test_cli_evidence_verify_fails_on_bad_bundle(monkeypatch, home, tmp_path, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    bad = tmp_path / "bad.evidence.zip"
    bad.write_text("not a zip", encoding="utf-8")
    rc = main(["evidence", "verify", str(bad)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAILED" in out


def test_cli_evidence_verify_json(app, tmp_path, monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    bundle = _build_bundle(app, tmp_path)
    rc = main(["evidence", "verify", bundle, "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["ok"] is True


# --- no full secrets in any report output (still holds after changes) --------
def test_no_full_secret_in_reports_after_hardening(app, sample_project, tmp_path):
    app.identity.scan(sample_project, persist=True)
    out = tmp_path / "reports_out"
    app.build_report(out_dir=out)
    for fp in out.iterdir():
        if not fp.is_file():
            continue
        data = fp.read_bytes()
        for secret in (b"wJalrXUtnFGNOCK7MDbPxRfiCYzKq0011223344ab",
                       b"ghp_GN0Cfake1234567890abcdefghijklmnopqrst"):
            assert secret not in data, fp
