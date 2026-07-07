"""Hardening tests: dashboard bind/auth/CSRF, active-check gating, evidence verify."""

from __future__ import annotations

import json

import pytest

from greynoc_bastion.cli import main
from greynoc_bastion.web.server import create_app, ensure_bind_allowed


# --- fail-closed binding -----------------------------------------------------
def test_loopback_bind_allowed(monkeypatch):
    for host in ("127.0.0.1", "::1", "localhost"):
        ensure_bind_allowed(host)  # no raise


def test_non_loopback_bind_refused_by_default(monkeypatch):
    monkeypatch.delenv("BASTION_ALLOW_REMOTE_DASHBOARD", raising=False)
    monkeypatch.delenv("BASTION_DASHBOARD_TOKEN", raising=False)
    for host in ("0.0.0.0", "192.168.1.10"):
        with pytest.raises(SystemExit):
            ensure_bind_allowed(host)


def test_remote_bind_requires_override_and_token(monkeypatch):
    monkeypatch.setenv("BASTION_ALLOW_REMOTE_DASHBOARD", "1")
    monkeypatch.delenv("BASTION_DASHBOARD_TOKEN", raising=False)
    # override set but no token -> still refused
    with pytest.raises(SystemExit):
        ensure_bind_allowed("0.0.0.0")
    # both set -> allowed
    monkeypatch.setenv("BASTION_DASHBOARD_TOKEN", "strong-token")
    ensure_bind_allowed("0.0.0.0")


# --- token auth --------------------------------------------------------------
def test_loopback_no_token_needs_no_auth(app, monkeypatch):
    monkeypatch.delenv("BASTION_DASHBOARD_TOKEN", raising=False)
    client = create_app(app).test_client()
    assert client.get("/").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_token_auth_required_when_configured(app, monkeypatch):
    monkeypatch.setenv("BASTION_DASHBOARD_TOKEN", "tkn-xyz")
    client = create_app(app).test_client()
    assert client.get("/").status_code == 401                       # no token
    assert client.get("/healthz").status_code == 200                # health stays open
    assert client.get("/", headers={"Authorization": "Bearer tkn-xyz"}).status_code == 200
    assert client.get("/?token=tkn-xyz").status_code == 200
    assert client.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 401


# --- CSRF --------------------------------------------------------------------
def test_csrf_rejects_missing_or_bad_token(app, monkeypatch):
    monkeypatch.delenv("BASTION_DASHBOARD_TOKEN", raising=False)
    client = create_app(app).test_client()
    # No token at all -> 403
    assert client.post("/run/doctor").status_code == 403
    # Wrong token -> 403
    client.get("/")  # establish a session token
    assert client.post("/run/doctor", data={"csrf_token": "nope"}).status_code == 403


def test_csrf_accepts_valid_token(app, monkeypatch):
    monkeypatch.delenv("BASTION_DASHBOARD_TOKEN", raising=False)
    client = create_app(app).test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess["_csrf"]
    r = client.post("/run/doctor", data={"csrf_token": token}, follow_redirects=True)
    assert r.status_code == 200


def test_bearer_post_is_csrf_exempt(app, monkeypatch):
    monkeypatch.setenv("BASTION_DASHBOARD_TOKEN", "tkn-abc")
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
