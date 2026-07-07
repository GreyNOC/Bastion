"""CLI, doctor, dashboard-health, and end-to-end app tests."""

from __future__ import annotations

import json

from greynoc_bastion.cli import main
from greynoc_bastion.web.server import create_app


# --- doctor ------------------------------------------------------------------
def test_doctor_passes_on_safe_defaults(app):
    result = app.doctor()
    assert result["ok"] is True
    names = {c["name"] for c in result["checks"]}
    assert "api_loopback_binding" in names
    assert "secret_masking_active" in names
    assert "ai_command_execution_disabled" in names
    assert "no_offensive_playbooks" in names


def test_doctor_flags_command_execution(config):
    config.ai_assistant = True
    config.ai_command_execution = True
    from greynoc_bastion.app import BastionApp
    app = BastionApp(config)
    result = app.doctor()
    exec_check = next(c for c in result["checks"] if c["name"] == "ai_command_execution_disabled")
    assert exec_check["ok"] is False


def test_cli_doctor_command(monkeypatch, home):
    monkeypatch.setenv("BASTION_HOME", str(home))
    rc = main(["doctor"])
    assert rc == 0


def test_cli_forecast_demo(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    rc = main(["forecast", "demo", "--pretty"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Threat Forecast" in out
    assert "CVE-2026-12345" in out


def test_cli_status_json(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    rc = main(["--json", "status"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["product"] == "GreyNOC Bastion"
    assert data["config"]["loopback_only"] is True


def test_cli_playbooks_list(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    rc = main(["playbooks", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Operator Playbooks" in out


# --- dashboard health --------------------------------------------------------
def test_dashboard_health_route(app):
    client = create_app(app).test_client()
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "ok"
    assert body["safety_posture"] == "hardened"


def test_dashboard_pages_render(app):
    client = create_app(app).test_client()
    for path in ["/", "/forecast", "/identities", "/detections",
                 "/playbooks", "/assets", "/reports", "/settings", "/safety"]:
        r = client.get(path)
        assert r.status_code == 200, path


def test_dashboard_no_secret_leak_after_scan(app, sample_project):
    app.identity.scan(sample_project, persist=True)
    client = create_app(app).test_client()
    r = client.get("/identities")
    assert b"wJalrXUtnFGNOCK7MDbPxRfiCYzKq0011223344ab" not in r.data


# --- end-to-end + logs -------------------------------------------------------
def test_end_to_end_pipeline_and_report(app, sample_project, tmp_path):
    app.threat_forecast.demo(sectors=["healthcare"], persist=True)
    app.identity.scan(sample_project, persist=True)
    app.detection.validate_all(persist=True)
    app.assets.scan_local(passive=True, observations=[
        {"host": "0.0.0.0", "port": 445, "exposure": "lan"},
    ], persist=True)
    report = app.build_report(out_dir=tmp_path)
    assert report.summary.total_findings > 0
    assert "html" in report.output_paths
    assert "evidence_bundle" in report.output_paths


def test_no_full_secrets_in_logs(app, sample_project, caplog):
    import logging
    caplog.set_level(logging.DEBUG, logger="greynoc_bastion")
    app.identity.scan(sample_project, persist=True)
    for secret in ("wJalrXUtnFGNOCK7MDbPxRfiCYzKq0011223344ab",
                   "ghp_GN0Cfake1234567890abcdefghijklmnopqrst"):
        assert secret not in caplog.text


def test_audit_log_records_asset_scan(app):
    app.assets.scan_local(passive=True, observations=[
        {"host": "127.0.0.1", "port": 8080, "exposure": "loopback"},
    ], persist=True)
    audit = app.db.recent_audit()
    assert any(a["action"] == "asset_scan_local" for a in audit)
