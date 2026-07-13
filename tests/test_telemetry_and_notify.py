"""Live telemetry replay and the notification fabric."""

from __future__ import annotations

import json

import pytest

from greynoc_bastion.app import BastionApp
from greynoc_bastion.config import load_config
from greynoc_bastion.safety.fetcher import FetchResult
from greynoc_bastion.services.telemetry_ingest import TelemetryIngestError


def _auth_events(n=6, host="web1"):
    return [{"event_type": "auth_failed", "host": host, "user": "svc",
             "message": "failed login for svc",
             "timestamp": f"2026-07-13T00:0{i}:00Z"} for i in range(n)]


def _write_jsonl(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return path


# --- telemetry replay ----------------------------------------------------------
def test_replay_jsonl_fires_matching_rule(app, tmp_path):
    log = _write_jsonl(tmp_path / "auth.jsonl", _auth_events())
    result = app.telemetry.replay_file(log)
    fired = {r["rule_id"] for r in result["rules_fired"]}
    assert "GNOC-AUTH-001" in fired
    assert result["alerts"] >= 1
    assert result["incidents"] and result["incidents"][0]["host"] == "web1"
    # Findings persisted and marked as live telemetry.
    findings = app.db.list_findings()
    assert any("Live telemetry" in f.title for f in findings)
    actions = [e["action"] for e in app.db.recent_audit(limit=10)]
    assert "telemetry_replayed" in actions


def test_replay_json_array_form(app, tmp_path):
    log = tmp_path / "auth.json"
    log.write_text(json.dumps(_auth_events()), encoding="utf-8")
    result = app.telemetry.replay_file(log)
    assert result["events"] == 6


def test_replay_skips_malformed_lines(app, tmp_path):
    lines = [json.dumps(e) for e in _auth_events()]
    lines.insert(2, "{not json at all")
    lines.insert(4, '"just a string"')
    log = tmp_path / "messy.jsonl"
    log.write_text("\n".join(lines), encoding="utf-8")
    result = app.telemetry.replay_file(log)
    assert result["events"] == 6
    assert result["skipped_lines"] == 2


def test_replay_refuses_oversized_file(app, tmp_path):
    log = tmp_path / "big.jsonl"
    log.write_text("x" * 2048, encoding="utf-8")
    with pytest.raises(TelemetryIngestError):
        app.telemetry.replay_file(log, max_bytes=1024)


def test_replay_missing_file_raises(app, tmp_path):
    with pytest.raises(TelemetryIngestError):
        app.telemetry.replay_file(tmp_path / "absent.jsonl")


def test_replay_event_cap(app, tmp_path):
    log = _write_jsonl(tmp_path / "many.jsonl", _auth_events(6))
    result = app.telemetry.replay_file(log, max_events=4)
    assert result["events"] == 4
    assert result["skipped_lines"] == 2


def test_replay_no_persist_mode(app, tmp_path):
    log = _write_jsonl(tmp_path / "auth.jsonl", _auth_events())
    app.telemetry.replay_file(log, persist=False)
    assert app.db.counts()["findings"] == 0


# --- notification fabric ---------------------------------------------------------
def _app_with_notify(home, **extra):
    overrides = {"BASTION_HOME": str(home), "BASTION_NOTIFY": "true", **extra}
    return BastionApp(load_config(overrides=overrides))


def test_notify_disabled_is_a_noop(app):
    result = app.notifications.notify("test", "hello")
    assert result["enabled"] is False and result["deliveries"] == []
    assert not (app.config.home / "notifications.jsonl").exists()


def test_notify_file_sink_writes_scrubbed_jsonl(home):
    napp = _app_with_notify(home)
    result = napp.notifications.notify(
        "test", "leak AKIAIOSFODNN7EXAMPLE here", detail="k = AKIAIOSFODNN7EXAMPLE")
    assert result["enabled"] and result["deliveries"][0]["ok"]
    body = (napp.config.home / "notifications.jsonl").read_text(encoding="utf-8")
    event = json.loads(body.splitlines()[0])
    assert event["kind"] == "test"
    assert "AKIAIOSFODNN7EXAMPLE" not in body


def test_notify_webhook_refused_off_allowlist_and_http(home):
    for url in ("https://hooks.example.com/x",      # not on the allowlist
                "http://allowed.example.com/x",     # not HTTPS
                "https://127.0.0.1/x"):             # private/loopback
        napp = _app_with_notify(
            home, BASTION_NOTIFY_WEBHOOK_URL=url,
            BASTION_NOTIFY_ALLOWLIST="allowed.example.com")
        result = napp.notifications.notify("test", "t")
        webhook = [d for d in result["deliveries"] if d["sink"] == "webhook"][0]
        assert webhook["ok"] is False


def test_notify_webhook_delivers_when_allowed(home, monkeypatch):
    napp = _app_with_notify(
        home, BASTION_NOTIFY_WEBHOOK_URL="https://allowed.example.com/hook",
        BASTION_NOTIFY_ALLOWLIST="allowed.example.com")
    sent = {}

    def fake_post(self, url, payload, audit=None):
        sent["url"], sent["payload"] = url, payload
        return FetchResult(url=url, final_url=url, status=200, body=b"", truncated=False, hops=0)

    monkeypatch.setattr("greynoc_bastion.safety.fetcher.SafeFetcher.post_json", fake_post)
    result = napp.notifications.notify("test", "delivered?")
    webhook = [d for d in result["deliveries"] if d["sink"] == "webhook"][0]
    assert webhook["ok"] is True and webhook["status"] == 200
    assert sent["payload"]["title"] == "delivered?"


def test_notify_failure_is_reported_not_raised(home, monkeypatch):
    napp = _app_with_notify(
        home, BASTION_NOTIFY_WEBHOOK_URL="https://allowed.example.com/hook",
        BASTION_NOTIFY_ALLOWLIST="allowed.example.com")

    def fake_post(self, url, payload, audit=None):
        raise OSError("network down")

    monkeypatch.setattr("greynoc_bastion.safety.fetcher.SafeFetcher.post_json", fake_post)
    result = napp.notifications.notify("test", "t")
    webhook = [d for d in result["deliveries"] if d["sink"] == "webhook"][0]
    assert webhook["ok"] is False and "network down" in webhook["error"]
    actions = [e["action"] for e in napp.db.recent_audit(limit=10)]
    assert "notification_failed" in actions
