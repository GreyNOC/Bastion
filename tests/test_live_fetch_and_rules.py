"""Tests for the guarded live fetcher and the custom rule-pack loader."""

from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from greynoc_bastion.adapters.dmz_adapter import DmzAdapter
from greynoc_bastion.safety.fetcher import (
    FetchResult,
    SafeFetcher,
    _read_capped,
    _resolve_redirect,
)
from greynoc_bastion.safety.netguard import FetchDecision, NetGuardError


# --- guard refusals (deterministic, no network) ------------------------------
def test_fetcher_off_by_default_refuses():
    f = SafeFetcher(live_fetch_enabled=False, allowlist=["www.cisa.gov"])
    assert not f.evaluate("https://www.cisa.gov/x").allowed
    with pytest.raises(NetGuardError):
        f.fetch("https://www.cisa.gov/x")


def test_fetcher_refuses_http_nonallowlist_and_private():
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["www.cisa.gov"])
    assert not f.evaluate("http://www.cisa.gov/x").allowed          # not https
    assert not f.evaluate("https://evil.example/x").allowed         # not allowlisted
    assert not f.evaluate("https://127.0.0.1/x").allowed            # private (SSRF)
    assert not f.evaluate("https://10.0.0.5/x").allowed
    for url in ("http://www.cisa.gov/x", "https://evil.example/x", "https://127.0.0.1/x"):
        with pytest.raises(NetGuardError):
            f.fetch(url)


def test_read_capped_truncates_and_flags():
    class FakeResp:
        def __init__(self, data):
            self._b = io.BytesIO(data)

        def read(self, n):
            return self._b.read(n)

    body, trunc = _read_capped(FakeResp(b"A" * 100), 50)
    assert len(body) == 50 and trunc is True
    body, trunc = _read_capped(FakeResp(b"A" * 30), 50)
    assert len(body) == 30 and trunc is False


def test_resolve_redirect_absolute_and_relative():
    assert _resolve_redirect("https://h/a/b", "https://other/x") == "https://other/x"
    assert _resolve_redirect("https://h/a/b", "/c") == "https://h/c"


# --- real transport against a loopback server (guard bypassed for the test) ---
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "https://blocked.example/next")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"X" * 5000)
        else:
            body = b'{"vulnerabilities": []}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture
def loopback_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _allow_only(host_ok):
    """Return an evaluate() replacement that allows only a given loopback host."""
    def _ev(url):
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        ok = host == "127.0.0.1" and host_ok
        return FetchDecision(url=url, allowed=ok, reason="test", host=host,
                             scheme="http", max_bytes=1024, timeout_seconds=5)
    return _ev


def test_fetch_success_over_loopback(loopback_server):
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["127.0.0.1"], max_bytes=1024, timeout_seconds=5)
    f.evaluate = _allow_only(True)  # bypass the private-host block for this transport test
    result = f.fetch(loopback_server + "/feed")
    assert isinstance(result, FetchResult)
    assert result.status == 200
    assert json.loads(result.body) == {"vulnerabilities": []}


def test_fetch_body_size_capped(loopback_server):
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["127.0.0.1"], max_bytes=1000, timeout_seconds=5)
    f.evaluate = _allow_only(True)
    result = f.fetch(loopback_server + "/big")
    assert result.truncated is True
    assert len(result.body) == 1000


def test_redirect_target_is_re_evaluated_and_refused(loopback_server):
    # The loopback origin is allowed, but its redirect to blocked.example must be
    # re-checked by the guard and refused — redirects never bypass the allowlist.
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["127.0.0.1"], timeout_seconds=5)
    f.evaluate = _allow_only(True)  # allows 127.0.0.1 only; blocked.example -> refused
    with pytest.raises(NetGuardError):
        f.fetch(loopback_server + "/redir")


# --- custom rule-pack loader -------------------------------------------------
def _write(d, name, content):
    p = d / name
    p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return p


def test_custom_rules_accept_and_reject(tmp_path):
    _write(tmp_path, "good.json", {
        "id": "CUST-1", "name": "ok", "event_type": "auth_failed",
        "match": {"message": {"op": "contains", "value": "failed login"}},
        "threshold": 5, "window_minutes": 10, "mitre": ["T1110"],
    })
    _write(tmp_path, "redos.json", {
        "id": "CUST-2", "name": "redos", "event_type": "process_event",
        "match": {"message": {"op": "regex", "value": "(a+)+$"}}, "mitre": ["T1059"],
    })
    _write(tmp_path, "shape.json", {"name": "no-id", "match": {}, "mitre": ["NOPE"]})
    _write(tmp_path, "broken.json", "{ not json")

    result = DmzAdapter().load_custom_rules(tmp_path)
    assert result["accepted_count"] == 1
    assert result["accepted"][0]["id"] == "CUST-1"
    rejected_ids = {(r.get("id") or r.get("file")) for r in result["rejected"]}
    assert "CUST-2" in rejected_ids            # ReDoS regex refused
    assert "shape.json" in rejected_ids        # missing required fields
    assert "broken.json" in rejected_ids       # invalid JSON


def test_custom_rules_reject_duplicate_ids(tmp_path):
    base = {"id": "DUP", "name": "d", "event_type": "auth_failed",
            "match": {"message": {"op": "contains", "value": "x"}}, "mitre": ["T1110"]}
    _write(tmp_path, "a.json", base)
    _write(tmp_path, "b.json", base)
    result = DmzAdapter().load_custom_rules(tmp_path)
    assert result["accepted_count"] == 1 and result["rejected_count"] == 1
    assert any("duplicate" in "; ".join(r["errors"]) for r in result["rejected"])


def test_custom_rules_missing_dir_is_not_fatal(tmp_path):
    result = DmzAdapter().load_custom_rules(tmp_path / "nope")
    assert result["accepted"] == [] and result["rejected"] == []


def test_app_load_custom_persists_accepted_as_drafts(app, tmp_path):
    from greynoc_bastion.schemas import ValidationStatus
    _write(tmp_path, "good.json", {
        "id": "CUST-DRAFT", "name": "ok", "event_type": "auth_failed",
        "match": {"message": {"op": "contains", "value": "failed login"}}, "mitre": ["T1110"],
    })
    result = app.load_custom_rules(tmp_path)
    assert result["accepted_count"] == 1
    stored = {d.detection_id: d for d in app.db.list_detections()}
    assert "CUST-DRAFT" in stored
    assert stored["CUST-DRAFT"].status is ValidationStatus.DRAFT  # never auto-validated
