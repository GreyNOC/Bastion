"""Tests for the guarded live fetcher and the custom rule-pack loader."""

from __future__ import annotations

import io
import json

import pytest

from greynoc_bastion.adapters.dmz_adapter import DmzAdapter
from greynoc_bastion.safety import fetcher as fetcher_mod
from greynoc_bastion.safety.fetcher import (
    FetchResult,
    SafeFetcher,
    _read_capped,
    _resolve_redirect,
)
from greynoc_bastion.safety.netguard import NetGuardError


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

    body, trunc = _read_capped(FakeResp(b"A" * 100), 50, timeout_seconds=5)
    assert len(body) == 50 and trunc is True
    body, trunc = _read_capped(FakeResp(b"A" * 30), 50, timeout_seconds=5)
    assert len(body) == 30 and trunc is False


def test_read_capped_enforces_time_budget(monkeypatch):
    # A response that never ends must not stall the worker forever — the read
    # loop has a wall-clock budget (simulated by advancing the clock).
    class Endless:
        def read(self, n):
            return b"A"  # never returns empty

    ticks = iter([0.0, 100.0, 100.0])  # start, then past the deadline
    monkeypatch.setattr(fetcher_mod.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError):
        _read_capped(Endless(), max_bytes=10 ** 9, timeout_seconds=1)


def test_resolve_redirect_absolute_and_relative():
    assert _resolve_redirect("https://h/a/b", "https://other/x") == "https://other/x"
    assert _resolve_redirect("https://h/a/b", "/c") == "https://h/c"


# --- SSRF pin: connect only to vetted public IPs (DNS-rebinding defense) ------
def _fake_getaddrinfo(*addrs):
    def _f(host, port, *a, **k):
        return [(2, 1, 6, "", (ip, 0)) for ip in addrs]
    return _f


def test_pin_refuses_private_resolution(monkeypatch):
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"])
    monkeypatch.setattr(fetcher_mod.socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.5"))
    with pytest.raises(NetGuardError):
        f._pin_public_ip("feed.example")


def test_pin_refuses_when_any_address_is_private(monkeypatch):
    # DNS returning one public + one private address must be refused (any private
    # answer blocks — this is the rebinding / multi-A-record defense).
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"])
    monkeypatch.setattr(fetcher_mod.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34", "127.0.0.1"))
    with pytest.raises(NetGuardError):
        f._pin_public_ip("feed.example")


def test_pin_accepts_public_resolution(monkeypatch):
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"])
    monkeypatch.setattr(fetcher_mod.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert f._pin_public_ip("feed.example") == "93.184.216.34"


def test_pin_resolution_failure_is_transport_error(monkeypatch):
    # A DNS/resolution failure is a *transport* problem, raised as OSError (not
    # NetGuardError) so the ingest path can fall back to a cached copy. A
    # resolve-to-private address stays a NetGuardError (covered above).
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"])

    def _boom(*a, **k):
        raise OSError("temporary failure in name resolution")

    monkeypatch.setattr(fetcher_mod.socket, "getaddrinfo", _boom)
    with pytest.raises(OSError):
        f._pin_public_ip("feed.example")
    assert not isinstance(OSError(), NetGuardError)  # the two are disjoint


# --- fetch flow via an injected fake connection (no real network) ------------
class _FakeResp:
    def __init__(self, status, headers, body):
        self.status = status
        self._headers = {k.lower(): v for k, v in headers.items()}
        self._b = io.BytesIO(body)

    def getheader(self, k):
        return self._headers.get(k.lower())

    def read(self, n):
        return self._b.read(n)


class _FakeConn:
    queue: list = []

    def __init__(self, host, ip, port, timeout):
        self.host = host

    def request(self, *a, **k):
        pass

    def getresponse(self):
        return _FakeConn.queue.pop(0)

    def close(self):
        pass


def _allowlist_evaluate(allowlist):
    """A real guard evaluation (allowlist + https enforced) without DNS."""
    from greynoc_bastion.safety.netguard import evaluate_fetch_target
    return lambda url: evaluate_fetch_target(
        url, live_fetch_enabled=True, allowlist=allowlist, resolve=False)


@pytest.fixture
def fake_conn(monkeypatch):
    _FakeConn.queue = []
    monkeypatch.setattr(fetcher_mod, "_PinnedHTTPSConnection", _FakeConn)
    # Bypass real DNS/pin for the transport-flow tests; the pin is covered above.
    monkeypatch.setattr(SafeFetcher, "_pin_public_ip", lambda self, host: "93.184.216.34")
    return _FakeConn


def test_fetch_success_flow(fake_conn):
    fake_conn.queue = [_FakeResp(200, {}, b'{"vulnerabilities": []}')]
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"], timeout_seconds=5)
    f.evaluate = _allowlist_evaluate(["feed.example"])
    result = f.fetch("https://feed.example/cves.json")
    assert isinstance(result, FetchResult) and result.status == 200
    assert json.loads(result.body) == {"vulnerabilities": []}


def test_fetch_size_capped_flow(fake_conn):
    fake_conn.queue = [_FakeResp(200, {}, b"X" * 5000)]
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"], max_bytes=1000, timeout_seconds=5)
    f.evaluate = _allowlist_evaluate(["feed.example"])
    result = f.fetch("https://feed.example/big")
    assert result.truncated is True and len(result.body) == 1000


def test_redirect_to_nonallowlisted_is_refused(fake_conn):
    # 302 -> blocked.example: the loop re-evaluates the redirect through the real
    # guard (allowlist), which refuses it. Redirects never bypass the allowlist.
    fake_conn.queue = [_FakeResp(302, {"Location": "https://blocked.example/x"}, b"")]
    f = SafeFetcher(live_fetch_enabled=True, allowlist=["feed.example"], timeout_seconds=5)
    f.evaluate = _allowlist_evaluate(["feed.example"])
    with pytest.raises(NetGuardError):
        f.fetch("https://feed.example/redir")


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


def test_redos_bounded_outer_quantifier_refused():
    # Security review finding: a bounded outer quantifier over an unbounded inner
    # group backtracks catastrophically and must be refused.
    from greynoc_bastion.utils.redos import is_safe_regex
    for bad in [r"(a+){30}b", r"(a+){1,40}b", r"(\d+){25}x", r"([a-z]+){20}0", r"(.+){25}!"]:
        assert not is_safe_regex(bad)[0], bad
    for good in [r"(abc){3}", r"(a){2,5}x", r"(foo|bar){1,3}", r"\d{1,4}", r"(ab){10}"]:
        assert is_safe_regex(good)[0], good


def test_custom_rules_survive_recursion_error(tmp_path, monkeypatch):
    # Deeply-nested JSON raises RecursionError, not JSONDecodeError; the loader
    # must record it as rejected and keep going, not abort the whole load.
    _write(tmp_path, "deep.json", "[" * 200 + "]" * 200)   # deeply nested
    _write(tmp_path, "good.json", {
        "id": "CUST-OK", "name": "ok", "event_type": "auth_failed",
        "match": {"message": {"op": "contains", "value": "x"}}, "mitre": ["T1110"]})
    result = DmzAdapter().load_custom_rules(tmp_path)  # must not raise
    assert result["accepted_count"] == 1
    assert any(r.get("file") == "deep.json" for r in result["rejected"])


def test_custom_rule_cannot_shadow_bundled_id(tmp_path):
    # A custom rule reusing a bundled (validated) rule id must be rejected so it
    # cannot overwrite a validated detection in the store (INSERT OR REPLACE).
    _write(tmp_path, "shadow.json", {
        "id": "GNOC-AUTH-001", "name": "shadow", "event_type": "auth_failed",
        "match": {"message": {"op": "contains", "value": "x"}}, "mitre": ["T1110"],
    })
    result = DmzAdapter().load_custom_rules(tmp_path)
    assert result["accepted_count"] == 0
    assert any("collides with a bundled" in "; ".join(r["errors"]) for r in result["rejected"])


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
