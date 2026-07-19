"""Tests for the per-source feed cache and the cached ingest orchestration."""

from __future__ import annotations

import http.client
import json

import pytest

from greynoc_bastion.config import load_config
from greynoc_bastion.safety import fetcher as fetcher_mod
from greynoc_bastion.safety.netguard import NetGuardError
from greynoc_bastion.services.feed_cache import FeedCache, build_feed_cache_from_config
from greynoc_bastion.services.threat_forecast import ThreatForecastService

FEED = b'{"vulnerabilities": []}'
URL = "https://feed.example/cves.json"


# --- FeedCache unit ----------------------------------------------------------
def test_cache_roundtrip_and_freshness(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100)
    assert c.get(URL) is None                      # empty -> miss
    c.put(URL, FEED, 200, now=1000.0)
    entry = c.get(URL)
    assert entry is not None and entry.body == FEED and entry.status == 200
    assert c.is_fresh(entry, now=1050.0) is True   # within TTL
    assert c.is_fresh(entry, now=1101.0) is False  # past TTL


def test_cache_ttl_zero_is_never_fresh(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=0)
    c.put(URL, FEED, 200, now=1000.0)
    assert c.is_fresh(c.get(URL), now=1000.0) is False


def test_cache_tampered_body_is_a_miss(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100)
    c.put(URL, FEED, 200, now=1000.0)
    body_file = next(tmp_path.glob("*.body"))
    body_file.write_bytes(b"tampered-content")     # break the SHA-256
    assert c.get(URL) is None                      # integrity mismatch -> miss


def test_cache_missing_body_is_a_miss(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100)
    c.put(URL, FEED, 200, now=1000.0)
    next(tmp_path.glob("*.body")).unlink()
    assert c.get(URL) is None


def test_cache_malformed_meta_is_a_miss_not_a_crash(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100)
    c.put(URL, FEED, 200, now=1000.0)
    meta_file = next(tmp_path.glob("*.meta.json"))
    meta_file.write_text("{ not json", encoding="utf-8")
    assert c.get(URL) is None                      # must not raise


def test_cache_url_mismatch_is_a_miss(tmp_path):
    # If the stored url field does not match (hash collision / tamper), miss.
    c = FeedCache(tmp_path, ttl_seconds=100)
    c.put(URL, FEED, 200, now=1000.0)
    meta_file = next(tmp_path.glob("*.meta.json"))
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    meta["url"] = "https://feed.example/OTHER"
    meta_file.write_text(json.dumps(meta), encoding="utf-8")
    assert c.get(URL) is None


def test_cache_key_is_traversal_safe(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100)
    nasty = "https://feed.example/../../../../etc/passwd?x=/../y"
    c.put(nasty, FEED, 200, now=1000.0)
    # Every produced file sits directly in the cache dir; the stem is hex only.
    for p in tmp_path.iterdir():
        assert p.parent == tmp_path
        stem = p.name.split(".")[0]
        assert all(ch in "0123456789abcdef" for ch in stem)
    assert c.get(nasty) is not None                # still retrievable by url


def test_cache_prune_keeps_newest(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100, max_entries=3)
    for i in range(6):
        c.put(f"https://feed.example/{i}", FEED, 200, now=1000.0 + i)
    metas = list(tmp_path.glob("*.meta.json"))
    assert len(metas) <= 3                          # bounded
    # Pruning honors the logical fetched_at (not filesystem mtime), so the three
    # newest survive and the three oldest are evicted — deterministically.
    for i in (3, 4, 5):
        assert c.get(f"https://feed.example/{i}") is not None, i
    for i in (0, 1, 2):
        assert c.get(f"https://feed.example/{i}") is None, i


def test_cache_prune_tolerates_corrupt_meta(tmp_path):
    """A single damaged meta must not crash `_prune` (and thus `put`). The
    recency sort tolerates the same malformed shapes `get` tolerates. `max_entries`
    is set above the total so this isolates the no-crash property from eviction
    ordering."""
    c = FeedCache(tmp_path, ttl_seconds=100, max_entries=10)
    c.put(URL, FEED, 200, now=1000.0)
    # Malformed metas that must not raise during the next prune: valid-JSON
    # scalars, dicts with a non-numeric fetched_at, and invalid JSON.
    (tmp_path / "corrupt1.meta.json").write_text("null", encoding="utf-8")
    (tmp_path / "corrupt2.meta.json").write_text("123", encoding="utf-8")
    (tmp_path / "corrupt3.meta.json").write_text('{"fetched_at": null}', encoding="utf-8")
    (tmp_path / "corrupt4.meta.json").write_text('{"fetched_at": [1,2]}', encoding="utf-8")
    (tmp_path / "corrupt5.meta.json").write_text("{not json", encoding="utf-8")
    # This put triggers _prune; it must complete without raising.
    c.put("https://feed.example/new", FEED, 200, now=1001.0)
    # The real, well-formed entries remain retrievable (nothing evicted here).
    assert c.get(URL) is not None
    assert c.get("https://feed.example/new") is not None


def test_cache_prune_sweeps_orphan_bodies_and_temp_files(tmp_path):
    c = FeedCache(tmp_path, ttl_seconds=100, max_entries=10)
    c.put(URL, FEED, 200, now=1000.0)
    (tmp_path / "deadbeef.body").write_bytes(b"orphan body, no meta")   # crash orphan
    (tmp_path / "abc.body.tmp").write_bytes(b"leftover temp")           # stale temp
    c.put("https://feed.example/other", FEED, 200, now=1001.0)          # triggers _prune
    names = {p.name for p in tmp_path.iterdir()}
    assert "deadbeef.body" not in names             # orphan body swept
    assert not any(n.endswith(".tmp") for n in names)   # temp files swept
    assert c.get(URL) is not None                   # real entries intact


def test_build_feed_cache_respects_disable(tmp_path):
    cfg = load_config(overrides={"BASTION_HOME": str(tmp_path)})
    assert build_feed_cache_from_config(cfg) is not None    # on by default
    cfg_off = load_config(overrides={"BASTION_HOME": str(tmp_path), "BASTION_FETCH_CACHE": "false"})
    assert build_feed_cache_from_config(cfg_off) is None


# --- ingest_url orchestration ------------------------------------------------
class _FakeFetcher:
    def __init__(self, behavior):
        self.behavior = behavior
        self.calls = 0

    def fetch(self, url, audit=None):
        self.calls += 1
        if audit:
            audit("live_fetch", f"GET {url}")
        if isinstance(self.behavior, Exception):
            raise self.behavior
        return _FakeResult(self.behavior)


class _FakeResult:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status


def _svc(tmp_path, monkeypatch, behavior, *, extra=None):
    overrides = {
        "BASTION_HOME": str(tmp_path), "BASTION_LIVE_FETCH": "true",
        "BASTION_FETCH_ALLOWLIST": "feed.example",
        "BASTION_FETCH_CACHE_TTL_SECONDS": "100",
    }
    overrides.update(extra or {})
    cfg = load_config(overrides=overrides)
    fake = _FakeFetcher(behavior)
    monkeypatch.setattr(fetcher_mod, "build_fetcher_from_config", lambda c: fake)
    return ThreatForecastService(db=None, config=cfg), fake


def test_live_success_then_fresh_hit(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    svc.ingest_url(URL, persist=False, now=1000.0)
    assert fake.calls == 1                          # live fetch happened
    svc.ingest_url(URL, persist=False, now=1050.0)  # within TTL
    assert fake.calls == 1                          # served from cache, no 2nd call


def test_refresh_forces_live_over_fresh_cache(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    svc.ingest_url(URL, persist=False, now=1000.0)
    svc.ingest_url(URL, persist=False, now=1010.0, refresh=True)
    assert fake.calls == 2                          # refresh ignored the fresh cache


@pytest.mark.parametrize("exc", [OSError("net down"), TimeoutError("slow")])
def test_transport_failure_falls_back_to_stale(tmp_path, monkeypatch, exc):
    # Seed the cache with a good copy, then make live fetch fail on transport.
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    svc.ingest_url(URL, persist=False, now=1000.0)
    svc2, fake2 = _svc(tmp_path, monkeypatch, exc)
    threats = svc2.ingest_url(URL, persist=False, now=999999.0)  # past TTL -> live -> fail -> stale
    assert fake2.calls == 1 and threats == []       # attempted live, then served stale


def test_transport_failure_without_cache_raises(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, OSError("net down"))
    with pytest.raises(RuntimeError):
        svc.ingest_url(URL, persist=False, now=1000.0)


def test_guard_refusal_is_never_masked_by_cache(tmp_path, monkeypatch):
    # Seed cache, then a live fetch that raises a *policy* refusal (e.g. a
    # redirect off the allowlist). This must propagate, not serve stale.
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    svc.ingest_url(URL, persist=False, now=1000.0)
    svc2, fake2 = _svc(tmp_path, monkeypatch, NetGuardError("redirect off allowlist"))
    with pytest.raises(NetGuardError):
        svc2.ingest_url(URL, persist=False, now=999999.0)


def test_offline_uses_cache_only(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    svc.ingest_url(URL, persist=False, now=1000.0)
    svc2, fake2 = _svc(tmp_path, monkeypatch, OSError("must not be called"))
    svc2.ingest_url(URL, persist=False, now=999999.0, offline=True)
    assert fake2.calls == 0                          # offline never touches network


def test_offline_without_cache_raises(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    with pytest.raises(RuntimeError):
        svc.ingest_url("https://feed.example/uncached.json", persist=False, offline=True)
    assert fake.calls == 0


def test_policy_gate_refuses_non_allowlisted_before_any_network(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    with pytest.raises(NetGuardError):
        svc.ingest_url("https://evil.example/x.json", persist=False)
    assert fake.calls == 0                           # never reached the fetcher


def test_non_https_refused(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    with pytest.raises(NetGuardError):
        svc.ingest_url("http://feed.example/x.json", persist=False)
    assert fake.calls == 0


def test_live_fetch_disabled_refuses(tmp_path, monkeypatch):
    svc, fake = _svc(tmp_path, monkeypatch, FEED, extra={"BASTION_LIVE_FETCH": "false"})
    with pytest.raises(RuntimeError):
        svc.ingest_url(URL, persist=False)
    assert fake.calls == 0


def test_cache_disabled_no_shortcircuit_no_fallback(tmp_path, monkeypatch):
    # With caching off, every ingest hits the network and a transport failure
    # has no stale copy to fall back on.
    svc, fake = _svc(tmp_path, monkeypatch, FEED, extra={"BASTION_FETCH_CACHE": "false"})
    svc.ingest_url(URL, persist=False, now=1000.0)
    svc.ingest_url(URL, persist=False, now=1001.0)
    assert fake.calls == 2                            # no fresh short-circuit
    svc2, fake2 = _svc(tmp_path, monkeypatch, OSError("down"),
                       extra={"BASTION_FETCH_CACHE": "false"})
    with pytest.raises(RuntimeError):
        svc2.ingest_url(URL, persist=False, now=1002.0)


def test_malformed_http_response_falls_back_to_stale(tmp_path, monkeypatch):
    # A malformed/truncated HTTP response (http.client.HTTPException) is a
    # transport failure, not a policy refusal, so it must trigger the stale
    # fallback — HTTPException is NOT an OSError, so this is a distinct catch.
    svc, fake = _svc(tmp_path, monkeypatch, FEED)
    svc.ingest_url(URL, persist=False, now=1000.0)          # seed the cache
    svc2, fake2 = _svc(tmp_path, monkeypatch, http.client.BadStatusLine("garbled"))
    threats = svc2.ingest_url(URL, persist=False, now=999999.0)
    assert fake2.calls == 1 and threats == []              # served stale, no raise


def test_real_fetcher_dns_down_serves_stale(tmp_path, monkeypatch):
    # Regression for the review finding: a real DNS/network-down failure must
    # reach ingest_url as a transport error so the stale cache is served. This
    # drives the REAL SafeFetcher (not a fake) so it exercises the true
    # evaluate()->_pin_public_ip ordering the fake-fetcher tests bypass. Before
    # the fix, evaluate(resolve=True) resolved first and raised a fail-closed
    # NetGuardError that the `except OSError` fallback could not catch.
    cfg = load_config(overrides={
        "BASTION_HOME": str(tmp_path), "BASTION_LIVE_FETCH": "true",
        "BASTION_FETCH_ALLOWLIST": "feed.example",
        "BASTION_FETCH_CACHE_TTL_SECONDS": "100",
    })
    FeedCache(cfg.fetch_cache_dir, cfg.fetch_cache_ttl_seconds).put(URL, FEED, 200, now=1000.0)

    def _boom(*a, **k):
        raise OSError("network is unreachable")

    monkeypatch.setattr(fetcher_mod.socket, "getaddrinfo", _boom)   # DNS is down
    svc = ThreatForecastService(db=None, config=cfg)
    # Past TTL -> not fresh -> live fetch attempted -> DNS down -> stale fallback.
    threats = svc.ingest_url(URL, persist=False, now=999999.0)
    assert threats == []                                   # served stale, did not raise
