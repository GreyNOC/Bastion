"""Safety-layer tests: masking, scrubbing, and the network fetch guard."""

from __future__ import annotations

import pytest

from greynoc_bastion.safety import (
    NetGuardError,
    evaluate_fetch_target,
    fingerprint_secret,
    is_private_host,
    looks_like_secret,
    mask_secret,
    scrub_text,
)
from greynoc_bastion.safety.netguard import validate_redirect


# --- masking -----------------------------------------------------------------
def test_mask_never_contains_full_value():
    secret = "wJalrXUtnFGNOCK7MDbPxRfiCYzKq0011223344ab"
    masked = mask_secret(secret)
    assert "*" in masked
    assert secret not in masked
    assert masked[:4] == secret[:4]  # a recognizable prefix is kept


def test_mask_short_values_fully_starred():
    assert set(mask_secret("abc")) == {"*"}


def test_fingerprint_is_deterministic_and_one_way():
    a = fingerprint_secret("supersecret")
    b = fingerprint_secret("supersecret")
    assert a == b and len(a) == 16
    assert "supersecret" not in a


@pytest.mark.parametrize("text", [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "-----BEGIN RSA PRIVATE KEY-----",
    "api_key = sk-abcdefghijklmnop12345",
])
def test_looks_like_secret_detects_known_shapes(text):
    assert looks_like_secret(text)


def test_scrub_text_redacts_but_keeps_context():
    scrubbed = scrub_text("password = hunter2secretvalue123")
    assert "hunter2secretvalue123" not in scrubbed
    assert "password" in scrubbed


# --- private-host detection --------------------------------------------------
@pytest.mark.parametrize("host", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.1.1",
    "localhost", "::1", "0.0.0.0", "fe80::1", "100.64.0.1",
])
def test_private_hosts_are_blocked(host):
    assert is_private_host(host) is True


@pytest.mark.parametrize("host", ["www.cisa.gov", "services.nvd.nist.gov", "api.first.org"])
def test_public_hosts_not_flagged_private(host):
    assert is_private_host(host) is False


# --- fetch guard -------------------------------------------------------------
def test_fetch_blocked_when_live_fetch_disabled():
    d = evaluate_fetch_target("https://www.cisa.gov/x", live_fetch_enabled=False,
                              allowlist=["www.cisa.gov"])
    assert not d.allowed and "disabled" in d.reason.lower()


def test_fetch_blocked_for_private_host_even_if_allowlisted():
    d = evaluate_fetch_target("https://127.0.0.1/x", live_fetch_enabled=True,
                              allowlist=["127.0.0.1"])
    assert not d.allowed
    assert "private" in d.reason.lower() or "loopback" in d.reason.lower()


def test_fetch_blocked_for_http_scheme():
    d = evaluate_fetch_target("http://www.cisa.gov/x", live_fetch_enabled=True,
                              allowlist=["www.cisa.gov"])
    assert not d.allowed and "https" in d.reason.lower()


def test_fetch_blocked_when_not_on_allowlist():
    d = evaluate_fetch_target("https://evil.example/x", live_fetch_enabled=True,
                              allowlist=["www.cisa.gov"])
    assert not d.allowed and "allowlist" in d.reason.lower()


def test_fetch_allowed_only_when_all_conditions_met():
    d = evaluate_fetch_target("https://www.cisa.gov/known-exploited",
                              live_fetch_enabled=True, allowlist=["www.cisa.gov"])
    assert d.allowed and d.reason == "allowed"


def test_raise_if_blocked_raises():
    d = evaluate_fetch_target("http://x", live_fetch_enabled=True, allowlist=[])
    with pytest.raises(NetGuardError):
        d.raise_if_blocked()


def test_redirect_to_private_host_is_refused():
    d = validate_redirect("https://10.0.0.1/internal", allowlist=["www.cisa.gov"])
    assert not d.allowed
