"""Network fetch guard.

All outbound fetching (only ever the optional threat-feed fetcher) must pass
through :func:`evaluate_fetch_target` first. The guard enforces, in order:

  1. Live fetching must be explicitly enabled.
  2. Scheme must be ``https``.
  3. Host must not be private, loopback, link-local, or otherwise non-public
     (SSRF protection) — checked against literal IPs and, when resolution is
     requested, every address the host resolves to.
  4. Host must appear on the operator's allowlist.

Size and timeout caps live on the decision object and are applied by the
fetcher. This module performs no network I/O unless ``resolve=True`` is passed.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse


class NetGuardError(Exception):
    """Raised when a fetch target is refused by the guard."""


# Hostnames that always mean "this machine" regardless of resolution.
_LOCAL_NAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


@dataclasses.dataclass
class FetchDecision:
    """The guard's verdict for a single URL."""

    url: str
    allowed: bool
    reason: str
    host: str = ""
    scheme: str = ""
    max_bytes: int = 10 * 1024 * 1024
    timeout_seconds: int = 20

    def raise_if_blocked(self) -> "FetchDecision":
        if not self.allowed:
            raise NetGuardError(self.reason)
        return self


# Special-use ranges that are NOT flagged by ``ipaddress.is_private`` but must
# still be refused for SSRF safety (shared CGNAT space, test-nets, benchmarking,
# and the 6to4 relay anycast prefix).
_EXTRA_BLOCKED_NETS = [
    ipaddress.ip_network("100.64.0.0/10"),   # RFC 6598 shared address space
    ipaddress.ip_network("192.0.0.0/24"),    # RFC 6890 IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),     # reserved (future use)
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast
]


def _is_non_public_ip(ip: ipaddress._BaseAddress) -> bool:
    """True for any address a defensive fetcher must never reach."""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (getattr(ip, "is_site_local", False))
    ):
        return True
    for net in _EXTRA_BLOCKED_NETS:
        if ip.version == net.version and ip in net:
            return True
    return False


def is_private_host(host: str, *, resolve: bool = False) -> bool:
    """Return True if ``host`` is private/loopback/link-local/reserved.

    Handles literal IPv4/IPv6 addresses and well-known local names directly.
    For DNS names, returns False unless ``resolve=True``, in which case every
    resolved address is checked (a single private answer blocks the host).
    """
    if not host:
        return True
    h = host.strip().lower().strip("[]")
    if h in _LOCAL_NAMES:
        return True
    # Literal IP?
    try:
        ip = ipaddress.ip_address(h)
        return _is_non_public_ip(ip)
    except ValueError:
        pass
    # ``.local`` / mDNS names are LAN-only by convention.
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    if not resolve:
        return False
    # Resolve and check every address. Any resolution failure is treated as
    # unsafe (fail closed).
    try:
        infos = socket.getaddrinfo(h, None)
    except OSError:
        return True
    for info in infos:
        sockaddr = info[4]
        addr = sockaddr[0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return True
        if _is_non_public_ip(ip):
            return True
    return False


def evaluate_fetch_target(
    url: str,
    *,
    live_fetch_enabled: bool,
    allowlist: List[str],
    max_bytes: int = 10 * 1024 * 1024,
    timeout_seconds: int = 20,
    resolve: bool = False,
) -> FetchDecision:
    """Evaluate whether ``url`` may be fetched. Never performs the fetch.

    Returns a :class:`FetchDecision`; call ``.raise_if_blocked()`` to convert a
    refusal into a :class:`NetGuardError`.
    """
    decision = FetchDecision(
        url=url,
        allowed=False,
        reason="unevaluated",
        max_bytes=max_bytes,
        timeout_seconds=timeout_seconds,
    )

    if not live_fetch_enabled:
        decision.reason = "live fetching is disabled (BASTION_LIVE_FETCH=false)"
        return decision

    try:
        parsed = urlparse(url)
    except Exception:
        decision.reason = "malformed URL"
        return decision

    decision.scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    decision.host = host

    if decision.scheme != "https":
        decision.reason = f"scheme '{decision.scheme or 'none'}' refused; HTTPS only"
        return decision
    if not host:
        decision.reason = "URL has no host"
        return decision
    if is_private_host(host, resolve=resolve):
        decision.reason = f"host '{host}' is private/loopback/link-local; refused (SSRF guard)"
        return decision

    allow = {a.strip().lower() for a in allowlist if a and a.strip()}
    if host not in allow:
        decision.reason = f"host '{host}' is not on the fetch allowlist"
        return decision

    decision.allowed = True
    decision.reason = "allowed"
    return decision


def validate_redirect(
    location: str,
    *,
    allowlist: List[str],
    resolve: bool = False,
) -> FetchDecision:
    """Re-run the guard against a redirect ``Location`` (live fetch assumed on)."""
    return evaluate_fetch_target(
        location,
        live_fetch_enabled=True,
        allowlist=allowlist,
        resolve=resolve,
    )
