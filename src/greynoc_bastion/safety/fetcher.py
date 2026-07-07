"""Guarded live fetcher.

The *only* sanctioned way Bastion makes an outbound request. It is OFF unless
live fetching is explicitly enabled, and every request — including every
redirect hop — is evaluated by :mod:`greynoc_bastion.safety.netguard` first:

  * live fetching must be enabled;
  * HTTPS only;
  * host must be on the operator's allowlist;
  * host must not resolve to a private/loopback/link-local/CGNAT/test-net
    address (SSRF), re-checked at fetch time with DNS resolution;
  * response body is hard-capped by size; the request is time-capped;
  * redirects are never auto-followed — each ``Location`` is re-evaluated by the
    guard and only followed if it passes;
  * GET only, no credentials, a fixed User-Agent, no cookies.

Standard library only (``urllib``); no new runtime dependency.
"""

from __future__ import annotations

import dataclasses
import urllib.request
from urllib.parse import urljoin, urlparse

from ..utils.logging import get_logger
from .netguard import FetchDecision, NetGuardError, evaluate_fetch_target

_USER_AGENT = "GreyNOC-Bastion/0.1 (+defensive; local-first)"
_MAX_REDIRECTS = 3


@dataclasses.dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    body: bytes
    truncated: bool
    hops: int


class SafeFetcher:
    """A defensive, allowlisted, SSRF-guarded HTTPS GET fetcher (off by default)."""

    def __init__(
        self,
        *,
        live_fetch_enabled: bool,
        allowlist: list[str],
        max_bytes: int = 10 * 1024 * 1024,
        timeout_seconds: int = 20,
    ) -> None:
        self.live_fetch_enabled = live_fetch_enabled
        self.allowlist = list(allowlist or [])
        self.max_bytes = int(max_bytes)
        self.timeout_seconds = int(timeout_seconds)
        self.log = get_logger("fetcher")

    def evaluate(self, url: str) -> FetchDecision:
        """Pre-flight the guard for ``url`` (resolves DNS to catch SSRF)."""
        return evaluate_fetch_target(
            url,
            live_fetch_enabled=self.live_fetch_enabled,
            allowlist=self.allowlist,
            max_bytes=self.max_bytes,
            timeout_seconds=self.timeout_seconds,
            resolve=True,
        )

    def fetch(self, url: str, *, audit=None) -> FetchResult:
        """Fetch ``url`` if and only if it passes the guard at every hop.

        Raises :class:`NetGuardError` if the request (or any redirect) is
        refused, or :class:`URLError`/:class:`OSError` on transport failure.
        ``audit`` is an optional callable ``(action, detail)`` for logging.
        """
        current = url
        hops = 0
        while True:
            decision = self.evaluate(current).raise_if_blocked()
            if audit:
                audit("live_fetch", f"GET {decision.host} (allowlisted, https, public)")
            self.log.info("live fetch: GET %s", decision.host)

            req = urllib.request.Request(
                current,
                method="GET",
                headers={"User-Agent": _USER_AGENT, "Accept": "*/*"},
            )
            # Pin the connection to a verified-public address is handled by the
            # guard's resolve check above; urlopen performs its own resolution.
            opener = urllib.request.build_opener(_NoRedirect())
            try:
                resp = opener.open(req, timeout=self.timeout_seconds)
            except _RedirectSignal as redir:
                hops += 1
                if hops > _MAX_REDIRECTS:
                    raise NetGuardError(f"too many redirects (> {_MAX_REDIRECTS})") from None
                location = redir.location
                if not location:
                    raise NetGuardError("redirect without a Location header") from None
                current = _resolve_redirect(current, location)
                # Loop re-evaluates `current` through the guard before following.
                continue

            status = getattr(resp, "status", 200) or 200
            body, truncated = _read_capped(resp, self.max_bytes)
            resp.close()
            return FetchResult(url=url, final_url=current, status=int(status),
                               body=body, truncated=truncated, hops=hops)


class _RedirectSignal(Exception):
    def __init__(self, location: str | None):
        self.location = location


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into a signal instead of auto-following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802,D401
        raise _RedirectSignal(newurl)


def _resolve_redirect(base: str, location: str) -> str:
    """Resolve a redirect target to an absolute URL (relative allowed)."""
    parsed = urlparse(location)
    if parsed.scheme and parsed.netloc:
        return location
    # Relative redirect: join against the base origin.
    return urljoin(base, location)


def _read_capped(resp, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes`` from ``resp``; report truncation."""
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        chunk = resp.read(min(65536, max_bytes - total + 1))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            # Trim to exactly max_bytes and flag truncation.
            data = b"".join(chunks)[:max_bytes]
            return data, True
    return b"".join(chunks), False


def build_fetcher_from_config(config) -> SafeFetcher:
    """Construct a :class:`SafeFetcher` from a resolved BastionConfig."""
    return SafeFetcher(
        live_fetch_enabled=config.live_fetch,
        allowlist=config.fetch_allowlist,
        max_bytes=config.fetch_max_bytes,
        timeout_seconds=config.fetch_timeout_seconds,
    )


__all__ = ["SafeFetcher", "FetchResult", "build_fetcher_from_config"]
