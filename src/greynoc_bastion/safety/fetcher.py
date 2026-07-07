"""Guarded live fetcher.

The *only* sanctioned way Bastion makes an outbound request. It is OFF unless
live fetching is explicitly enabled, and every request — including every
redirect hop — is evaluated by :mod:`greynoc_bastion.safety.netguard` first:

  * live fetching must be enabled;
  * HTTPS only;
  * host must be on the operator's allowlist;
  * host must resolve *only* to public addresses (SSRF), and the connection is
    **pinned to the vetted IP** so a DNS-rebinding flip between check and connect
    cannot redirect us to a private/loopback/metadata address;
  * TLS certificate + hostname are validated (SNI uses the real hostname);
  * response body is hard-capped by size, and the read has a wall-clock budget;
  * redirects are never auto-followed — each ``Location`` is re-evaluated by the
    guard and only followed if it passes;
  * GET only, no credentials, a fixed User-Agent, identity encoding, no cookies.

Standard library only (``http.client``/``ssl``/``socket``); no new dependency.
"""

from __future__ import annotations

import dataclasses
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

from ..utils.logging import get_logger
from .netguard import (
    FetchDecision,
    NetGuardError,
    _is_non_public_ip,
    evaluate_fetch_target,
)

_USER_AGENT = "GreyNOC-Bastion/0.1 (+defensive; local-first)"
_MAX_REDIRECTS = 3
_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclasses.dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    body: bytes
    truncated: bool
    hops: int


class SafeFetcher:
    """A defensive, allowlisted, SSRF-guarded, IP-pinned HTTPS GET fetcher."""

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
        """Pre-flight the guard for ``url``: off/HTTPS/allowlist + literal-IP SSRF.

        This does NOT resolve DNS. Resolution-based SSRF is enforced
        authoritatively by :meth:`_pin_public_ip`, which resolves the host once
        and connects only to a vetted public IP. Keeping resolution in one place
        matters for the taxonomy: a name-resolution *failure* must surface as a
        transport error (``OSError`` from the pin), not as a fail-closed
        ``NetGuardError`` from a pre-flight resolve — otherwise a network-down
        feed can never fall back to a cached copy.
        """
        return evaluate_fetch_target(
            url,
            live_fetch_enabled=self.live_fetch_enabled,
            allowlist=self.allowlist,
            max_bytes=self.max_bytes,
            timeout_seconds=self.timeout_seconds,
            resolve=False,
        )

    def _pin_public_ip(self, host: str) -> str:
        """Resolve ``host`` once, refuse if any address is non-public, pin one.

        Returns a single vetted public IP the caller will connect to directly.
        Resolving here (and connecting to the returned IP) closes the DNS-rebinding
        TOCTOU: the address we vet is the address we dial.
        """
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            # Resolution failure is a *transport* problem (network down / DNS),
            # not a policy refusal: raise OSError so callers can fall back to a
            # cached copy. A resolve-to-private address below is still a hard
            # NetGuardError (SSRF), which must never be masked by the cache.
            raise OSError(f"could not resolve host '{host}': {exc}") from exc
        vetted: list[str] = []
        for info in infos:
            addr = str(info[4][0]).split("%")[0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                raise NetGuardError(f"host '{host}' returned a bad address") from None
            if _is_non_public_ip(ip):
                raise NetGuardError(
                    f"host '{host}' resolves to a non-public address ({addr}); refused (SSRF)"
                ) from None
            vetted.append(addr)
        if not vetted:
            raise NetGuardError(f"host '{host}' did not resolve to any address") from None
        return vetted[0]

    def fetch(self, url: str, *, audit=None) -> FetchResult:
        """Fetch ``url`` iff it passes the guard at every hop. Never auto-follows.

        Raises :class:`NetGuardError` if the request (or any redirect) is refused
        (policy / SSRF — never a transport problem), or a transport failure:
        :class:`OSError` (network down, DNS failure, ``TimeoutError``,
        ``ssl.SSLError``) or :class:`http.client.HTTPException` (malformed or
        truncated response). ``audit`` is an optional callable ``(action, detail)``.
        """
        current = url
        hops = 0
        while True:
            # 1) Off/HTTPS/allowlist + literal-IP SSRF checks (no DNS here).
            decision = self.evaluate(current).raise_if_blocked()
            parsed = urlparse(current)
            host = parsed.hostname or ""
            port = parsed.port or 443
            # 2) Authoritative resolve-and-pin: the ONLY place DNS is resolved.
            #    A resolution failure raises OSError (transport → caller may fall
            #    back to cache); a resolve-to-private raises NetGuardError (SSRF,
            #    never masked). Connect only to the vetted public IP.
            pinned_ip = self._pin_public_ip(host)
            if audit:
                audit("live_fetch", f"GET {decision.host} -> {pinned_ip} (allowlisted, https, pinned)")
            self.log.info("live fetch: GET %s (pinned %s)", host, pinned_ip)

            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            conn = _PinnedHTTPSConnection(host, pinned_ip, port, timeout=self.timeout_seconds)
            try:
                conn.request("GET", path, headers={
                    "Host": host,
                    "User-Agent": _USER_AGENT,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",   # no compression -> no decompression bomb
                    "Connection": "close",
                })
                resp = conn.getresponse()
                status = int(resp.status)
                if status in _REDIRECT_CODES:
                    hops += 1
                    if hops > _MAX_REDIRECTS:
                        raise NetGuardError(f"too many redirects (> {_MAX_REDIRECTS})")
                    location = resp.getheader("Location")
                    if not location:
                        raise NetGuardError("redirect without a Location header")
                    current = _resolve_redirect(current, location)
                    continue  # loop re-evaluates + re-pins the new target
                body, truncated = _read_capped(resp, self.max_bytes, self.timeout_seconds)
                return FetchResult(url=url, final_url=current, status=status,
                                   body=body, truncated=truncated, hops=hops)
            finally:
                conn.close()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a pinned IP but validates cert/SNI vs host."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: int):
        context = ssl.create_default_context()  # verifies certificate + hostname
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._ssl_context = context

    def connect(self) -> None:  # noqa: D401
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # SNI + cert hostname check use self.host (the real hostname), not the IP.
        self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)


def _resolve_redirect(base: str, location: str) -> str:
    """Resolve a redirect target to an absolute URL (relative allowed)."""
    parsed = urlparse(location)
    if parsed.scheme and parsed.netloc:
        return location
    return urljoin(base, location)


def _read_capped(resp, max_bytes: int, timeout_seconds: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes`` within a wall-clock budget; report truncation.

    Bounds both memory (``max_bytes``) and time (``timeout_seconds``) so a slow
    or endless response (slowloris-style) cannot stall the worker.
    """
    deadline = time.monotonic() + max(1, timeout_seconds)
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        if time.monotonic() > deadline:
            raise TimeoutError("live fetch exceeded its read time budget")
        chunk = resp.read(min(65536, max_bytes - total + 1))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            return b"".join(chunks)[:max_bytes], True
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
