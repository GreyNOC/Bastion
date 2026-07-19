"""Per-source cache for guarded live feeds.

A small, dependency-free, integrity-checked disk cache for the bodies returned
by the guarded live fetcher. It buys two things for the (opt-in) live-feed path:

  * **Freshness short-circuit** — inside a TTL window a repeated ingest of the
    same source is served from disk with no outbound request at all.
  * **Offline fallback** — when a live fetch fails on *transport* (network down,
    timeout, TLS error), a previously-cached copy can be served *stale* rather
    than failing the operator hard. See :mod:`greynoc_bastion.services.threat_forecast`.

Safety notes:

  * The cache is a **performance/availability aid, never a policy gate**. The
    caller re-checks the network guard (HTTPS + allowlist) on every ingest, so a
    cache hit can never resurrect a URL the operator has since de-allowlisted,
    nor serve anything while live fetch is disabled.
  * Only public threat-feed bodies are stored (never secrets). Files live under
    the operator's Bastion home. Each entry carries a SHA-256 of its body; a
    mismatch (accidental corruption or a truncated write) is treated as a miss,
    so a damaged cache file can never inject unverified content. This is a
    corruption check, not a MAC — the cache dir is the operator's own trusted
    storage, so it is not a boundary against someone who can already write there.
  * Filenames are derived from a SHA-256 of the URL, so a hostile URL cannot
    escape the cache directory (no path traversal).

Standard library only.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import time
from pathlib import Path

from ..utils.logging import get_logger

_META_SUFFIX = ".meta.json"
_BODY_SUFFIX = ".body"
_TMP_SUFFIX = ".tmp"
_DEFAULT_MAX_ENTRIES = 256


@dataclasses.dataclass
class CacheEntry:
    """A single cached feed body plus its provenance."""

    url: str
    body: bytes
    status: int
    fetched_at: float          # wall-clock epoch seconds when stored
    sha256: str

    def age_seconds(self, now: float) -> float:
        return max(0.0, now - self.fetched_at)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FeedCache:
    """An integrity-checked, per-URL disk cache for live-feed bodies."""

    def __init__(
        self,
        cache_dir: Path,
        ttl_seconds: int,
        *,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = int(ttl_seconds)
        self.max_entries = max(1, int(max_entries))
        self.log = get_logger("feed_cache")

    # --- key / path helpers --------------------------------------------------
    def _key(self, url: str) -> str:
        """A filesystem-safe, traversal-proof key for ``url``."""
        return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()

    def _meta_path(self, url: str) -> Path:
        return self.cache_dir / f"{self._key(url)}{_META_SUFFIX}"

    def _body_path(self, url: str) -> Path:
        return self.cache_dir / f"{self._key(url)}{_BODY_SUFFIX}"

    # --- read ----------------------------------------------------------------
    def get(self, url: str) -> CacheEntry | None:
        """Return the cached entry for ``url``, or ``None`` on miss/corruption.

        Any malformed metadata, missing body, or SHA-256 mismatch is treated as
        a miss (fail closed) — the cache never yields unverified bytes and never
        raises for a damaged file.
        """
        meta_path = self._meta_path(url)
        body_path = self._body_path(url)
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if not isinstance(meta, dict):
                return None
            body = body_path.read_bytes()
        except (OSError, ValueError, RecursionError):
            return None
        expected = meta.get("sha256")
        if not isinstance(expected, str) or _digest(body) != expected:
            self.log.warning("feed cache entry for %s failed integrity check; ignoring", url)
            return None
        try:
            fetched_at = float(meta.get("fetched_at", 0.0))
            status = int(meta.get("status", 0))
        except (TypeError, ValueError):
            return None
        stored_url = meta.get("url")
        if stored_url != url:  # key collision or a tampered url field
            return None
        return CacheEntry(url=url, body=body, status=status,
                          fetched_at=fetched_at, sha256=expected)

    def is_fresh(self, entry: CacheEntry, now: float | None = None) -> bool:
        """True if ``entry`` is within the TTL window (``ttl<=0`` is never fresh)."""
        if self.ttl_seconds <= 0:
            return False
        now = time.time() if now is None else now
        return entry.age_seconds(now) < self.ttl_seconds

    # --- write ---------------------------------------------------------------
    def put(self, url: str, body: bytes, status: int, now: float | None = None) -> CacheEntry:
        """Store ``body`` for ``url`` atomically and return the new entry."""
        now = time.time() if now is None else now
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        sha = _digest(body)
        entry = CacheEntry(url=url, body=body, status=int(status),
                           fetched_at=float(now), sha256=sha)
        meta = {
            "url": url,
            "status": entry.status,
            "fetched_at": entry.fetched_at,
            "sha256": sha,
            "size": len(body),
        }
        # Write body first, then meta, each via temp+replace so a reader never
        # sees a half-written file. Meta last means a present meta implies a
        # complete body (its hash is verified on read regardless).
        self._atomic_write_bytes(self._body_path(url), body)
        self._atomic_write_bytes(
            self._meta_path(url),
            json.dumps(meta, ensure_ascii=False).encode("utf-8"),
        )
        self._prune()
        return entry

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        tmp = path.with_suffix(path.suffix + _TMP_SUFFIX)
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # --- maintenance ---------------------------------------------------------
    def _prune(self) -> None:
        """Bound cache growth: keep the ``max_entries`` most recent (meta, body)
        pairs, and sweep orphaned bodies and stale temp files.

        The live allowlist is small, but query-string variation could otherwise
        grow the cache, and a crash mid-write could leave an orphan ``.body`` or
        a ``.tmp`` behind. Cleaning all three keeps disk use genuinely bounded.
        """
        def _recency(p: Path) -> tuple[float, str]:
            """Sort key: the logical ``fetched_at`` recorded in the meta is the
            authoritative recency, with the filename as a stable tiebreaker.
            Filesystem mtime is only a fallback for an unreadable meta — it is
            unreliable (equal under fast writes, and an AV scan or backup can
            touch a body file and reorder the cache).

            Must never raise: a corrupt meta (invalid JSON, not an object, or a
            non-numeric ``fetched_at``) is tolerated here exactly as ``get()``
            tolerates it — falling back to mtime — so a single damaged cache file
            can never crash ``_prune`` and, through it, a live ingest."""
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return (float(data.get("fetched_at", 0.0)), p.name)
            except (OSError, ValueError, TypeError):
                pass
            try:
                return (p.stat().st_mtime, p.name)
            except OSError:
                return (0.0, p.name)

        try:
            metas = sorted(
                self.cache_dir.glob(f"*{_META_SUFFIX}"),
                key=_recency,
                reverse=True,
            )
        except OSError:
            return

        def _unlink(p: Path) -> None:
            try:
                p.unlink()
            except OSError:
                pass

        # Trim complete pairs beyond the cap; remember which keys survive.
        keep_keys: set[str] = set()
        for i, meta in enumerate(metas):
            key = meta.name[: -len(_META_SUFFIX)]
            if i < self.max_entries:
                keep_keys.add(key)
            else:
                _unlink(meta)
                _unlink(self.cache_dir / f"{key}{_BODY_SUFFIX}")

        # Sweep orphan bodies (no surviving meta) and any leftover temp files.
        for body in self.cache_dir.glob(f"*{_BODY_SUFFIX}"):
            if body.name[: -len(_BODY_SUFFIX)] not in keep_keys:
                _unlink(body)
        for tmp in self.cache_dir.glob(f"*{_TMP_SUFFIX}"):
            _unlink(tmp)


def build_feed_cache_from_config(config) -> FeedCache | None:
    """Construct a :class:`FeedCache` from config, or ``None`` if disabled."""
    if not getattr(config, "fetch_cache", False):
        return None
    return FeedCache(
        cache_dir=config.fetch_cache_dir,
        ttl_seconds=config.fetch_cache_ttl_seconds,
    )


__all__ = ["FeedCache", "CacheEntry", "build_feed_cache_from_config"]
