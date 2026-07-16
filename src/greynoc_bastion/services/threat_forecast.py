"""Threat Forecast service.

Wraps the Detector-Engine adapter: builds a ranked threat forecast from offline
fixtures, an ingested feed file, or — only when live fetching is explicitly
enabled — a guarded HTTPS fetch (with an integrity-checked per-source cache and
offline fallback). Persists the threats and converts each into the universal
``BastionFinding`` envelope for reporting.
"""

from __future__ import annotations

import http.client
import json
import time
from pathlib import Path

from ..adapters.detector_engine_adapter import DetectorEngineAdapter
from ..db import Database
from ..safety.netguard import evaluate_fetch_target
from ..schemas import (
    BastionEvidence,
    BastionFinding,
    BastionThreat,
    EvidenceKind,
    FindingCategory,
)
from ..utils.logging import get_logger


class ThreatForecastService:
    def __init__(self, db: Database | None = None, adapter: DetectorEngineAdapter | None = None,
                 config=None):
        self.db = db
        self.adapter = adapter or DetectorEngineAdapter()
        self.config = config
        self.log = get_logger("threat_forecast")

    def ingest_url(self, url: str, sectors: list[str] | None = None,
                   persist: bool = True, *, refresh: bool = False,
                   offline: bool = False, now: float | None = None) -> list[BastionThreat]:
        """Ingest a CVE feed from a URL via the guarded fetcher (opt-in only).

        Refuses unless live fetching is enabled. Every URL is first checked
        against the network guard (HTTPS-only + allowlist); a refusal here is a
        hard refusal that neither the live path nor the cache may bypass. On a
        live fetch, the request (and every redirect) is additionally SSRF-pinned
        and size/timeout-capped, and the body is cached.

        Cache behaviour (:class:`~greynoc_bastion.services.feed_cache.FeedCache`):

          * a fresh cached copy (within TTL) is served with no network request;
          * ``refresh=True`` forces a live fetch even if a fresh copy exists;
          * ``offline=True`` serves only from cache and never touches the network;
          * if a live fetch fails on *transport* (network/timeout/TLS), a stale
            cached copy is served as a fallback (a guard refusal is never masked).

        Every path is audit-logged with its provenance.
        """
        if self.config is None or not getattr(self.config, "live_fetch", False):
            raise RuntimeError(
                "live fetching is disabled. Set BASTION_LIVE_FETCH=true and add the host to "
                "BASTION_FETCH_ALLOWLIST to ingest from a URL (HTTPS-only, SSRF-guarded)."
            )

        # Policy gate (literal checks, no DNS): HTTPS + allowlist. This runs on
        # EVERY path — live, fresh-cache, stale-fallback, and offline — so the
        # cache can never resurrect a de-allowlisted or non-HTTPS URL.
        evaluate_fetch_target(
            url, live_fetch_enabled=True, allowlist=self.config.fetch_allowlist, resolve=False,
        ).raise_if_blocked()

        from ..safety.fetcher import build_fetcher_from_config
        from .feed_cache import build_feed_cache_from_config

        now = time.time() if now is None else now
        cache = build_feed_cache_from_config(self.config)

        def _audit(action: str, detail: str) -> None:
            if self.db is not None:
                self.db.audit(action, actor="threat_forecast", detail=detail)

        def _finish(body: bytes, provenance: str) -> list[BastionThreat]:
            _audit("threat_ingest", f"{provenance}: {url}")
            self.log.info("threat feed ingest (%s): %s", provenance, url)
            data = self._parse_feed(body)
            cves = self.adapter.parse_cve_feed(data)
            threats = self.adapter.build_threats(cves, {}, {}, sectors)
            if persist and self.db:
                for t in threats:
                    self.db.save_threat(t)
                self.db.save_findings(self.to_findings(threats))
            return threats

        # 1) Offline: cache only, never touch the network.
        if offline:
            entry = cache.get(url) if cache is not None else None
            if cache is None or entry is None:
                raise RuntimeError(
                    "offline ingest requested but no cached copy of this feed exists"
                )
            return _finish(entry.body, "cache" if cache.is_fresh(entry, now) else "cache-stale")

        # 2) Fresh-cache short-circuit (no network) unless a refresh was forced.
        if cache is not None and not refresh:
            entry = cache.get(url)
            if entry is not None and cache.is_fresh(entry, now):
                return _finish(entry.body, "cache")

        # 3) Live fetch through the guarded, SSRF-pinned fetcher.
        fetcher = build_fetcher_from_config(self.config)
        try:
            result = fetcher.fetch(url, audit=_audit)
        except (OSError, http.client.HTTPException) as exc:
            # Transport failure — network down / DNS failure / timeout / TLS (all
            # OSError subclasses), or a malformed/truncated HTTP response
            # (http.client.HTTPException). Serve a stale cached copy if we have
            # one. A guard refusal (NetGuardError — a redirect off the allowlist
            # or an SSRF resolve-to-private during the pin) is neither of these
            # and always propagates: it is never masked by the cache.
            if cache is not None:
                entry = cache.get(url)
                if entry is not None:
                    self.log.warning("live fetch failed (%s); serving stale cache for %s",
                                     type(exc).__name__, url)
                    return _finish(entry.body, "cache-stale-fallback")
            raise RuntimeError(
                f"live fetch failed and no cached copy is available: {exc}"
            ) from None

        # 4) Success — refresh the cache, then use the fresh body.
        if cache is not None:
            try:
                cache.put(url, result.body, result.status, now)
            except OSError as exc:
                self.log.warning("could not write feed cache for %s: %s", url, exc)
        return _finish(result.body, "live")

    @staticmethod
    def _parse_feed(body: bytes):
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except (ValueError, RecursionError) as exc:
            raise RuntimeError(f"fetched feed is not valid JSON: {type(exc).__name__}") from None

    def demo(self, sectors: list[str] | None = None, persist: bool = False) -> list[BastionThreat]:
        threats = self.adapter.forecast_from_fixtures(sectors=sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def ingest(self, fixture_path: Path, sectors: list[str] | None = None,
               persist: bool = True) -> list[BastionThreat]:
        threats = self.adapter.forecast_from_path(Path(fixture_path), sectors=sectors)
        if persist and self.db:
            for t in threats:
                self.db.save_threat(t)
            self.db.save_findings(self.to_findings(threats))
        return threats

    def to_findings(self, threats: list[BastionThreat]) -> list[BastionFinding]:
        findings: list[BastionFinding] = []
        for t in threats:
            drivers = t.metadata.get("drivers", [])
            evidence = [
                BastionEvidence(kind=EvidenceKind.FEED_RECORD, summary=d, source=t.source)
                for d in drivers
            ]
            why = t.summary or t.title
            if drivers:
                why = f"{why} Key drivers: " + "; ".join(drivers) + "."
            findings.append(BastionFinding(
                title=t.title,
                severity=t.severity,
                confidence=t.confidence,
                category=FindingCategory.THREAT,
                evidence=evidence,
                source=t.source,
                affected=", ".join(t.cve_ids) or t.threat_id,
                why_it_matters=why,
                recommended_action=t.remediation,
                validation_status=t.detection_status,
                false_positive_notes=(
                    "Threat intel reflects population-level risk; confirm the affected "
                    "product/version is present in your environment before prioritizing."
                ),
                ref_type="threat",
                ref_id=t.threat_id,
                tags=(
                    [t.category.value]
                    + (["kev"] if t.kev else [])
                    + (["ransomware"] if t.ransomware_used else [])
                    + list(t.attack_techniques)
                    + ([f"forecast:{t.forecast.window}"] if t.forecast else [])
                    + [f"ai-abuse:{a['id']}" for a in t.ai_abuse]
                    + (["pqc-hndl"] if t.pqc_risk else [])
                ),
                metadata={
                    "urgency": t.score.urgency, "epss": t.epss, "cvss": t.cvss,
                    "attack_techniques": t.attack_techniques,
                    "forecast": t.forecast.to_dict() if t.forecast else None,
                    "ai_abuse": t.ai_abuse,
                    "pqc_risk": t.pqc_risk,
                },
            ))
        return findings
