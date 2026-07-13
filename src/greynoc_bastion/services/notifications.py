"""Notification fabric — pluggable, opt-in, egress-guarded.

OFF by default (``BASTION_NOTIFY=false``): :meth:`NotificationFabric.notify`
is a no-op that reports itself as skipped. When enabled:

  * **File sink** (local-only): events append to a JSONL file under the
    Bastion home (``BASTION_NOTIFY_FILE`` to relocate). Always on when the
    fabric is enabled — the safe, local-first default.
  * **Webhook sink** (opt-in on top): set ``BASTION_NOTIFY_WEBHOOK_URL`` (HTTPS)
    *and* put its host on ``BASTION_NOTIFY_ALLOWLIST``. Dispatch goes through
    the same guard as live fetching — HTTPS-only, allowlisted, SSRF-blocked,
    IP-pinned, size/time-capped, redirects refused.

Event payloads are scrubbed of secrets before they leave the process, every
dispatch attempt is audited, and a sink failure never breaks the operation
that emitted the event (best-effort delivery, honestly reported).
"""

from __future__ import annotations

import json
from typing import Any

from ..config import BastionConfig
from ..db import Database
from ..safety.fetcher import SafeFetcher
from ..safety.masking import scrub_text
from ..schemas import utcnow_iso
from ..utils.logging import get_logger

_MAX_TEXT = 2000


class NotificationFabric:
    def __init__(self, config: BastionConfig, db: Database | None = None):
        self.config = config
        self.db = db
        self.log = get_logger("notify")

    @property
    def enabled(self) -> bool:
        return bool(self.config.notify_enabled)

    def notify(self, kind: str, title: str, *, detail: str = "",
               severity: str = "info") -> dict[str, Any]:
        """Emit one event to every configured sink. Returns delivery statuses."""
        event = {
            "ts": utcnow_iso(),
            "kind": scrub_text(str(kind or "event"))[:80],
            "title": scrub_text(str(title or ""))[:_MAX_TEXT],
            "detail": scrub_text(str(detail or ""))[:_MAX_TEXT],
            "severity": str(severity or "info")[:20],
            "source": "greynoc-bastion",
        }
        if not self.enabled:
            return {"enabled": False, "event": event, "deliveries": [],
                    "note": "notifications disabled (BASTION_NOTIFY=false); nothing sent"}

        deliveries = [self._deliver_file(event)]
        if self.config.notify_webhook_url:
            deliveries.append(self._deliver_webhook(event))
        return {"enabled": True, "event": event, "deliveries": deliveries}

    # --- sinks -----------------------------------------------------------------
    def _deliver_file(self, event: dict[str, Any]) -> dict[str, Any]:
        path = self.config.notify_file or (self.config.home / "notifications.jsonl")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._audit("notification_file", f"appended to {path.name}")
            return {"sink": "file", "ok": True, "target": str(path)}
        except OSError as exc:
            self.log.warning("notification file sink failed: %s", exc)
            self._audit("notification_failed", f"file sink: {exc}")
            return {"sink": "file", "ok": False, "error": str(exc)}

    def _deliver_webhook(self, event: dict[str, Any]) -> dict[str, Any]:
        url = self.config.notify_webhook_url
        fetcher = SafeFetcher(
            live_fetch_enabled=True,  # the fabric's own gate (self.enabled) was already checked
            allowlist=self.config.notify_allowlist,
            max_bytes=64 * 1024,
            timeout_seconds=10,
        )
        try:
            result = fetcher.post_json(url, event, audit=self._audit)
            ok = 200 <= result.status < 300
            if not ok:
                self._audit("notification_failed", f"webhook returned HTTP {result.status}")
            return {"sink": "webhook", "ok": ok, "status": result.status}
        except Exception as exc:  # noqa: BLE001 - guard refusals + transport errors alike
            self.log.warning("notification webhook refused/failed: %s", exc)
            self._audit("notification_failed", f"webhook: {scrub_text(str(exc))[:200]}")
            return {"sink": "webhook", "ok": False, "error": scrub_text(str(exc))[:200]}

    def _audit(self, action: str, detail: str) -> None:
        if self.db:
            self.db.audit(action, actor="notify", detail=detail)
