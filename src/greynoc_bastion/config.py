"""Configuration for GreyNOC Bastion.

Local-first, safe-by-default. Every default here is the conservative choice;
turning anything more permissive on is an explicit operator decision made via
environment variables or a ``.env`` file (env vars take precedence).

No third-party settings library — a tiny, dependency-free ``.env`` reader keeps
the MVP portable and auditable.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n", ""}

DEFAULT_ALLOWLIST = ["www.cisa.gov", "services.nvd.nist.gov", "api.first.org"]


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default


def _parse_env_file(path: Path) -> dict[str, str]:
    """Minimal ``.env`` parser: ``KEY=VALUE`` lines, ``#`` comments, quotes."""
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            out[key] = val
    return out


@dataclasses.dataclass
class BastionConfig:
    """Resolved, immutable-ish runtime configuration."""

    # Network / API
    host: str = "127.0.0.1"
    port: int = 8788

    # Paths
    home: Path = dataclasses.field(default_factory=lambda: Path.home() / ".greynoc-bastion")
    db_path: Path = dataclasses.field(default_factory=lambda: Path.home() / ".greynoc-bastion" / "bastion.db")
    report_dir: Path = dataclasses.field(default_factory=lambda: Path.home() / ".greynoc-bastion" / "reports")

    # Live fetch (threat feeds)
    live_fetch: bool = False
    fetch_allowlist: list[str] = dataclasses.field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    fetch_max_bytes: int = 10 * 1024 * 1024
    fetch_timeout_seconds: int = 20

    # Per-source feed cache (integrity-checked; local-only). On by default: it
    # only ever caches bodies the guarded fetcher already returned, and it is a
    # performance/offline-resilience aid — never a policy gate (see FeedCache).
    fetch_cache: bool = True
    fetch_cache_ttl_seconds: int = 3600
    fetch_cache_dir: Path = dataclasses.field(
        default_factory=lambda: Path.home() / ".greynoc-bastion" / "cache" / "feeds")

    # Active local checks (Assets & Exposure)
    active_checks: bool = False

    # Notification fabric (Phase 3). OFF by default. The file sink is local-only;
    # the webhook sink additionally requires an HTTPS URL whose host is on the
    # (separate) notify allowlist, and every dispatch goes through the same
    # SSRF/TLS/pinning guard as live fetching.
    notify_enabled: bool = False
    notify_file: Path | None = None
    notify_webhook_url: str = ""
    notify_allowlist: list[str] = dataclasses.field(default_factory=list)

    # Optional directory of user-supplied detection rules (ReDoS-screened on load).
    rules_dir: Path | None = None

    # Dashboard remote access (fail-closed). Resolved from .env + environment so
    # a token placed in .env is honored (not only a real environment variable).
    allow_remote_dashboard: bool = False
    dashboard_token: str = ""
    web_secret: str = ""

    # AI assistant
    ai_assistant: bool = False
    ai_command_execution: bool = False
    ai_endpoint: str = ""
    ai_allow_cloud: bool = False

    # Logging
    log_level: str = "INFO"

    # Provenance for the Safety Status page: which knobs were changed from
    # their safe defaults, and where the config was sourced from.
    source: str = "defaults"

    @property
    def loopback_only(self) -> bool:
        return self.host in {"127.0.0.1", "::1", "localhost"}

    def ensure_dirs(self) -> BastionConfig:
        """Create the home and report directories if missing."""
        self.home.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        return self

    def public_dict(self) -> dict[str, object]:
        """A safe-to-display view (no secrets; there are none, but be explicit)."""
        return {
            "host": self.host,
            "port": self.port,
            "loopback_only": self.loopback_only,
            "home": str(self.home),
            "db_path": str(self.db_path),
            "report_dir": str(self.report_dir),
            "live_fetch": self.live_fetch,
            "fetch_allowlist": list(self.fetch_allowlist),
            "fetch_max_bytes": self.fetch_max_bytes,
            "fetch_timeout_seconds": self.fetch_timeout_seconds,
            "fetch_cache": self.fetch_cache,
            "fetch_cache_ttl_seconds": self.fetch_cache_ttl_seconds,
            "fetch_cache_dir": str(self.fetch_cache_dir),
            "active_checks": self.active_checks,
            "notify_enabled": self.notify_enabled,
            "notify_file": str(self.notify_file) if self.notify_file else "",
            "notify_webhook_set": bool(self.notify_webhook_url),  # never expose the URL (may embed a token)
            "notify_allowlist": list(self.notify_allowlist),
            "allow_remote_dashboard": self.allow_remote_dashboard,
            "dashboard_token_set": bool(self.dashboard_token),  # never expose the value
            "ai_assistant": self.ai_assistant,
            "ai_command_execution": self.ai_command_execution,
            "ai_endpoint_set": bool(self.ai_endpoint),
            "ai_allow_cloud": self.ai_allow_cloud,
            "log_level": self.log_level,
            "source": self.source,
        }


def _resolve_path(base: Path, value: str, default: Path) -> Path:
    if not value:
        return default
    p = Path(value).expanduser()
    return p if p.is_absolute() else (base / p)


def load_config(
    env_file: Path | None = None,
    overrides: dict[str, str] | None = None,
) -> BastionConfig:
    """Build a :class:`BastionConfig` from ``.env`` + environment + overrides.

    Precedence (low -> high): dataclass defaults, ``.env`` file, process
    environment, explicit ``overrides``.
    """
    # Layer sources into one mapping.
    layered: dict[str, str] = {}
    sources: list[str] = ["defaults"]

    if env_file is None:
        candidate = Path.cwd() / ".env"
        env_file = candidate if candidate.is_file() else None
    if env_file and Path(env_file).is_file():
        layered.update(_parse_env_file(Path(env_file)))
        sources.append(f"env-file:{env_file}")

    env_keys = [
        "BASTION_HOST", "BASTION_PORT", "BASTION_HOME", "BASTION_DB_PATH",
        "BASTION_REPORT_DIR", "BASTION_LIVE_FETCH", "BASTION_FETCH_ALLOWLIST",
        "BASTION_FETCH_MAX_BYTES", "BASTION_FETCH_TIMEOUT_SECONDS",
        "BASTION_FETCH_CACHE", "BASTION_FETCH_CACHE_TTL_SECONDS", "BASTION_FETCH_CACHE_DIR",
        "BASTION_ACTIVE_CHECKS", "BASTION_RULES_DIR",
        "BASTION_NOTIFY", "BASTION_NOTIFY_FILE", "BASTION_NOTIFY_WEBHOOK_URL",
        "BASTION_NOTIFY_ALLOWLIST",
        "BASTION_ALLOW_REMOTE_DASHBOARD",
        "BASTION_DASHBOARD_TOKEN", "BASTION_WEB_SECRET", "BASTION_AI_ASSISTANT",
        "BASTION_AI_COMMAND_EXECUTION", "BASTION_AI_ENDPOINT",
        "BASTION_AI_ALLOW_CLOUD", "BASTION_LOG_LEVEL",
    ]
    env_present = False
    for k in env_keys:
        if k in os.environ:
            layered[k] = os.environ[k]
            env_present = True
    if env_present:
        sources.append("environment")

    if overrides:
        layered.update(overrides)
        sources.append("overrides")

    def get(key: str, default: str = "") -> str:
        return layered.get(key, default)

    home_raw = get("BASTION_HOME")
    # Resolve to an absolute path so db_path/report_dir are cwd-independent
    # (a relative BASTION_HOME would otherwise move with the process's cwd).
    home = Path(home_raw).expanduser().resolve() if home_raw else (Path.home() / ".greynoc-bastion")

    db_path = _resolve_path(home, get("BASTION_DB_PATH", "bastion.db"), home / "bastion.db")
    report_dir = _resolve_path(home, get("BASTION_REPORT_DIR", "reports"), home / "reports")
    fetch_cache_dir = _resolve_path(
        home, get("BASTION_FETCH_CACHE_DIR", "cache/feeds"), home / "cache" / "feeds")

    allowlist_raw = get("BASTION_FETCH_ALLOWLIST")
    allowlist = (
        [h.strip() for h in allowlist_raw.split(",") if h.strip()]
        if allowlist_raw
        else list(DEFAULT_ALLOWLIST)
    )

    def _int(key: str, default: int) -> int:
        try:
            return int(get(key, str(default)))
        except (TypeError, ValueError):
            return default

    cfg = BastionConfig(
        host=get("BASTION_HOST", "127.0.0.1") or "127.0.0.1",
        port=_int("BASTION_PORT", 8788),
        home=home,
        db_path=db_path,
        report_dir=report_dir,
        live_fetch=_parse_bool(get("BASTION_LIVE_FETCH"), False),
        fetch_allowlist=allowlist,
        fetch_max_bytes=_int("BASTION_FETCH_MAX_BYTES", 10 * 1024 * 1024),
        fetch_timeout_seconds=_int("BASTION_FETCH_TIMEOUT_SECONDS", 20),
        # Use layered.get (None when absent) so an *unset* key keeps the True
        # default — get() would return "" which _parse_bool reads as False.
        fetch_cache=_parse_bool(layered.get("BASTION_FETCH_CACHE"), True),
        fetch_cache_ttl_seconds=_int("BASTION_FETCH_CACHE_TTL_SECONDS", 3600),
        fetch_cache_dir=fetch_cache_dir,
        active_checks=_parse_bool(get("BASTION_ACTIVE_CHECKS"), False),
        notify_enabled=_parse_bool(get("BASTION_NOTIFY"), False),
        notify_file=(_resolve_path(home, get("BASTION_NOTIFY_FILE"), home / "notifications.jsonl")
                     if _parse_bool(get("BASTION_NOTIFY"), False) or get("BASTION_NOTIFY_FILE")
                     else None),
        notify_webhook_url=get("BASTION_NOTIFY_WEBHOOK_URL", ""),
        notify_allowlist=[h.strip() for h in get("BASTION_NOTIFY_ALLOWLIST").split(",") if h.strip()],
        rules_dir=(Path(get("BASTION_RULES_DIR")).expanduser() if get("BASTION_RULES_DIR") else None),
        allow_remote_dashboard=get("BASTION_ALLOW_REMOTE_DASHBOARD").strip() == "1",
        dashboard_token=get("BASTION_DASHBOARD_TOKEN", ""),
        web_secret=get("BASTION_WEB_SECRET", ""),
        ai_assistant=_parse_bool(get("BASTION_AI_ASSISTANT"), False),
        ai_command_execution=_parse_bool(get("BASTION_AI_COMMAND_EXECUTION"), False),
        ai_endpoint=get("BASTION_AI_ENDPOINT", ""),
        ai_allow_cloud=_parse_bool(get("BASTION_AI_ALLOW_CLOUD"), False),
        log_level=get("BASTION_LOG_LEVEL", "INFO") or "INFO",
        source=" + ".join(sources),
    )
    return cfg
