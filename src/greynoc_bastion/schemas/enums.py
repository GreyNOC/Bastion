"""Controlled vocabularies shared across every Bastion schema.

Keeping these as ``str`` enums means they serialize cleanly to JSON, compare
against plain strings, and stay stable across the SQLite -> Postgres path.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """A string enum whose value is the member value (JSON-friendly)."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)

    @classmethod
    def coerce(cls, value, default=None):
        """Return the matching member for ``value`` or ``default``.

        Accepts members, exact values, and case-insensitive names/values so
        that data imported from source repos with looser conventions still
        lands on a known vocabulary term instead of raising.
        """
        if value is None:
            return default
        if isinstance(value, cls):
            return value
        text = str(value).strip()
        for member in cls:
            if text == member.value:
                return member
        lowered = text.lower()
        for member in cls:
            if lowered == member.value.lower() or lowered == member.name.lower():
                return member
        return default


class Severity(StrEnum):
    """Impact ranking, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class Confidence(StrEnum):
    """How much we trust a finding. Distinct from severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class ValidationStatus(StrEnum):
    """Lifecycle of a detection or finding against evidence.

    Generated detections MUST remain ``DRAFT`` until validated — this is a
    product safety rule, not just bookkeeping.
    """

    DRAFT = "draft"
    VALIDATING = "validating"
    VALIDATED = "validated"
    NEEDS_TUNING = "needs_tuning"
    DEPRECATED = "deprecated"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class ThreatCategory(StrEnum):
    """Buckets used by the Threat Forecast module."""

    CVE = "cve"
    KEV = "kev"                     # CISA Known Exploited Vulnerability
    ADVISORY = "advisory"
    IOC = "ioc"
    RANSOMWARE = "ransomware"
    CAMPAIGN = "campaign"
    AI_ABUSE = "ai_abuse"
    POST_QUANTUM = "post_quantum"
    MALWARE = "malware"
    OTHER = "other"


class IdentityType(StrEnum):
    """Non-human identity classes scanned by Identity Blast Radius."""

    API_KEY = "api_key"
    SERVICE_ACCOUNT = "service_account"
    CI_CD_TOKEN = "ci_cd_token"  # nosec B105
    OAUTH_APP = "oauth_app"
    WEBHOOK = "webhook"
    MODEL_GATEWAY = "model_gateway"
    MCP_SERVER = "mcp_server"
    AI_AGENT = "ai_agent"
    BROWSER_EXTENSION = "browser_extension"
    CLOUD_WORKLOAD = "cloud_workload"
    DEPLOYMENT_IDENTITY = "deployment_identity"
    SSH_KEY = "ssh_key"
    GENERIC_SECRET = "generic_secret"  # nosec B105
    UNKNOWN = "unknown"


class AssetKind(StrEnum):
    """Local asset classes reviewed by Assets & Exposure."""

    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    LISTENER = "listener"
    DEV_SERVER = "dev_server"
    DEVICE = "device"
    SHARE = "share"
    OTHER = "other"


class Exposure(StrEnum):
    """Where an asset or finding can be reached from."""

    LOOPBACK = "loopback"          # 127.0.0.0/8, ::1 — safest
    LAN = "lan"                    # private RFC1918 / link-local
    PUBLIC = "public"              # routable / internet-facing
    UNKNOWN = "unknown"


class EvidenceKind(StrEnum):
    """Types of evidence a finding can carry."""

    LOG_LINE = "log_line"
    TELEMETRY = "telemetry"
    FILE_MATCH = "file_match"
    RULE_RESULT = "rule_result"
    FEED_RECORD = "feed_record"
    PORT_OBSERVATION = "port_observation"
    CONFIG_SNAPSHOT = "config_snapshot"
    NOTE = "note"


class ReportFormat(StrEnum):
    """Output formats the Report Center can emit."""

    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"
    SARIF = "sarif"
    EVIDENCE_BUNDLE = "evidence_bundle"


class FindingCategory(StrEnum):
    """Which module produced a finding (for routing and filtering)."""

    THREAT = "threat"
    IDENTITY = "identity"
    DETECTION = "detection"
    ASSET = "asset"
    PLAYBOOK = "playbook"
    SYSTEM = "system"


class CaseStatus(StrEnum):
    """Lifecycle of a case in the operator workqueue."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class OperatorRole(StrEnum):
    """RBAC roles for multi-operator use, least to most privileged.

    ``VIEWER`` reads; ``OPERATOR`` also runs modules and works cases;
    ``ADMIN`` also manages operator accounts.
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {"viewer": 0, "operator": 1, "admin": 2}[self.value]

    def allows(self, required: OperatorRole) -> bool:
        return self.rank >= required.rank
