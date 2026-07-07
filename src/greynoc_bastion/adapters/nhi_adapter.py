"""Non-Human-Identity adapter — Identity Blast Radius scanning.

Clean-room port of GreyNOC/Non-Human-Identity-Engine's defensive scanner. It
walks a repo/project tree and identifies automation identities (API keys,
service accounts, CI/CD tokens, OAuth apps, webhooks, model gateways, MCP
servers, AI agents, cloud workload identities) from filenames, ``.env`` keys,
and high-confidence value patterns.

Hard safety rules enforced here:
  * Only masked previews + one-way fingerprints ever leave this module.
  * Placeholder/example values are suppressed (false-positive reduction).
  * Bastion NEVER validates, replays, or transmits a discovered credential —
    ``is_active_unknown`` is always True.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..safety.masking import fingerprint_secret, iter_secret_matches, mask_secret
from ..schemas import (
    BastionIdentity,
    Confidence,
    Exposure,
    IdentityType,
    Severity,
)
from .base import BaseAdapter

# Env-var key -> (label, provider, identity_type). Ported from the NHI engine's
# curated SECRET_KEYS knowledge base (defensive data only).
SECRET_KEYS: Dict[str, Tuple[str, Optional[str], IdentityType]] = {
    "AWS_ACCESS_KEY_ID": ("Cloud IAM user", "aws", IdentityType.CLOUD_WORKLOAD),
    "AWS_SECRET_ACCESS_KEY": ("Cloud IAM user", "aws", IdentityType.CLOUD_WORKLOAD),
    "AZURE_CLIENT_SECRET": ("Service account", "azure", IdentityType.SERVICE_ACCOUNT),
    "GOOGLE_APPLICATION_CREDENTIALS": ("Service account key file", "google cloud", IdentityType.SERVICE_ACCOUNT),
    "GITHUB_TOKEN": ("GitHub token", "github", IdentityType.CI_CD_TOKEN),
    "GH_TOKEN": ("GitHub token", "github", IdentityType.CI_CD_TOKEN),
    "GITLAB_TOKEN": ("GitLab token", "gitlab", IdentityType.CI_CD_TOKEN),
    "OPENAI_API_KEY": ("Model gateway key", "openai", IdentityType.MODEL_GATEWAY),
    "ANTHROPIC_API_KEY": ("Model gateway key", "anthropic", IdentityType.MODEL_GATEWAY),
    "GEMINI_API_KEY": ("Model gateway key", "gemini", IdentityType.MODEL_GATEWAY),
    "GOOGLE_API_KEY": ("API key", "google", IdentityType.API_KEY),
    "AZURE_OPENAI_API_KEY": ("Model gateway key", "azure openai", IdentityType.MODEL_GATEWAY),
    "HUGGINGFACEHUB_API_TOKEN": ("Model gateway key", "hugging face", IdentityType.MODEL_GATEWAY),
    "REPLICATE_API_TOKEN": ("Model gateway key", "replicate", IdentityType.MODEL_GATEWAY),
    "MISTRAL_API_KEY": ("Model gateway key", "mistral", IdentityType.MODEL_GATEWAY),
    "COHERE_API_KEY": ("Model gateway key", "cohere", IdentityType.MODEL_GATEWAY),
    "TOGETHER_API_KEY": ("Model gateway key", "together", IdentityType.MODEL_GATEWAY),
    "GROQ_API_KEY": ("Model gateway key", "groq", IdentityType.MODEL_GATEWAY),
    "PERPLEXITY_API_KEY": ("Model gateway key", "perplexity", IdentityType.MODEL_GATEWAY),
    "OPENROUTER_API_KEY": ("Model gateway key", "openrouter", IdentityType.MODEL_GATEWAY),
    "STRIPE_SECRET_KEY": ("Payment API key", "stripe", IdentityType.API_KEY),
    "SENDGRID_API_KEY": ("Email API key", "sendgrid", IdentityType.API_KEY),
    "SLACK_BOT_TOKEN": ("Bot account token", "slack", IdentityType.SERVICE_ACCOUNT),
    "DATABASE_URL": ("Database connection identity", "database", IdentityType.SERVICE_ACCOUNT),
    "JWT_SECRET": ("Automation credential", None, IdentityType.GENERIC_SECRET),
    "WEBHOOK_SECRET": ("Webhook secret", None, IdentityType.WEBHOOK),
    "API_KEY": ("API key", None, IdentityType.API_KEY),
    "CLIENT_SECRET": ("OAuth application secret", None, IdentityType.OAUTH_APP),
    "PRIVATE_KEY": ("Private key", None, IdentityType.SSH_KEY),
}

AI_PROVIDER_KEYS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY", "HUGGINGFACEHUB_API_TOKEN", "REPLICATE_API_TOKEN",
    "MISTRAL_API_KEY", "COHERE_API_KEY", "TOGETHER_API_KEY", "GROQ_API_KEY",
    "PERPLEXITY_API_KEY", "OPENROUTER_API_KEY",
}

# Filenames that indicate a specific non-human identity surface.
_FILENAME_SIGNALS: List[Tuple[str, str, IdentityType]] = [
    (".mcp.json", "MCP server configuration", IdentityType.MCP_SERVER),
    ("mcp.json", "MCP server configuration", IdentityType.MCP_SERVER),
    ("mcp_config.json", "MCP server configuration", IdentityType.MCP_SERVER),
    ("cursor_mcp.json", "MCP server configuration", IdentityType.MCP_SERVER),
    ("agents.yaml", "AI agent definition", IdentityType.AI_AGENT),
    ("agents.yml", "AI agent definition", IdentityType.AI_AGENT),
    ("litellm_config.yaml", "Model gateway configuration", IdentityType.MODEL_GATEWAY),
    ("serviceaccount.json", "Cloud service account key", IdentityType.SERVICE_ACCOUNT),
    ("manifest.json", "Browser extension manifest", IdentityType.BROWSER_EXTENSION),
]

# Placeholder values we must NOT flag (false-positive reduction).
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(x{3,}|changeme|your[_-]?\w*|example|placeholder|dummy|test|todo|"
    r"none|null|<[^>]+>|\$\{[^}]+\}|\*+|redacted|xxx+|foo|bar|secret|password)$"
)

# Substrings that mark an obvious placeholder even inside a longer, hyphenated
# value (e.g. "your-client-secret-here", "example-token-value").
_PLACEHOLDER_SUBSTRINGS = (
    "your-", "your_", "changeme", "change-me", "placeholder", "example",
    "-here", "replace-me", "replaceme", "xxxxx", "dummy", "<your", "put-your",
    "insert-", "todo", "fixme", "notreal", "fake-me",
)

# Directories skipped during traversal.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", ".idea", ".vscode",
    "vendor", ".terraform",
}

_SCANNABLE_SUFFIXES = {
    ".env", ".txt", ".json", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".toml", ".properties", ".py", ".js", ".ts", ".sh", ".ps1", ".xml", "",
}

_MAX_FILE_BYTES = 2 * 1024 * 1024  # skip files larger than 2MB


def _is_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("'\"")
    if len(v) < 6:
        return True
    if _PLACEHOLDER_RE.match(v):
        return True
    low = v.lower()
    return any(sub in low for sub in _PLACEHOLDER_SUBSTRINGS)


def _severity_for(itype: IdentityType, privileged: bool) -> Severity:
    high_blast = {
        IdentityType.CLOUD_WORKLOAD, IdentityType.SERVICE_ACCOUNT,
        IdentityType.CI_CD_TOKEN, IdentityType.SSH_KEY, IdentityType.DEPLOYMENT_IDENTITY,
    }
    if privileged or itype in high_blast:
        return Severity.HIGH
    if itype in {IdentityType.MODEL_GATEWAY, IdentityType.OAUTH_APP, IdentityType.API_KEY}:
        return Severity.MEDIUM
    return Severity.LOW


class NhiAdapter(BaseAdapter):
    source_repo = "GreyNOC/Non-Human-Identity-Engine"
    name = "nhi"

    def iter_files(self, root: Path) -> Iterable[Path]:
        """Root-confined, skip-listed traversal. Symlinks are not followed."""
        root = Path(root).resolve()
        for path in root.rglob("*"):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            if path.name.startswith(".env"):
                yield path
                continue
            if path.suffix.lower() in _SCANNABLE_SUFFIXES:
                yield path

    def _scan_env_line(self, key: str, value: str) -> Optional[Tuple[str, Optional[str], IdentityType, bool]]:
        key_up = key.strip().upper()
        # Exact match, then suffix heuristics.
        if key_up in SECRET_KEYS:
            label, provider, itype = SECRET_KEYS[key_up]
            privileged = key_up in {"AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "AZURE_CLIENT_SECRET"}
            return label, provider, itype, privileged
        for suffix, (label, provider, itype) in (
            ("_API_KEY", ("API key", None, IdentityType.API_KEY)),
            ("_TOKEN", ("Token", None, IdentityType.GENERIC_SECRET)),
            ("_SECRET", ("Secret", None, IdentityType.GENERIC_SECRET)),
            ("_PASSWORD", ("Password", None, IdentityType.GENERIC_SECRET)),
        ):
            if key_up.endswith(suffix):
                return label, provider, itype, False
        return None

    def scan_repo(self, root: Path, max_files: int = 5000) -> List[BastionIdentity]:
        """Scan a directory tree and return masked non-human identities."""
        root = Path(root).resolve()
        identities: List[BastionIdentity] = []
        seen_fingerprints: set[str] = set()
        count = 0

        for path in self.iter_files(root):
            count += 1
            if count > max_files:
                self.log.warning("scan hit max_files=%s; stopping traversal", max_files)
                break
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(path.relative_to(root))

            # 1) Filename-based non-human identity surfaces.
            for fname, label, itype in _FILENAME_SIGNALS:
                if path.name == fname:
                    identities.append(self._make_identity(
                        name=label, provider=None, itype=itype, secret_value=None,
                        rel=rel, line=None, root=root, detector="filename",
                    ))

            # 2) .env-style KEY=VALUE assignments.
            if path.name.startswith(".env") or path.suffix.lower() in {".env", ".ini", ".cfg", ".conf", ".properties"}:
                for lineno, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if not s or s.startswith("#") or "=" not in s:
                        continue
                    key, value = s.split("=", 1)
                    value = value.strip().strip("'\"")
                    match = self._scan_env_line(key, value)
                    if not match:
                        continue
                    if _is_placeholder(value):
                        continue
                    label, provider, itype, privileged = match
                    fp = fingerprint_secret(value)
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)
                    identities.append(self._make_identity(
                        name=f"{label} ({key.strip()})", provider=provider, itype=itype,
                        secret_value=value, rel=rel, line=lineno, root=root,
                        detector="env-key", privileged=privileged,
                        is_ai=key.strip().upper() in AI_PROVIDER_KEYS,
                    ))

            # 3) High-confidence value patterns anywhere in the file.
            for pattern_name, token in iter_secret_matches(text):
                if _is_placeholder(token):
                    continue
                fp = fingerprint_secret(token)
                if fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)
                itype = self._itype_for_pattern(pattern_name)
                identities.append(self._make_identity(
                    name=f"{pattern_name.replace('_', ' ').title()}", provider=None,
                    itype=itype, secret_value=token, rel=rel, line=None, root=root,
                    detector=f"value:{pattern_name}",
                    privileged=pattern_name in {"aws_access_key", "private_key_block"},
                ))

        identities.sort(key=lambda i: (i.severity.rank, i.confidence.rank), reverse=True)
        return identities

    @staticmethod
    def _itype_for_pattern(pattern_name: str) -> IdentityType:
        return {
            "aws_access_key": IdentityType.CLOUD_WORKLOAD,
            "github_token": IdentityType.CI_CD_TOKEN,
            "slack_token": IdentityType.SERVICE_ACCOUNT,
            "google_api_key": IdentityType.API_KEY,
            "openai_key": IdentityType.MODEL_GATEWAY,
            "stripe_key": IdentityType.API_KEY,
            "private_key_block": IdentityType.SSH_KEY,
            "jwt": IdentityType.GENERIC_SECRET,
            "bearer": IdentityType.GENERIC_SECRET,
        }.get(pattern_name, IdentityType.GENERIC_SECRET)

    def _make_identity(
        self, *, name: str, provider: Optional[str], itype: IdentityType,
        secret_value: Optional[str], rel: str, line: Optional[int], root: Path,
        detector: str, privileged: bool = False, is_ai: bool = False,
    ) -> BastionIdentity:
        masked = mask_secret(secret_value) if secret_value else ""
        fp = fingerprint_secret(secret_value) if secret_value else ""
        severity = _severity_for(itype, privileged)

        reachable, chain = self._blast_radius(itype, provider, privileged, is_ai)

        action = self._remediation(itype, provider)
        ident = BastionIdentity(
            identity_type=itype,
            name=name,
            provider=provider or "",
            masked_preview=masked,
            secret_fingerprint=fp,
            detector=detector,
            location=rel,
            line=line,
            repo_path=str(root),
            severity=severity,
            confidence=Confidence.HIGH if secret_value else Confidence.MEDIUM,
            exposure=Exposure.UNKNOWN,
            privileged=privileged,
            reachable_services=reachable,
            permission_chain=chain,
            is_active_unknown=True,  # we never test liveness
            recommended_action=action,
            false_positive_notes="Placeholder/example values are suppressed; verify the value is a live credential before acting.",
        )
        return ident

    @staticmethod
    def _blast_radius(
        itype: IdentityType, provider: Optional[str], privileged: bool, is_ai: bool
    ) -> Tuple[List[str], List[str]]:
        """Derive reachable services and a coarse permission chain (blast radius)."""
        reachable: List[str] = []
        chain: List[str] = ["credential"]
        if itype == IdentityType.CLOUD_WORKLOAD:
            reachable = ["cloud control plane", "object storage", "compute", "IAM"]
            chain = ["IAM user", "assumed role", "cloud resources"]
        elif itype == IdentityType.CI_CD_TOKEN:
            reachable = ["source repositories", "CI runners", "package registry", "deploy targets"]
            chain = ["CI/CD token", "pipeline", "production deploy"]
        elif itype == IdentityType.SERVICE_ACCOUNT:
            reachable = ["backend services", "databases", "internal APIs"]
            chain = ["service account", "internal services"]
        elif itype == IdentityType.MODEL_GATEWAY:
            reachable = [f"{provider or 'model'} inference API", "billing / usage quota"]
            chain = ["model gateway key", "LLM provider"]
        elif itype == IdentityType.MCP_SERVER:
            reachable = ["MCP tool surface", "connected data sources"]
            chain = ["MCP server", "agent tools"]
        elif itype == IdentityType.OAUTH_APP:
            reachable = ["OAuth-scoped resources"]
            chain = ["OAuth app", "granted scopes"]
        if privileged:
            chain.append("elevated privileges")
        if is_ai:
            reachable.append("AI agent action surface")
        return reachable, chain

    @staticmethod
    def _remediation(itype: IdentityType, provider: Optional[str]) -> str:
        base = "Rotate the credential at the provider, remove it from source, and store it in a secrets manager. "
        specific = {
            IdentityType.CLOUD_WORKLOAD: "Prefer short-lived workload identity federation over static keys.",
            IdentityType.CI_CD_TOKEN: "Use scoped, short-lived CI tokens; restrict to required repos/environments.",
            IdentityType.MODEL_GATEWAY: "Scope the key, set spend limits, and route calls through a gateway with logging.",
            IdentityType.MCP_SERVER: "Review the MCP server's tool scopes and require explicit approval for privileged tools.",
            IdentityType.SSH_KEY: "Replace the key pair and audit authorized_keys on all reachable hosts.",
        }.get(itype, "Confirm least-privilege scoping after rotation.")
        return base + specific
