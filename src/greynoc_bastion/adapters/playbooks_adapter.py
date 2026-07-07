"""Playbooks adapter — Operator doctrine layer.

Clean-room parser over GreyNOC/Playbooks markdown doctrine (data ported into
``fixtures/playbooks``). It detects the series, extracts the title, MITRE
technique mapping, embedded draft-detection JSON, and a response checklist,
and returns ``BastionPlaybook`` records.

The two authorized-offensive bug-bounty playbooks are excluded at import time
(they were never copied into the fixtures) — this module only serves defensive
doctrine.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from ..schemas import BastionPlaybook, PlaybookStep, Severity
from .base import BaseAdapter

# Files that are documentation, not playbooks.
_NON_PLAYBOOK = {"README.md", "CONVENTIONS.md", "SECURITY.md", "index.md", "LICENSE.md"}

_MITRE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
_H1_RE = re.compile(r"^#\s+(.*)$", re.MULTILINE)
_H2_RE = re.compile(r"^##\s+(.*)$", re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

# Category keyword map (checked against filename + title).
_CATEGORY_KEYWORDS = [
    ("post-quantum-crypto", ("pqc", "quantum", "crypto", "e2ee", "kem", "tls",
                             "signature", "pki", "vpn", "ipsec", "harvest-now",
                             "code-signing", "crypto-agility", "hybrid")),
    ("identity", ("password", "spray", "brute", "credential", "ad-credential",
                  "impossible-travel", "phishing", "business-email")),
    ("execution", ("powershell", "execution", "web-shell", "webshell")),
    ("persistence", ("persistence",)),
    ("privilege-escalation", ("privilege", "escalation")),
    ("lateral-movement", ("lateral",)),
    ("command-and-control", ("beacon", "c2", "command")),
    ("exfiltration", ("exfil", "data-exfiltration")),
    ("impact", ("ransomware", "impact")),
    ("ai-abuse", ("ai-", "agent-abuse", "augmented", "automated-agent")),
    ("discovery", ("port-scan", "discovery", "scan")),
]

_SEVERITY_KEYWORDS = {
    Severity.CRITICAL: ("ransomware", "ad-credential", "web-shell", "exfiltration"),
    Severity.HIGH: ("privilege", "lateral", "persistence", "phishing",
                    "business-email", "beacon", "malware", "harvest-now"),
}


def _categorize(slug: str, title: str) -> str:
    hay = f"{slug} {title}".lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(k in hay for k in keywords):
            return category
    return "general"


def _severity_for(slug: str, title: str) -> Severity:
    hay = f"{slug} {title}".lower()
    for sev, keywords in _SEVERITY_KEYWORDS.items():
        if any(k in hay for k in keywords):
            return sev
    return Severity.MEDIUM


class PlaybooksAdapter(BaseAdapter):
    source_repo = "GreyNOC/Playbooks"
    name = "playbooks"

    def __init__(self, playbooks_dir: Optional[Path] = None) -> None:
        super().__init__()
        self.playbooks_dir = Path(playbooks_dir) if playbooks_dir else (
            Path(__file__).resolve().parents[1] / "fixtures" / "playbooks"
        )

    def _iter_files(self) -> List[Path]:
        if not self.playbooks_dir.is_dir():
            return []
        files = []
        for f in sorted(self.playbooks_dir.glob("*.md")):
            if f.name in _NON_PLAYBOOK:
                continue
            if "bugbounty" in f.name.lower():  # defense-in-depth: never serve these
                continue
            files.append(f)
        return files

    def parse_file(self, path: Path) -> BastionPlaybook:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        slug = Path(path).stem

        h2 = _H2_RE.findall(text)
        h1 = _H1_RE.findall(text)
        # The playbook's real name is the first H2 ("## X Detection & Response");
        # fall back to H1 or the slug.
        name = (h2[0].strip() if h2 else (h1[0].strip() if h1 else slug))
        name = re.sub(r"\s*[-—]\s*$", "", name)

        category = _categorize(slug, name)
        severity = _severity_for(slug, name)

        techniques = sorted(set(_MITRE_RE.findall(text)))

        # First paragraph after an Overview heading, else first non-heading line.
        summary = self._extract_summary(text)

        # Embedded draft-detection JSON blocks -> related detections (as drafts).
        related_detections: List[str] = []
        for m in _JSON_BLOCK_RE.finditer(text):
            block = m.group(1)
            name_m = re.search(r'"rule_name"\s*:\s*"([^"]+)"', block)
            if name_m:
                related_detections.append(name_m.group(1))

        steps = self._extract_steps(text)
        references = re.findall(r"https?://\S+", text)

        return BastionPlaybook(
            slug=slug,
            name=name,
            category=category,
            summary=summary,
            severity=severity,
            attack_techniques=techniques,
            related_detections=related_detections,
            detection_guidance=self._extract_section(text, ("Detection Strategy", "Detection", "Key Indicators")),
            response_steps=steps,
            references=sorted(set(references))[:20],
            source_path=str(path),
            body_markdown=text,
        )

    @staticmethod
    def _extract_summary(text: str) -> str:
        m = re.search(r"###?\s*(?:\d+\.\s*)?Overview\s*\n+(.+?)(?:\n\n|\n#)", text, re.DOTALL | re.IGNORECASE)
        if m:
            return " ".join(m.group(1).split())[:600]
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith("---") and not s.startswith("|"):
                return s[:600]
        return ""

    @staticmethod
    def _extract_section(text: str, headings: tuple) -> str:
        for h in headings:
            m = re.search(
                rf"###?\s*(?:\d+\.\s*)?{re.escape(h)}\b.*?\n+(.+?)(?:\n###?\s|\Z)",
                text, re.DOTALL | re.IGNORECASE,
            )
            if m:
                return " ".join(m.group(1).split())[:1200]
        return ""

    @staticmethod
    def _extract_steps(text: str) -> List[PlaybookStep]:
        """Pull a response checklist from a Response/Containment section."""
        steps: List[PlaybookStep] = []
        section = None
        for h in ("Response", "Containment", "Response & Containment", "Response Actions",
                  "Response Playbook", "Remediation"):
            m = re.search(
                rf"###?\s*(?:\d+\.\s*)?{re.escape(h)}\b.*?\n+(.+?)(?:\n###?\s+(?:\d+\.\s*)?[A-Z]|\Z)",
                text, re.DOTALL | re.IGNORECASE,
            )
            if m:
                section = m.group(1)
                break
        if not section:
            return steps
        order = 0
        for line in section.splitlines():
            s = line.strip()
            m = re.match(r"^(?:[-*]|\d+\.)\s+(.*)$", s)
            if m and len(m.group(1)) > 3:
                order += 1
                detail = m.group(1).strip()
                title = detail[:80] + ("…" if len(detail) > 80 else "")
                steps.append(PlaybookStep(order=order, title=title, detail=detail, phase="respond"))
            if order >= 25:
                break
        return steps

    def load_all(self) -> List[BastionPlaybook]:
        out: List[BastionPlaybook] = []
        for f in self._iter_files():
            try:
                out.append(self.parse_file(f))
            except Exception as exc:  # noqa: BLE001 - isolation boundary
                self.log.warning("failed to parse playbook %s: %s", f.name, exc)
        return out

    def get(self, slug_or_name: str) -> Optional[BastionPlaybook]:
        key = slug_or_name.lower().strip()
        for pb in self.load_all():
            if pb.slug.lower() == key or pb.name.lower() == key or key in pb.slug.lower():
                return pb
        return None
