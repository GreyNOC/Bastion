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

    def __init__(self, playbooks_dir: Path | None = None) -> None:
        super().__init__()
        self.playbooks_dir = Path(playbooks_dir) if playbooks_dir else (
            Path(__file__).resolve().parents[1] / "fixtures" / "playbooks"
        )

    def _iter_files(self) -> list[Path]:
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
        # Detection playbooks title in H2 ("## X Detection & Response"); crypto
        # playbooks title in H1 ("# 09 — Post-Quantum ..."). Pick a title-like
        # H2, else a meaningful H1, else derive from the slug.
        name = self._pick_name(h1, h2, slug)
        name = re.sub(r"\s*[-—]\s*$", "", name)

        category = _categorize(slug, name)
        severity = _severity_for(slug, name)

        techniques = sorted(set(_MITRE_RE.findall(text)))

        # First paragraph after an Overview heading, else first non-heading line.
        summary = self._extract_summary(text)

        # Embedded draft-detection JSON blocks -> related detections (as drafts).
        related_detections: list[str] = []
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

    # Section headings that are never a playbook title.
    _GENERIC_HEADINGS = {
        "overview", "mitre att&ck mapping", "mitre attack mapping", "mitre mapping",
        "detection strategy", "detection", "key indicators", "indicators",
        "sample detection logic", "sample logic", "response", "containment",
        "remediation", "references", "analyst notes", "investigation steps",
        "summary", "scope", "background", "introduction", "table of contents",
        "example data", "greynoc security playbook",
    }

    @classmethod
    def _pick_name(cls, h1_list: list[str], h2_list: list[str], slug: str) -> str:
        def generic(text: str) -> bool:
            clean = re.sub(r"^\d+\.\s*", "", text.strip()).strip().lower().rstrip(":")
            # Generic if it exactly matches, or starts with, a known section name.
            return (clean in cls._GENERIC_HEADINGS
                    or any(clean.startswith(g) for g in cls._GENERIC_HEADINGS)
                    or len(clean) <= 3)

        # Detection-series titles are the H2 "X Detection & Response" — they
        # contain BOTH "detection" and "response" (distinguishes the title from
        # a plain "Response actions" section).
        for h in h2_list:
            if re.search(r"detection", h, re.IGNORECASE) and re.search(r"response", h, re.IGNORECASE):
                return re.sub(r"^\d+\.\s*", "", h.strip())
        # Crypto-series titles are the H1 (strip a leading "NN — " ordinal prefix).
        for h in h1_list:
            if not generic(h):
                return re.sub(r"^\d+\s*[-—:]\s*", "", h.strip())
        # Any non-generic H2, then slug-derived title.
        for h in h2_list:
            if not generic(h):
                return re.sub(r"^\d+\.\s*", "", h.strip())
        stem = re.sub(r"^\d+[-_]", "", slug).replace("-", " ").replace("_", " ")
        return stem.title() if stem else slug

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
    def _extract_steps(text: str) -> list[PlaybookStep]:
        """Pull a response checklist from a Response/Containment section."""
        steps: list[PlaybookStep] = []
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

    def load_all(self) -> list[BastionPlaybook]:
        out: list[BastionPlaybook] = []
        for f in self._iter_files():
            try:
                out.append(self.parse_file(f))
            except Exception as exc:  # noqa: BLE001 - isolation boundary
                self.log.warning("failed to parse playbook %s: %s", f.name, exc)
        return out

    def get(self, slug_or_name: str) -> BastionPlaybook | None:
        key = slug_or_name.lower().strip()
        playbooks = self.load_all()
        # 1) Exact slug or name match wins.
        for pb in playbooks:
            if pb.slug.lower() == key or pb.name.lower() == key:
                return pb
        # 2) Otherwise accept a partial match ONLY if it is unambiguous, so a
        # partial like "1" never silently resolves to the first playbook that
        # happens to contain it.
        partial = [pb for pb in playbooks if key and (key in pb.slug.lower() or key in pb.name.lower())]
        return partial[0] if len(partial) == 1 else None
