"""MITRE ATT&CK (enterprise) knowledge base — curated, offline.

A compact catalog of the 14 enterprise tactics and the techniques Bastion
reasons about, plus a keyword inference map that turns free-text CVE/advisory
descriptions into candidate techniques. This is the shared ATT&CK vocabulary:
Threat Forecast maps CVEs to techniques, Detection Validation measures coverage
against it, and the correlation spine uses technique IDs as a join key.

Defensive use only: this maps *what an adversary technique is* so defenders can
detect and prioritize. It contains no procedure, payload, or how-to content.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

# --- tactics (enterprise, catalog order) ------------------------------------
ATTACK_TACTICS: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# --- techniques: id -> (name, tactic_id) ------------------------------------
# Curated to cover Bastion's playbooks, the GNOC detection pack, and the common
# CVE-driven initial-access / execution / impact techniques.
TECHNIQUES: Dict[str, Dict[str, str]] = {
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1133": {"name": "External Remote Services", "tactic": "TA0001"},
    "T1566": {"name": "Phishing", "tactic": "TA0001"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "TA0001"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "TA0001"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "TA0001"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1059.001": {"name": "PowerShell", "tactic": "TA0002"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "TA0002"},
    "T1059.004": {"name": "Unix Shell", "tactic": "TA0002"},
    "T1059.007": {"name": "JavaScript", "tactic": "TA0002"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "TA0002"},
    "T1204": {"name": "User Execution", "tactic": "TA0002"},
    # Persistence
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "TA0003"},
    "T1505.003": {"name": "Web Shell", "tactic": "TA0003"},
    "T1136": {"name": "Create Account", "tactic": "TA0003"},
    "T1098": {"name": "Account Manipulation", "tactic": "TA0003"},
    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "TA0004"},
    # Defense Evasion
    "T1562": {"name": "Impair Defenses", "tactic": "TA0005"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "TA0005"},
    "T1070": {"name": "Indicator Removal", "tactic": "TA0005"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1112": {"name": "Modify Registry", "tactic": "TA0005"},
    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "TA0006"},
    "T1110.003": {"name": "Password Spraying", "tactic": "TA0006"},
    "T1110.004": {"name": "Credential Stuffing", "tactic": "TA0006"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "TA0006"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "TA0006"},
    "T1528": {"name": "Steal Application Access Token", "tactic": "TA0006"},
    # Discovery
    "T1087": {"name": "Account Discovery", "tactic": "TA0007"},
    "T1087.001": {"name": "Local Account Discovery", "tactic": "TA0007"},
    "T1046": {"name": "Network Service Discovery", "tactic": "TA0007"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "TA0008"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "TA0008"},
    "T1021.004": {"name": "SSH", "tactic": "TA0008"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "TA0008"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "TA0009"},
    "T1074": {"name": "Data Staged", "tactic": "TA0009"},
    "T1114": {"name": "Email Collection", "tactic": "TA0009"},
    "T1560": {"name": "Archive Collected Data", "tactic": "TA0009"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1071.001": {"name": "Web Protocols", "tactic": "TA0011"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "TA0011"},
    "T1573": {"name": "Encrypted Channel", "tactic": "TA0011"},
    "T1090": {"name": "Proxy", "tactic": "TA0011"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "TA0010"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1489": {"name": "Service Stop", "tactic": "TA0040"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040"},
    "T1485": {"name": "Data Destruction", "tactic": "TA0040"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "TA0040"},
    "T1498": {"name": "Network Denial of Service", "tactic": "TA0040"},
}

# --- inference: CVE/advisory phrase -> technique ids -------------------------
# Ordered, longest/most-specific first. Each entry maps a vulnerability class
# phrase to the ATT&CK techniques a defender should associate with it.
_INFERENCE: List[tuple] = [
    (r"remote code execution|\brce\b|arbitrary code execution", ["T1190", "T1203"]),
    (r"command injection|os command|shell injection", ["T1190", "T1059"]),
    (r"sql injection|sqli\b", ["T1190"]),
    (r"deserializ|insecure deserialization", ["T1190"]),
    (r"server-side request forgery|\bssrf\b", ["T1190"]),
    (r"cross[- ]site scripting|\bxss\b", ["T1059.007"]),
    (r"path traversal|directory traversal|arbitrary file read", ["T1083", "T1552.001"]),
    (r"arbitrary file (?:write|upload)|unrestricted file upload", ["T1505.003", "T1190"]),
    (r"web ?shell", ["T1505.003"]),
    (r"authentication bypass|auth bypass|improper authentication", ["T1078", "T1190"]),
    (r"privilege escalation|elevation of privilege|\beop\b", ["T1068"]),
    (r"buffer overflow|heap overflow|stack overflow|out-of-bounds write", ["T1203", "T1068"]),
    (r"use[- ]after[- ]free|type confusion|memory corruption", ["T1203"]),
    (r"hard[- ]coded credential|default credential", ["T1078", "T1552.001"]),
    (r"credential (?:disclosure|leak|exposure)|information disclosure of credentials", ["T1552"]),
    (r"password spray", ["T1110.003"]),
    (r"credential stuffing", ["T1110.004"]),
    (r"brute[- ]force", ["T1110"]),
    (r"phishing|spearphish", ["T1566"]),
    (r"ransomware|encrypt(?:s|ed)? files for", ["T1486"]),
    (r"denial[- ]of[- ]service|\bdos\b|resource exhaustion", ["T1499", "T1498"]),
    (r"remote desktop|\brdp\b", ["T1021.001"]),
    (r"\bsmb\b|server message block", ["T1021.002"]),
    (r"\bssh\b", ["T1021.004"]),
    (r"supply[- ]chain", ["T1195"]),
    (r"exposed (?:api|service|endpoint)|internet[- ]facing|externally exposed", ["T1190", "T1133"]),
    (r"powershell", ["T1059.001"]),
    (r"scheduled task|cron", ["T1053"]),
    (r"token (?:theft|hijack|forgery)|oauth (?:abuse|token)", ["T1528", "T1550"]),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), tids) for p, tids in _INFERENCE]
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def normalize_technique(value: str) -> Optional[str]:
    """Return a canonical ATT&CK technique id from a raw value, or None."""
    if not value:
        return None
    m = _TECH_RE.search(str(value).upper())
    return m.group(0) if m else None


def technique_name(technique_id: str) -> str:
    """Human name for a technique id (sub-technique falls back to parent)."""
    tid = normalize_technique(technique_id)
    if not tid:
        return technique_id
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]["name"]
    parent = tid.split(".")[0]
    return TECHNIQUES.get(parent, {}).get("name", tid)


def tactic_for_technique(technique_id: str) -> Optional[str]:
    """Return the tactic id for a technique (parent fallback for sub-techniques)."""
    tid = normalize_technique(technique_id)
    if not tid:
        return None
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]["tactic"]
    parent = tid.split(".")[0]
    return TECHNIQUES.get(parent, {}).get("tactic")


def infer_techniques(text: str, *, max_techniques: int = 8) -> List[str]:
    """Infer candidate ATT&CK technique ids from free-text description.

    Deterministic keyword inference over the vulnerability-class map. Returns a
    de-duplicated, order-preserving list. Empty for empty/None input.
    """
    if not text:
        return []
    found: List[str] = []
    for pattern, tids in _COMPILED:
        if pattern.search(text):
            for t in tids:
                if t not in found:
                    found.append(t)
        if len(found) >= max_techniques:
            break
    # Also pick up explicitly-cited technique ids present in the text.
    for m in _TECH_RE.findall(text.upper()):
        if m not in found:
            found.append(m)
    return found[:max_techniques]
