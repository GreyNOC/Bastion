"""Post-quantum readiness knowledge — curated, offline.

Classifies cryptographic primitives as quantum-vulnerable or quantum-safe,
detects harvest-now-decrypt-later (HNDL) exposure in text, and computes the
Mosca-inequality migration margin. Defensive planning aid; no cryptographic
attack content.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

# Quantum-vulnerable primitives (broken by Shor/Grover at scale).
QUANTUM_VULNERABLE: Dict[str, str] = {
    "rsa": "RSA (Shor-vulnerable)",
    "ecc": "Elliptic Curve (Shor-vulnerable)",
    "ecdsa": "ECDSA (Shor-vulnerable)",
    "ecdh": "ECDH (Shor-vulnerable)",
    "dh": "Diffie-Hellman (Shor-vulnerable)",
    "dsa": "DSA (Shor-vulnerable)",
    "el gamal": "ElGamal (Shor-vulnerable)",
    "3des": "3DES (Grover-weakened; also legacy)",
}

# Quantum-safe / PQC primitives (NIST selections + hybrids).
QUANTUM_SAFE: Dict[str, str] = {
    "ml-kem": "ML-KEM (FIPS 203, Kyber)",
    "kyber": "ML-KEM (FIPS 203, Kyber)",
    "ml-dsa": "ML-DSA (FIPS 204, Dilithium)",
    "dilithium": "ML-DSA (FIPS 204, Dilithium)",
    "slh-dsa": "SLH-DSA (FIPS 205, SPHINCS+)",
    "sphincs": "SLH-DSA (FIPS 205, SPHINCS+)",
    "falcon": "FN-DSA (Falcon)",
    "lms": "LMS (stateful hash signature, RFC 8554)",
    "hss": "HSS (stateful hash signature)",
    "aes-256": "AES-256 (Grover-resistant at 256-bit)",
}

_VULN_RE = re.compile(
    r"\b(rsa|ecdsa|ecdh|ecc|diffie[- ]?hellman|\bdh\b|\bdsa\b|elgamal|3des|triple des)\b",
    re.IGNORECASE,
)
_SAFE_RE = re.compile(
    r"\b(ml-?kem|kyber|ml-?dsa|dilithium|slh-?dsa|sphincs|falcon|\blms\b|\bhss\b|aes-?256)\b",
    re.IGNORECASE,
)
# Long-lived / high-confidentiality data signals that make HNDL relevant.
_LONGLIVED_RE = re.compile(
    r"\b(archive|backup|long[- ]term|health record|classified|state secret|"
    r"genomic|financial record|legal|retention|encrypted (?:storage|at rest)|"
    r"tls|vpn|ipsec|key exchange|certificate)\b",
    re.IGNORECASE,
)


def classify_crypto(text: str) -> Dict[str, List[str]]:
    """Return {'vulnerable': [...], 'safe': [...]} primitives found in text."""
    if not text:
        return {"vulnerable": [], "safe": []}
    vuln = sorted({QUANTUM_VULNERABLE.get(m.lower().replace("triple des", "3des")
                                          .replace("diffie hellman", "dh")
                                          .replace("diffie-hellman", "dh"), m)
                   for m in _VULN_RE.findall(text)})
    safe = sorted({QUANTUM_SAFE.get(m.lower().replace("-", ""), m) for m in _SAFE_RE.findall(text)})
    return {"vulnerable": vuln, "safe": safe}


def hndl_exposure(text: str) -> Optional[Dict[str, object]]:
    """Assess harvest-now-decrypt-later exposure.

    HNDL matters when quantum-vulnerable crypto protects data with a long
    confidentiality shelf life. Returns a small assessment dict, or None if the
    text shows no quantum-vulnerable crypto.
    """
    if not text:
        return None
    crypto = classify_crypto(text)
    if not crypto["vulnerable"]:
        return None
    long_lived = bool(_LONGLIVED_RE.search(text))
    return {
        "at_risk": True,
        "vulnerable_primitives": crypto["vulnerable"],
        "has_pqc": bool(crypto["safe"]),
        "long_lived_data": long_lived,
        "severity": "high" if long_lived else "medium",
        "note": (
            "Quantum-vulnerable cryptography protecting long-lived data: data "
            "captured today could be decrypted once a cryptographically relevant "
            "quantum computer exists (harvest-now-decrypt-later)."
            if long_lived else
            "Quantum-vulnerable cryptography present; plan migration to PQC."
        ),
    }


def mosca_margin(shelf_life_years: float, migration_years: float,
                 time_to_quantum_years: float) -> Dict[str, object]:
    """Mosca inequality: risk when (shelf_life + migration_time) > time_to_quantum.

    Returns the margin (negative = at risk) and a plain verdict. The margin is
    ``time_to_quantum - (shelf_life + migration_time)``.
    """
    margin = time_to_quantum_years - (shelf_life_years + migration_years)
    at_risk = margin < 0
    return {
        "margin_years": round(margin, 2),
        "at_risk": at_risk,
        "verdict": (
            "At risk now: begin PQC migration immediately — data protected today "
            "will still be sensitive when quantum decryption becomes feasible."
            if at_risk else
            "Margin positive: on the current estimate, migration can complete "
            "before the quantum threat window, but track the estimate."
        ),
    }
