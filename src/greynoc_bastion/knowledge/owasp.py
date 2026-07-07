"""OWASP mappings — Non-Human Identity Top 10 (2025) and cross-refs.

Maps discovered non-human identities to the OWASP NHI Top 10 categories so
findings carry recognized framework references. Pure data + lookup functions.
"""

from __future__ import annotations

# OWASP Non-Human Identities Top 10 (2025).
OWASP_NHI_TOP_10: dict[str, str] = {
    "NHI1": "Improper Offboarding",
    "NHI2": "Secret Leakage",
    "NHI3": "Vulnerable Third-Party NHI",
    "NHI4": "Insecure Authentication",
    "NHI5": "Overprivileged NHI",
    "NHI6": "Insecure Cloud Deployment Configurations",
    "NHI7": "Long-Lived Secrets",
    "NHI8": "Environment Isolation",
    "NHI9": "NHI Reuse",
    "NHI10": "Human Use of NHI",
}


def owasp_nhi_for(identity_type: str, *, privileged: bool = False,
                  in_source: bool = True) -> list[dict[str, str]]:
    """Map an identity to relevant OWASP NHI Top 10 categories.

    ``identity_type`` is a ``schemas.IdentityType`` value string.
    """
    refs: list[str] = []
    # A secret found in source/config is, by definition, secret leakage.
    if in_source:
        refs.append("NHI2")
    # Static credentials are long-lived by nature.
    refs.append("NHI7")
    if privileged:
        refs.append("NHI5")

    by_type = {
        "cloud_workload": ["NHI5", "NHI6"],
        "service_account": ["NHI5", "NHI4"],
        "ci_cd_token": ["NHI5", "NHI6"],
        "deployment_identity": ["NHI6"],
        "oauth_app": ["NHI3", "NHI4"],
        "model_gateway": ["NHI3"],
        "mcp_server": ["NHI3", "NHI8"],
        "ai_agent": ["NHI3", "NHI8"],
        "webhook": ["NHI4"],
        "browser_extension": ["NHI3"],
        "ssh_key": ["NHI4", "NHI7"],
    }
    refs.extend(by_type.get(identity_type, []))

    seen: set = set()
    out: list[dict[str, str]] = []
    for r in refs:
        if r in seen or r not in OWASP_NHI_TOP_10:
            continue
        seen.add(r)
        out.append({"id": r, "label": OWASP_NHI_TOP_10[r]})
    return out
