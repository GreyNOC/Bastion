"""GreyNOC Bastion — local-first defensive cyber operations platform.

Bastion unifies threat forecasting, non-human identity auditing, detection
validation, operator playbooks, local asset/exposure review, reporting, and a
deterministic offline report helper in one defensive console.

Design tenets (enforced elsewhere in this package):
  * Local-first. Loopback binding by default. No cloud dependency for the MVP.
  * Live fetching off by default; guarded when enabled.
  * No full secrets stored, logged, or reported.
  * No offensive capability. Defensive only.
"""

__version__ = "0.3.0"
__product__ = "GreyNOC Bastion"

__all__ = ["__version__", "__product__"]
