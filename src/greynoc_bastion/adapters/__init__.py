"""Source-repo adapters.

Each adapter isolates one GreyNOC source repo's defensive logic/data behind a
stable interface that speaks Bastion's shared schemas. Adapters are clean-room
ports (see docs/INTEGRATION_NOTES.md) — no conflicting upstream packages are
imported, and no offensive code is pulled in.
"""

from __future__ import annotations

from .base import AdapterResult, BaseAdapter
from .detections_adapter import DetectionsAdapter
from .detector_engine_adapter import DetectorEngineAdapter
from .dmz_adapter import DmzAdapter
from .greyiq_adapter import GreyIQAdapter, TrustAssessment
from .homeguard_adapter import HomeGuardAdapter
from .nhi_adapter import NhiAdapter
from .playbooks_adapter import PlaybooksAdapter
from .port_manager_adapter import PortManagerAdapter

__all__ = [
    "AdapterResult",
    "BaseAdapter",
    "DetectorEngineAdapter",
    "NhiAdapter",
    "DmzAdapter",
    "PlaybooksAdapter",
    "HomeGuardAdapter",
    "DetectionsAdapter",
    "PortManagerAdapter",
    "GreyIQAdapter",
    "TrustAssessment",
]
