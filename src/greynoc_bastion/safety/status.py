"""Safety status snapshot.

One structured view of the live safety posture, consumed by:
  * the Safety Status dashboard page,
  * ``bastion doctor`` / ``bastion status``,
  * the test suite (which asserts the defaults are safe).
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass
class SafetyStatus:
    """A point-in-time description of every safety-relevant control."""

    # Network posture
    live_fetch_enabled: bool = False
    allowed_fetch_hosts: list[str] = dataclasses.field(default_factory=list)
    private_host_blocking: bool = True          # always on; here for visibility
    https_only: bool = True                     # always on
    api_binding_host: str = "127.0.0.1"
    api_binding_port: int = 8788
    loopback_only: bool = True

    # Data posture
    report_output_path: str = ""
    secret_storage_policy: str = "masked-only (no full secrets stored, logged, or reported)"

    # AI posture
    ai_assistant_enabled: bool = False
    ai_command_execution_enabled: bool = False
    ai_endpoint_configured: bool = False
    ai_allow_cloud: bool = False

    # Active checks
    active_checks_enabled: bool = False
    active_checks_scope: str = "private/loopback only, opt-in, bounded, logged"

    # Health
    last_doctor_result: str | None = None
    last_doctor_at: str | None = None

    # Derived, human-readable warnings for anything moved off a safe default.
    warnings: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @property
    def posture(self) -> str:
        """Overall posture label for the status badge."""
        if not self.loopback_only:
            return "elevated"
        if self.live_fetch_enabled or self.active_checks_enabled or self.ai_assistant_enabled:
            return "attention"
        return "hardened"


def build_safety_status(
    config,
    *,
    last_doctor_result: str | None = None,
    last_doctor_at: str | None = None,
) -> SafetyStatus:
    """Derive a :class:`SafetyStatus` from a :class:`~greynoc_bastion.config.BastionConfig`."""
    warnings: list[str] = []

    if not config.loopback_only:
        warnings.append(
            f"API is bound to '{config.host}', not loopback. Exposed beyond this machine."
        )
    if config.live_fetch:
        warnings.append(
            "Live fetching is ENABLED. Fetches are HTTPS-only, allowlisted, "
            "size/timeout-capped, and refuse private hosts."
        )
        if not config.fetch_allowlist:
            warnings.append("Live fetching is on but the allowlist is empty; all fetches will be refused.")
    if config.active_checks:
        warnings.append(
            "Active local checks are ENABLED (private/loopback only, bounded, logged)."
        )
    if config.ai_assistant:
        warnings.append("Offline report helper is ENABLED (deterministic formatting; no model calls).")
    if config.ai_command_execution:
        warnings.append(
            "Legacy AI command-execution flag is set, but no command runner is implemented; "
            "requests are refused."
        )
    if config.ai_allow_cloud or config.ai_endpoint:
        warnings.append(
            "Legacy AI endpoint/cloud settings are present but ignored; this build has no "
            "model or network integration."
        )

    return SafetyStatus(
        live_fetch_enabled=config.live_fetch,
        allowed_fetch_hosts=list(config.fetch_allowlist),
        private_host_blocking=True,
        https_only=True,
        api_binding_host=config.host,
        api_binding_port=config.port,
        loopback_only=config.loopback_only,
        report_output_path=str(config.report_dir),
        ai_assistant_enabled=config.ai_assistant,
        ai_command_execution_enabled=config.ai_command_execution,
        ai_endpoint_configured=bool(config.ai_endpoint),
        ai_allow_cloud=config.ai_allow_cloud,
        active_checks_enabled=config.active_checks,
        last_doctor_result=last_doctor_result,
        last_doctor_at=last_doctor_at,
        warnings=warnings,
    )
