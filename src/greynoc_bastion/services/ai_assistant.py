"""AI Assistant service.

A thin, safety-first wrapper over the GreyIQ adapter. Disabled by default. When
enabled it explains findings, summarizes reports, and drafts tickets using
deterministic, offline helpers — no network, no model required. Command
execution is a separate gate and remains disabled/refused in the MVP.

Untrusted inputs (file contents, feed text) are screened for prompt-injection
before use, and treated strictly as data.
"""

from __future__ import annotations

from typing import Any

from ..adapters.greyiq_adapter import GreyIQAdapter
from ..config import BastionConfig
from ..db import Database
from ..schemas import BastionFinding, BastionReport
from ..utils.logging import get_logger


class AIAssistantService:
    def __init__(self, config: BastionConfig, db: Database | None = None):
        self.config = config
        self.db = db
        self.log = get_logger("ai_assistant")
        self.adapter = GreyIQAdapter(
            enabled=config.ai_assistant,
            command_execution=config.ai_command_execution,
            allow_cloud=config.ai_allow_cloud,
            endpoint=config.ai_endpoint,
        )

    @property
    def enabled(self) -> bool:
        return self.config.ai_assistant

    def _require_enabled(self) -> dict[str, Any] | None:
        if not self.enabled:
            return {
                "enabled": False,
                "message": (
                    "The AI assistant is disabled. Enable it with BASTION_AI_ASSISTANT=true. "
                    "It runs locally and never uploads your data unless you also set "
                    "BASTION_AI_ALLOW_CLOUD=true."
                ),
            }
        return None

    def explain_finding(self, finding: BastionFinding) -> dict[str, Any]:
        blocked = self._require_enabled()
        if blocked:
            return blocked
        return {"enabled": True, "text": self.adapter.explain_finding(finding)}

    def summarize_report(self, report: BastionReport) -> dict[str, Any]:
        blocked = self._require_enabled()
        if blocked:
            return blocked
        return {"enabled": True, "text": self.adapter.summarize_report(report)}

    def draft_ticket(self, finding: BastionFinding) -> dict[str, Any]:
        blocked = self._require_enabled()
        if blocked:
            return blocked
        return {"enabled": True, "ticket": self.adapter.draft_ticket(finding)}

    def screen_untrusted(self, text: str) -> dict[str, Any]:
        """Always available: screen text for prompt-injection (a safety tool)."""
        assessment = self.adapter.assess_text(text)
        return {"assessment": assessment.to_dict(), "wrapped": self.adapter.wrap_untrusted(text)}

    def request_command_execution(self, command: str, workspace: str = "") -> dict[str, Any]:
        """Gated + logged + refused in the MVP."""
        result = self.adapter.request_command_execution(command, workspace)
        if self.db:
            self.db.audit(
                "ai_command_execution_requested",
                actor="ai_assistant",
                detail=f"executed={result['executed']} gate={self.adapter.can_execute_commands()}",
            )
        return result
