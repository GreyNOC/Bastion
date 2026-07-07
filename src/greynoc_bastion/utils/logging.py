"""Logging with mandatory secret scrubbing.

Every log record passes through :class:`ScrubbingFilter`, which runs the
message (and args) through the safety scrubber. This is a defense-in-depth
backstop: even if a caller forgets to mask, secrets never reach the log sink.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from ..safety.masking import scrub_text

_CONFIGURED = False


class ScrubbingFilter(logging.Filter):
    """Redact secret-looking substrings from every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        scrubbed = scrub_text(msg)
        if scrubbed != msg:
            record.msg = scrubbed
            record.args = ()
        return True


def setup_logging(level: str = "INFO", stream=None) -> None:
    """Configure root logging once, with the scrubbing filter attached."""
    global _CONFIGURED
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    handler.addFilter(ScrubbingFilter())

    root = logging.getLogger("greynoc_bastion")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a Bastion child logger (configures logging on first use)."""
    if not _CONFIGURED:
        setup_logging()
    suffix = name or "core"
    return logging.getLogger(f"greynoc_bastion.{suffix}")
