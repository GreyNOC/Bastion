"""Adapter base class.

Every source repo's logic is isolated behind an adapter. Adapters translate a
source repo's concepts into Bastion's shared schemas. They must:

  * expose a guard that converts implementation exceptions to a typed failed
    result; services turn that into one controlled boundary error;
  * declare their provenance (which source repo they represent);
  * be import-safe with no side effects at construction.

The Bastion MVP uses *clean-room* adapters: the defensive logic and data from
each source repo are reimplemented/ported here rather than importing the
original packages, which carry conflicting dependencies (FastAPI vs custom
ASGI, differing Pydantic/uvicorn floors) and, in a few repos, offensive code
that must never be pulled in. See docs/INTEGRATION_NOTES.md.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from ..utils.logging import get_logger


@dataclasses.dataclass
class AdapterResult:
    """Uniform wrapper around an adapter call outcome."""

    ok: bool
    data: Any = None
    error: str | None = None
    adapter: str = ""
    source_repo: str = ""

    def unwrap(self, default=None):
        return self.data if self.ok else default


class AdapterExecutionError(RuntimeError):
    """Controlled service-boundary error for a failed adapter invocation."""


def guarded_call(adapter: BaseAdapter, fn, *args, **kwargs):
    """Invoke an adapter through its isolation boundary or raise one safe error."""
    result = adapter.guard(fn, *args, **kwargs)
    if not result.ok:
        raise AdapterExecutionError(
            f"{result.adapter} adapter failed: {result.error or 'unknown error'}"
        )
    return result.data


class BaseAdapter:
    """Base for all Bastion adapters."""

    #: Human name of the source repo this adapter represents.
    source_repo: str = "unknown"
    #: Short adapter id.
    name: str = "base"

    def __init__(self) -> None:
        self.log = get_logger(f"adapter.{self.name}")

    def available(self) -> bool:
        """Whether this adapter can run in the current environment.

        Clean-room adapters are always available (no external package needed).
        Override if an adapter depends on optional data or binaries.
        """
        return True

    def health(self) -> dict[str, Any]:
        """A small status dict for ``doctor`` / Safety Status."""
        return {
            "adapter": self.name,
            "source_repo": self.source_repo,
            "available": self.available(),
        }

    def _ok(self, data: Any) -> AdapterResult:
        return AdapterResult(ok=True, data=data, adapter=self.name, source_repo=self.source_repo)

    def _fail(self, error: str) -> AdapterResult:
        self.log.warning("adapter %s failed: %s", self.name, error)
        return AdapterResult(ok=False, error=error, adapter=self.name, source_repo=self.source_repo)

    def guard(self, fn, *args, **kwargs) -> AdapterResult:
        """Run ``fn`` and convert any exception into a failed AdapterResult."""
        try:
            return self._ok(fn(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 - deliberate isolation boundary
            from ..safety.masking import scrub_text
            return self._fail(f"{type(exc).__name__}: {scrub_text(str(exc))}")
