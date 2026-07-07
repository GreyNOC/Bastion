"""Base machinery shared by every Bastion schema.

All schemas are plain dataclasses so the MVP has no heavy modelling dependency.
``BastionModel`` gives them deterministic, JSON-safe serialization plus a
tolerant ``from_dict`` that ignores unknown keys (so importing slightly
different shapes from source repos never explodes).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import types
import typing
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TypeVar, get_args, get_origin

T = TypeVar("T", bound="BastionModel")

# Both spellings of a union must be recognized: ``Optional[X]`` / ``Union[...]``
# (origin ``typing.Union``) and the PEP 604 ``X | None`` (origin
# ``types.UnionType``). Missing the latter silently skips nested-model coercion.
_UNION_ORIGINS = (typing.Union, types.UnionType)


def utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing ``Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_correlation_id(prefix: str = "bstn") -> str:
    """A short, sortable-ish correlation id for cross-referencing records.

    Format: ``<prefix>-<12 hex chars>``. Correlation ids tie a finding to its
    evidence, its report entry, and any downstream ticket.
    """
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def stable_fingerprint(*parts: Any) -> str:
    """Deterministic short hash of the given parts.

    Used for de-duplication and — importantly — for representing a secret by a
    non-reversible fingerprint instead of its value. Never feed a raw secret to
    a store; feed its fingerprint.
    """
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:16]


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, BastionModel):
        return value.to_dict()
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    return value


@dataclasses.dataclass
class BastionModel:
    """Base for all Bastion schemas.

    Provides ``to_dict`` / ``to_json`` / ``from_dict``. Subclasses stay pure
    dataclasses; enum fields serialize to their string value and deserialize
    back through each enum's ``coerce`` classmethod when present.
    """

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in dataclasses.fields(self):
            out[f.name] = _to_jsonable(getattr(self, f.name))
        return out

    def to_json(self, *, indent: int | None = None, sort_keys: bool = False) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=sort_keys, ensure_ascii=False)

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        if data is None:
            raise ValueError(f"{cls.__name__}.from_dict got None")
        try:
            hints = typing.get_type_hints(cls)
        except Exception:  # pragma: no cover - defensive
            hints = {}
        kwargs: dict[str, Any] = {}
        for f in dataclasses.fields(cls):
            if f.name not in data:
                continue
            kwargs[f.name] = _coerce_value(hints.get(f.name), data[f.name], _field_default(f))
        return cls(**kwargs)  # type: ignore[arg-type]


def _field_default(f: dataclasses.Field):
    """The declared default of a dataclass field, or None if it has none."""
    if f.default is not dataclasses.MISSING:
        return f.default
    if f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
        try:
            return f.default_factory()  # type: ignore[misc]
        except Exception:  # pragma: no cover - defensive
            return None
    return None


def _coerce_value(ftype: Any, value: Any, default: Any = None) -> Any:
    """Best-effort coercion of a raw value onto a resolved type annotation."""
    if ftype is None or value is None:
        return value

    origin = get_origin(ftype)
    if origin in (list, set, tuple):
        # Guard against a non-sequence value (e.g. a scalar where a list is
        # expected). str/bytes are iterable but must not be char-exploded.
        if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set)):
            return value
        (inner,) = (get_args(ftype) or (None,))[:1] or (None,)
        return [_coerce_value(inner, v) for v in value]
    if origin is dict:
        return value  # dicts are passed through untouched
    if origin in _UNION_ORIGINS:  # Optional[X], Union[...], and X | None
        args = [a for a in get_args(ftype) if a is not type(None)]
        if len(args) == 1:
            return _coerce_value(args[0], value, default)
        return value

    if isinstance(ftype, type) and issubclass(ftype, Enum):
        coerce = getattr(ftype, "coerce", None)
        if callable(coerce):
            # Fall back to the field's declared default (a valid enum member)
            # so an unknown value can never leave None in a non-optional field.
            result = coerce(value, default if isinstance(default, ftype) else None)
            if result is None:
                result = coerce(value, next(iter(ftype)))
            return result
        try:
            return ftype(value)
        except ValueError:
            return default if isinstance(default, ftype) else next(iter(ftype))
    if isinstance(ftype, type) and issubclass(ftype, BastionModel) and isinstance(value, dict):
        return ftype.from_dict(value)
    return value
