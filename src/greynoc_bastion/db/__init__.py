"""Bastion persistence layer (SQLite; Postgres-ready repository pattern)."""

from __future__ import annotations

from .database import Database

__all__ = ["Database"]
