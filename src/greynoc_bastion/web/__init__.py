"""Local web dashboard (Flask, loopback-bound by default)."""

from __future__ import annotations

from .server import create_app, serve

__all__ = ["create_app", "serve"]
