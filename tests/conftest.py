"""Shared pytest fixtures.

Each test gets an isolated Bastion home in a temp dir so nothing touches the
operator's real ``~/.greynoc-bastion``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make ``src`` importable without an install step.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from greynoc_bastion.app import BastionApp  # noqa: E402
from greynoc_bastion.config import load_config  # noqa: E402

FIXTURES = _SRC / "greynoc_bastion" / "fixtures"


@pytest.fixture
def home(tmp_path) -> Path:
    return tmp_path / "bastion-home"


@pytest.fixture
def config(home):
    return load_config(overrides={"BASTION_HOME": str(home)})


@pytest.fixture
def app(config) -> BastionApp:
    return BastionApp(config)


@pytest.fixture
def sample_project() -> Path:
    return FIXTURES / "sample_project"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
