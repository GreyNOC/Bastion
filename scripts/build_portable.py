#!/usr/bin/env python3
"""Build a self-contained, portable GreyNOC Bastion bundle.

Produces ``dist/bastion-portable-<version>-<platform>.zip``. Unzip it anywhere
and run the bundled ``bastion`` (POSIX) or ``bastion.cmd`` (Windows) launcher —
the only requirement on the target is a Python 3.10+ interpreter. Bastion's
runtime dependency (Flask and its pure-Python stack) is vendored into the
bundle, so there is no ``pip``/network step at run time.

The bundle is specific to the *building* platform (a vendored wheel may carry a
compiled speedup such as MarkupSafe's), so the platform tag is in the filename;
build on each OS you want to ship. Use ``--no-deps`` for a CLI-only bundle that
vendors nothing (the dashboard's ``serve`` command then needs Flask installed
separately, but every other command works).

Standard library only. Run it with the interpreter you want to build against:

    python scripts/build_portable.py            # full bundle (vendors Flask)
    python scripts/build_portable.py --no-deps  # CLI-only, no vendoring
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PKG = "greynoc_bastion"

_MAIN_PY = """\
import sys

from greynoc_bastion.cli import main

if __name__ == "__main__":
    sys.exit(main())
"""

_LAUNCH_SH = """\
#!/bin/sh
# Portable GreyNOC Bastion launcher. Runs the bundled package with the bundle
# directory on sys.path so vendored deps resolve. Requires python3 on PATH.
here="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$here" "$@"
"""

_LAUNCH_CMD = """\
@echo off
rem Portable GreyNOC Bastion launcher (Windows). Requires python on PATH.
python "%~dp0." %*
"""

_BUNDLE_README = """\
# GreyNOC Bastion — portable bundle

Self-contained build. Requires only a Python 3.10+ interpreter on the target.

Run it:

    ./bastion status          # POSIX
    bastion.cmd status        # Windows

Or invoke the interpreter on the bundle directory directly:

    python . status

Everything is local-first and safe-by-default: the network is off unless you
explicitly enable live fetch, and the dashboard binds to 127.0.0.1 only. See the
project README and docs/ for configuration (BASTION_* environment variables).

This bundle was built for a specific OS/architecture; rebuild on the target
platform if a vendored dependency does not load.
"""


def _project_version() -> str:
    """Read ``[project].version`` from pyproject.toml without a TOML dependency."""
    section = ""
    for raw in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip()
        elif section == "project" and s.startswith("version"):
            return s.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("could not find [project].version in pyproject.toml")


def _copy_package(stage: Path) -> None:
    shutil.copytree(
        SRC / PKG, stage / PKG,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def _vendor_dependencies(stage: Path) -> None:
    """Install Flask (+ its pure-Python stack) into the bundle root via pip."""
    cmd = [
        sys.executable, "-m", "pip", "install", "flask>=3.0",
        "--target", str(stage), "--no-compile", "--disable-pip-version-check",
        "--no-input", "--quiet",
    ]
    print("  vendoring runtime deps:", " ".join(cmd[3:]))
    subprocess.run(cmd, check=True)  # nosec B603 - fixed argv, no shell
    # Drop the console-script shims pip drops in bin/Scripts; we ship launchers.
    for noise in ("bin", "Scripts"):
        shutil.rmtree(stage / noise, ignore_errors=True)


def _write_text(path: Path, text: str, *, executable: bool = False) -> None:
    path.write_text(text, encoding="utf-8")
    if executable:
        path.chmod(0o755)


def _smoke_test(stage: Path) -> None:
    """Prove the bundle runs from its own directory (imports + fixtures wire up)."""
    with tempfile.TemporaryDirectory() as td:
        env = dict(os.environ, BASTION_HOME=td, PYTHONDONTWRITEBYTECODE="1")
        for argv in (["--version"], ["forecast", "demo"]):
            print("  smoke:", "python .", *argv)
            subprocess.run([sys.executable, str(stage), *argv],  # nosec B603 - fixed argv
                           check=True, env=env, stdout=subprocess.DEVNULL)


def _zip_bundle(stage: Path, out_zip: Path) -> None:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    top = stage.name
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stage.rglob("*")):
            if path.is_dir():
                continue
            arcname = f"{top}/{path.relative_to(stage).as_posix()}"
            info = zipfile.ZipInfo(arcname)
            data = path.read_bytes()
            # Preserve an executable bit on the POSIX launcher.
            mode = 0o755 if path.name == "bastion" else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)


def build(*, vendor_deps: bool, out_dir: Path) -> Path:
    version = _project_version()
    platform = sysconfig.get_platform().replace(".", "_").replace("-", "_")
    suffix = "" if vendor_deps else "-cli"
    name = f"bastion-portable-{version}-{platform}{suffix}"

    stage_root = ROOT / "build" / "portable"
    stage = stage_root / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    print(f"building portable bundle: {name}")
    _copy_package(stage)
    if vendor_deps:
        _vendor_dependencies(stage)
    else:
        print("  --no-deps: CLI-only bundle (Flask NOT vendored; 'serve' needs Flask)")
    _write_text(stage / "__main__.py", _MAIN_PY)
    _write_text(stage / "bastion", _LAUNCH_SH, executable=True)
    _write_text(stage / "bastion.cmd", _LAUNCH_CMD)
    _write_text(stage / "README.txt", _BUNDLE_README)

    _smoke_test(stage)

    out_zip = out_dir / f"{name}.zip"
    _zip_bundle(stage, out_zip)
    size_mb = out_zip.stat().st_size / (1024 * 1024)
    print(f"ok: {out_zip}  ({size_mb:.1f} MiB)")
    return out_zip


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a portable GreyNOC Bastion bundle.")
    parser.add_argument("--no-deps", action="store_true",
                        help="CLI-only bundle; do not vendor Flask (no build-time network)")
    parser.add_argument("--out", default=str(ROOT / "dist"),
                        help="output directory for the .zip (default: dist/)")
    args = parser.parse_args(argv)
    try:
        build(vendor_deps=not args.no_deps, out_dir=Path(args.out))
    except subprocess.CalledProcessError as exc:
        print(f"error: a build step failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
