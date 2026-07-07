"""Port-Manager adapter — localhost service / dev-server tracking.

Clean-room port of GreyNOC/Port-Manager's *passive* localhost inventory
concepts (Python, not the Electron shell). It reads the local machine's own
socket table (no packets are sent — this is local introspection, not network
probing) and labels dev servers using ported ``DEV_HINTS`` / ``COMMON_PORTS``
knowledge, then classifies each endpoint's exposure scope.

Excluded from the port (flagged unsafe): process kill/stop, PowerShell
``-ExecutionPolicy Bypass`` string interpolation, and the CLI auto-install shim.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

from ..schemas import Exposure
from .base import BaseAdapter

# port -> dev/service label (ported COMMON_PORTS).
COMMON_PORTS: Dict[int, str] = {
    3000: "React / Next.js / Node dev server",
    3001: "Node dev server",
    4200: "Angular dev server",
    5000: "Flask / dev server",
    5173: "Vite dev server",
    5174: "Vite dev server",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "Python http.server / Django",
    8080: "HTTP alternate / dev proxy",
    8888: "Jupyter / admin",
    9000: "PHP / SonarQube / dev",
    27017: "MongoDB",
}

# process/command regex -> dev framework label (ported DEV_HINTS).
DEV_HINTS: List[tuple] = [
    (re.compile(r"vite", re.I), "Vite"),
    (re.compile(r"next(?:\.js|-server)?", re.I), "Next.js"),
    (re.compile(r"react-scripts", re.I), "React"),
    (re.compile(r"astro", re.I), "Astro"),
    (re.compile(r"nuxt", re.I), "Nuxt"),
    (re.compile(r"svelte|vite-plugin-svelte", re.I), "Svelte"),
    (re.compile(r"webpack", re.I), "Webpack"),
    (re.compile(r"ng\s+serve|angular", re.I), "Angular"),
    (re.compile(r"flask", re.I), "Flask"),
    (re.compile(r"django|manage\.py\s+runserver", re.I), "Django"),
    (re.compile(r"uvicorn|fastapi", re.I), "FastAPI/Uvicorn"),
    (re.compile(r"jupyter", re.I), "Jupyter"),
    (re.compile(r"http\.server", re.I), "Python http.server"),
]

# Windows system process names that are expected to hold ports.
WINDOWS_SYSTEM_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "spoolsv.exe",
}


def classify_endpoint(addr: str) -> Exposure:
    """Classify a bind address into an exposure scope."""
    if not addr:
        return Exposure.UNKNOWN
    a = addr.strip().strip("[]").lower()
    if a in ("*", "0.0.0.0", "::", "[::]"):
        # Bound to all interfaces -> reachable from the LAN.
        return Exposure.LAN
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        if a in ("localhost", "ip6-localhost"):
            return Exposure.LOOPBACK
        return Exposure.UNKNOWN
    if ip.is_loopback:
        return Exposure.LOOPBACK
    if ip.is_private or ip.is_link_local:
        return Exposure.LAN
    return Exposure.PUBLIC


def label_service(port: int, process: str = "") -> str:
    for pat, label in DEV_HINTS:
        if process and pat.search(process):
            return f"{label} dev server"
    return COMMON_PORTS.get(port, process or "service")


def is_dev_server(port: int, process: str = "") -> bool:
    if port in COMMON_PORTS and port not in (5432, 6379, 27017):
        return True
    return any(pat.search(process or "") for pat, _ in DEV_HINTS)


class PortManagerAdapter(BaseAdapter):
    source_repo = "GreyNOC/Port-Manager"
    name = "port_manager"

    def list_local_listeners(self, *, active: bool = True) -> List[Dict[str, Any]]:
        """Read the local socket table for LISTENING sockets.

        Returns observations ``{host, port, protocol, process, exposure, is_dev_server}``.
        This reads the OS's own connection table; it sends no network traffic.
        ``active=False`` returns an empty list (used when the operator has not
        opted into any local enumeration).
        """
        if not active:
            return []
        system = platform.system().lower()
        try:
            if system == "windows":
                raw = self._run(["netstat", "-ano", "-p", "TCP"])
                return self._parse_netstat_windows(raw)
            # Linux/macOS: prefer ss, fall back to netstat.
            raw = self._run(["ss", "-ltnH"]) or self._run(["netstat", "-ltn"])
            return self._parse_ss(raw)
        except Exception as exc:  # noqa: BLE001 - never crash the caller
            self.log.warning("local listener enumeration failed: %s", exc)
            return []

    @staticmethod
    def _run(cmd: List[str]) -> str:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, check=False,
            )
            return proc.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return ""

    def _parse_netstat_windows(self, raw: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: set = set()
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0].upper() != "TCP":
                continue
            if "LISTENING" not in [p.upper() for p in parts]:
                continue
            local = parts[1]
            host, port = self._split_addr(local)
            if port is None:
                continue
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            exposure = classify_endpoint(host)
            out.append({
                "host": host, "port": port, "protocol": "tcp", "process": "",
                "exposure": exposure.value, "is_dev_server": is_dev_server(port),
                "service": label_service(port), "observed_by": "active-local",
            })
        return out

    def _parse_ss(self, raw: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: set = set()
        for line in raw.splitlines():
            if "LISTEN" not in line.upper() and not line.strip().startswith(("tcp", "LISTEN")):
                # ss -ltnH omits the state column header; accept lines with an addr:port.
                pass
            m = re.search(r"(\S+):(\d+)\s", line)
            if not m:
                continue
            host, port = m.group(1), int(m.group(2))
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            exposure = classify_endpoint(host)
            out.append({
                "host": host, "port": port, "protocol": "tcp", "process": "",
                "exposure": exposure.value, "is_dev_server": is_dev_server(port),
                "service": label_service(port), "observed_by": "active-local",
            })
        return out

    @staticmethod
    def _split_addr(addr: str) -> tuple:
        """Split ``host:port`` handling IPv6 ``[::]:port``."""
        addr = addr.strip()
        if addr.startswith("["):
            m = re.match(r"\[(.+)\]:(\d+)$", addr)
            if m:
                return m.group(1), int(m.group(2))
            return addr, None
        if ":" in addr:
            host, _, port = addr.rpartition(":")
            try:
                return host, int(port)
            except ValueError:
                return host, None
        return addr, None
