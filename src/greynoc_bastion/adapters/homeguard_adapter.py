"""HomeGuard adapter — Assets & Exposure review (risky-service knowledge).

Clean-room port of GreyNOC/HomeGuard's *defensive, non-mutating* asset-review
knowledge: the risky-port knowledge base, plain-English explanations, and
safe local-only remediation guidance. It classifies observed local services
into ``BastionAsset`` records.

Deliberately excluded from the port (flagged unsafe in the audit): firewall
rule rewriting, quarantine/file deletion, process-memory scanning, and
SSH-into-router flows. HomeGuard here is read-only and explanatory.
"""

from __future__ import annotations

from typing import Any

from ..schemas import AssetKind, BastionAsset, Confidence, Exposure, Severity
from .base import BaseAdapter

# Risky-port knowledge base ported verbatim (data only) from HomeGuard's
# DEFAULT_RISKY_PORTS. Every entry carries a plain-English "why".
DEFAULT_RISKY_PORTS: list[dict[str, Any]] = [
    {"port": 21, "service": "FTP", "severity": "medium", "why": "FTP is often unencrypted. Do not expose it unless you know why it is needed."},
    {"port": 22, "service": "SSH", "severity": "low", "why": "SSH is normal for some advanced devices, but it should use strong passwords or keys."},
    {"port": 23, "service": "Telnet", "severity": "high", "why": "Telnet sends logins in clear text and is risky on home networks."},
    {"port": 80, "service": "HTTP", "severity": "info", "why": "A web admin page may be normal for routers, cameras, printers, or smart hubs."},
    {"port": 139, "service": "NetBIOS", "severity": "medium", "why": "Windows file-sharing services should not be reachable from untrusted devices."},
    {"port": 445, "service": "SMB", "severity": "medium", "why": "SMB file sharing can expose files if permissions are weak."},
    {"port": 554, "service": "RTSP", "severity": "medium", "why": "Camera streaming services can expose video feeds if default passwords are still used."},
    {"port": 1080, "service": "SOCKS proxy", "severity": "medium", "why": "Port 1080 is a SOCKS proxy. It can be legitimate, but an unexpected proxy can relay traffic and should be reviewed."},
    {"port": 2323, "service": "Telnet alternate", "severity": "high", "why": "Port 2323 is a Telnet variant commonly scanned on IoT devices. Unexpected Telnet exposure should be disabled."},
    {"port": 3306, "service": "MySQL", "severity": "medium", "why": "MySQL databases should not be exposed unless you specifically run a database server."},
    {"port": 3389, "service": "Remote Desktop", "severity": "high", "why": "Remote Desktop should be disabled unless you intentionally use it."},
    {"port": 4444, "service": "Unusual shell / lab listener", "severity": "high", "why": "Port 4444 is common in labs and testing tools but unusual on normal devices. Review it if you did not intentionally open it."},
    {"port": 5555, "service": "ADB / debug bridge", "severity": "high", "why": "Port 5555 is often Android Debug Bridge or a similar debug service. Exposed debug access should be confirmed."},
    {"port": 5900, "service": "VNC", "severity": "high", "why": "VNC remote-control services are risky when left open or weakly protected."},
    {"port": 5938, "service": "TeamViewer", "severity": "high", "why": "TeamViewer-style remote-control services should only be reachable when you intentionally use them."},
    {"port": 6667, "service": "IRC-style service", "severity": "medium", "why": "Port 6667 is commonly associated with IRC-style services. Unexpected listeners should be reviewed."},
    {"port": 7547, "service": "TR-069 router management", "severity": "high", "why": "Port 7547 (CWMP/TR-069) is a router remote-management protocol widely abused against home routers. It should not be reachable unless your provider requires it."},
    {"port": 8080, "service": "HTTP alternate", "severity": "low", "why": "Alternate web admin ports are common but should be reviewed."},
    {"port": 8443, "service": "HTTPS alternate", "severity": "low", "why": "Alternate web admin ports are common but should be reviewed."},
    {"port": 8888, "service": "HTTP alternate admin", "severity": "medium", "why": "Port 8888 hosts legitimate admin pages for some devices but is unusual on many endpoints. Confirm the service is expected."},
    {"port": 9100, "service": "Raw printing (JetDirect)", "severity": "medium", "why": "Raw print services can be abused to exfiltrate documents or send unwanted print jobs from anywhere on the LAN."},
    {"port": 31337, "service": "Unusual legacy service port", "severity": "high", "why": "Port 31337 is historically unusual on home devices. A port-only observation cannot prove malicious use, but unexpected exposure should be reviewed."},
]

_PORT_INDEX: dict[int, dict[str, Any]] = {p["port"]: p for p in DEFAULT_RISKY_PORTS}

# Idempotent hedging note appended to every asset finding — a port observation
# is not proof of compromise. Ported from HomeGuard guidance.py intent.
INDICATOR_NOTE = (
    "This is based on an observed listening service, not proof of compromise. "
    "Confirm the service is expected before taking action."
)
REPORT_DISCLAIMER = (
    "GreyNOC Bastion performs local, passive review by default. It does not "
    "change device settings, block traffic, or remove files."
)


class HomeGuardAdapter(BaseAdapter):
    source_repo = "GreyNOC/HomeGuard"
    name = "homeguard"

    def lookup_port(self, port: int) -> dict[str, Any] | None:
        return _PORT_INDEX.get(int(port)) if port is not None else None

    def classify_service(
        self,
        *,
        host: str,
        port: int,
        protocol: str = "tcp",
        process: str = "",
        exposure: Exposure = Exposure.LOOPBACK,
        in_baseline: bool = False,
        observed_by: str = "passive",
    ) -> BastionAsset:
        """Turn one observed listening service into a reviewed BastionAsset."""
        kb = self.lookup_port(port)
        service_name = kb["service"] if kb else (process or "unknown service")
        risky = kb is not None
        reasons: list[str] = []
        base_sev = Severity.coerce(kb["severity"], Severity.INFO) if kb else Severity.INFO

        # Exposure escalates severity: a risky service on the LAN/public matters
        # more than the same service bound to loopback.
        severity = base_sev
        if kb:
            reasons.append(kb["why"])
            if exposure == Exposure.PUBLIC and base_sev.rank < Severity.CRITICAL.rank:
                severity = Severity.CRITICAL if base_sev.rank >= Severity.HIGH.rank else Severity.HIGH
                reasons.append("Service appears reachable from outside the local network.")
            elif exposure == Exposure.LAN and base_sev.rank < Severity.HIGH.rank:
                severity = Severity(list(Severity)[min(base_sev.rank + 1, Severity.HIGH.rank)].value)
                reasons.append("Service is reachable across the local network.")
            elif exposure == Exposure.LOOPBACK:
                reasons.append("Service is bound to loopback (this machine only), which limits exposure.")

        if in_baseline:
            reasons.append("Matches a known-good baseline entry; likely expected.")
            if severity.rank > Severity.LOW.rank:
                severity = Severity.LOW

        explanation = self._plain_explanation(host, port, service_name, exposure, kb)
        action = self._remediation(kb, exposure, in_baseline)

        return BastionAsset(
            kind=AssetKind.SERVICE,
            label=f"{service_name} on {host}:{port}",
            host=host,
            port=int(port),
            protocol=protocol,
            process=process,
            service_name=service_name,
            exposure=exposure,
            severity=severity,
            confidence=Confidence.MEDIUM,
            risky=risky,
            risk_reasons=reasons,
            plain_explanation=explanation,
            recommended_action=action,
            in_baseline=in_baseline,
            observed_by=observed_by,
        )

    @staticmethod
    def _plain_explanation(host: str, port: int, service: str, exposure: Exposure, kb) -> str:
        where = {
            Exposure.LOOPBACK: "only reachable from this computer",
            Exposure.LAN: "reachable from other devices on your local network",
            Exposure.PUBLIC: "potentially reachable from the internet",
            Exposure.UNKNOWN: "of unknown reachability",
        }[exposure]
        base = f"A service that looks like {service} is listening on {host}:{port}. It is {where}. "
        if kb:
            base += kb["why"] + " "
        return base + INDICATOR_NOTE

    @staticmethod
    def _remediation(kb, exposure: Exposure, in_baseline: bool) -> str:
        if in_baseline:
            return ("This service is on your known-good baseline. No action needed unless it "
                    "started behaving differently. If it is no longer used, disable it.")
        parts = []
        if kb and exposure in (Exposure.LAN, Exposure.PUBLIC):
            parts.append("If you did not intend to expose this service, disable it or restrict it to loopback.")
        elif kb:
            parts.append("Confirm this service is expected. If not, stop the program that opened this port.")
        else:
            parts.append("This port is not on the risky-service list. Review only if it is unexpected.")
        parts.append("Bastion does not change any settings for you; apply changes yourself after review.")
        return " ".join(parts)

    def review_observations(self, observations: list[dict[str, Any]]) -> list[BastionAsset]:
        """Classify a list of passively-observed services into assets.

        Each observation: ``{host, port, protocol?, process?, exposure?, in_baseline?}``.
        """
        assets: list[BastionAsset] = []
        for obs in observations:
            try:
                exposure = Exposure.coerce(obs.get("exposure"), Exposure.LOOPBACK)
                assets.append(self.classify_service(
                    host=obs.get("host", "127.0.0.1"),
                    port=int(obs["port"]),
                    protocol=obs.get("protocol", "tcp"),
                    process=obs.get("process", ""),
                    exposure=exposure,
                    in_baseline=bool(obs.get("in_baseline", False)),
                    observed_by=obs.get("observed_by", "passive"),
                ))
            except (KeyError, ValueError, TypeError) as exc:
                self.log.warning("skipping malformed observation %s: %s", obs, exc)
        assets.sort(key=lambda a: (a.risky, a.severity.rank), reverse=True)
        return assets
