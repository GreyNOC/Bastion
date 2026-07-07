# GreyNOC Security Playbook

## Distributed Port Scan Detection & Response

---

### 1. Overview

A distributed port scan is reconnaissance activity in which an adversary maps services on one or many targets by issuing connection probes from **multiple coordinated source IPs**. By spreading probes across sources, the attacker evades per-IP rate thresholds that detect classic single-source nmap-style scanning.

Port scanning precedes most targeted intrusions. It identifies exploitable services (SSH, RDP, SMB, Exchange, web admin panels, exposed databases) and feeds vulnerability triage. Internet-facing infrastructure sees this constantly; the operational question is whether a given burst is opportunistic noise or coordinated reconnaissance of your specific surface.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Network Service Discovery | T1046 | Discovery |
| Active Scanning | T1595 | Reconnaissance |
| Active Scanning: Scanning IP Blocks | T1595.001 | Reconnaissance |
| Active Scanning: Vulnerability Scanning | T1595.002 | Reconnaissance |

---

### 3. Detection Strategy

Single-source scan detection is solved. The harder problem is distributed scans, where each source touches few ports but the aggregate coverage of your assets is comprehensive.

Effective detection requires shifting the analysis pivot:

- Pivot on destination, not source. Aggregate by `(dst_ip, dst_port)` and look at distinct sources hitting it.
- Time-correlate small probes across sources within a window. A coordinated scan typically completes in minutes to hours.
- Detect coverage anomalies, such as an unusual number of ports touched against a single asset within a window, regardless of how many sources are involved.
- Apply graph or set-based correlation: cluster sources that touched overlapping target/port sets, especially if they share TCP/IP fingerprint, TTL, window size, or timing patterns.
- Differentiate opportunistic Internet noise (mass-Internet scanners hitting a single port) from targeted distributed scans (your subnet, many ports, many sources, narrow window).

---

### 4. Key Indicators

- Many distinct source IPs probing the same destination IP within a short window.
- Sequential or strided port coverage across sources (each source hits a slice of the port space).
- Sources sharing TCP fingerprint (TTL, window size, options) or JA3/JA4 hashes.
- SYN packets without follow-up ACK (half-open scan signature) at scale.
- Probes against ports/services that have no public-facing role for the asset.
- Timing patterns: tightly clustered start times, suspiciously even pacing across sources.
- Sources in disparate ASNs but converging on a small set of destinations.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Distributed Port Scan - Many Sources, One Destination",
  "description": "Detects coordinated port scanning where many distinct sources probe a single destination across multiple ports within a short window.",
  "data_source": ["Firewall.Conn", "NetFlow", "IDS.Alerts"],
  "logic": {
    "window": "10m",
    "group_by": ["dst_ip"],
    "where": {
      "tcp_flags_in": ["SYN", "SYN_only"],
      "bytes_in_lt": 200
    },
    "having": {
      "distinct_src_ip_gte": 25,
      "distinct_dst_port_gte": 30,
      "avg_ports_per_src_lte": 5
    }
  },
  "severity": "medium",
  "tags": ["T1046", "T1595", "reconnaissance", "perimeter"]
}
```

---

### 6. Example Event Data

```json
[
  {"ts":"2025-03-10T22:01:11Z","src":"185.12.X.X","dst":"203.0.113.10","dport":22,"flags":"S","bytes":60},
  {"ts":"2025-03-10T22:01:12Z","src":"194.55.X.X","dst":"203.0.113.10","dport":80,"flags":"S","bytes":60},
  {"ts":"2025-03-10T22:01:12Z","src":"45.143.X.X","dst":"203.0.113.10","dport":443,"flags":"S","bytes":60},
  {"ts":"2025-03-10T22:01:13Z","src":"77.91.X.X","dst":"203.0.113.10","dport":3389,"flags":"S","bytes":60},
  {"ts":"2025-03-10T22:01:14Z","src":"185.12.X.X","dst":"203.0.113.10","dport":445,"flags":"S","bytes":60},
  {"ts":"2025-03-10T22:01:15Z","src":"194.55.X.X","dst":"203.0.113.10","dport":3306,"flags":"S","bytes":60}
]
```

---

### 7. Investigation Steps

1. **Confirm coordination.** Plot probes over time. Coordinated scans show synchronized starts and even port distribution across sources; opportunistic scanners do not.
2. **Map the coverage.** Determine the full port set probed against the destination(s) and any responses.
3. **Identify responsive services.** Any port that returned `SYN-ACK` is now known to the attacker — prioritize hardening or exposure review for those.
4. **Profile the source set.** ASN, geolocation, hosting provider, TCP fingerprint, JA3/JA4. Are the sources cloud/VPS, residential proxies, or known scanner infrastructure?
5. **Correlate with other surfaces.** Are the same sources also touching DNS, web crawl endpoints, or auth portals?
6. **Check downstream telemetry.** Did any of the sources, or related infrastructure, return for an exploitation attempt against a discovered service?
7. **Pivot on shared characteristics** to surface the full source set (not just the IPs that triggered the rule).

---

### 8. False Positive Considerations

- Internet-wide research scanners (Shodan, Censys, Project Sonar, Rapid7 Sonar, Shadowserver). Many announce themselves with reverse DNS or specific user-agents.
- Authorized external attack-surface management (ASM) and penetration testing.
- Multi-source CDN or load balancer health checks if naïvely aggregated.
- Anti-DDoS providers probing your edge.
- Internal vulnerability scanners probing through NAT (apparent multi-source from NAT pools).

---

### 9. Tuning Guidance

- Maintain an allowlist of known research scanners by ASN/PTR — but **alert separately** on any new ones that appear.
- Suppress single-port mass-Internet noise (e.g., port 23 scans) at a different severity than multi-port targeted activity.
- Tune destination thresholds to your **asset surface size** — a /24 with 5 hosts has different normal than a /24 with 250.
- Use **TCP fingerprint clustering** to escalate confidence: many sources sharing identical fingerprints often indicates a single distributed tool.
- Decay scores for sources that probe and disappear; sustain scores for sources that probe, return, and probe again with overlapping coverage.

---

### 10. Response Actions

**Immediate**

- Add the source set to perimeter blocklists.
- Identify any responsive service discovered during the scan and validate it should be exposed.
- Capture full PCAP / NetFlow for the window for retrospective analysis.

**Short-term**

- Reduce the public attack surface: take any unintentionally exposed service offline.
- Add geo / ASN-based access controls where supported.
- Enable rate limiting and SYN flood protections at the edge.
- Update IDS/IPS signatures for the observed scanner fingerprint.

**Long-term**

- Continuous external attack surface management (ASM) to baseline what *should* be exposed.
- Deploy deception assets (canary services on common scanned ports) to catch follow-up exploitation attempts.
- Move from allowlist-on-detection to **default-deny** ingress with explicit exceptions.
- Track and trend reconnaissance volume against your surface as a leading indicator of targeting interest.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- The scan was followed by exploitation attempts against discovered services.
- Probed assets included sensitive systems that should not be Internet-reachable (RDP, SMB, databases, ICS/OT).
- The same coordinated source set has previously been observed targeting the org or its supply chain.
- The scan completes a full TCP handshake against a sensitive service (suggests authentication or vuln-check, not just discovery).

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Target IP(s) / Subnet:
Distinct Source IPs:
Source ASN(s) / Geo:
Ports Probed (set):
Responsive Services Discovered:
Coordination Indicators (timing, fingerprint):
Follow-On Activity Observed:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Distributed scans hide in the aggregate. No single source crosses a per-IP threshold, but the destination sees comprehensive coverage in a narrow window. Detection has to pivot to the destination dimension and correlate sources by timing and fingerprint. Anything the scan discovered as responsive is on an exploitation shortlist somewhere; harden it before the follow-up arrives.

---

*GreyNOC — detection-engineering-first security operations.*
