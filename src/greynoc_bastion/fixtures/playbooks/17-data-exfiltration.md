# GreyNOC Security Playbook

## Data Exfiltration Detection & Response

---

### 1. Overview

Data exfiltration is the theft phase: data is located, staged (typically compressed and encrypted into archives), and moved out of the environment — over the existing C2 channel, direct uploads to attacker infrastructure, personal cloud storage (MEGA, Dropbox, personal Google Drive/OneDrive), or alternative protocols like DNS and FTP/SFTP. External actors running double-extortion ransomware exfiltrate *before* encrypting; the theft is the leverage. Tooling like Rclone, MEGAsync, WinSCP, and FileZilla shows up constantly in these intrusions because it blends with legitimate admin activity.

The second major driver is the insider: a departing employee copying customer lists, source code, or design documents to personal cloud accounts or USB in the weeks before resignation. Both cases produce the same core telemetry — staging artifacts on the host and egress anomalies on the wire — but differ sharply in identity context, which makes HR-status enrichment a first-class detection feature, not an afterthought.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Archive Collected Data | T1560 | Collection |
| Data Staged | T1074 | Collection |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | Exfiltration |
| Data Transfer Size Limits | T1030 | Exfiltration |
| Automated Exfiltration | T1020 | Exfiltration |

---

### 3. Detection Strategy

No single event is "exfiltration." The signal is a chain: collection → staging → egress. Detect each link independently, then correlate on host and identity.

- Staging telemetry. Archiver execution (`7z`, `rar`, `tar`, `zip`) with recursive paths against file shares, `-p`/`-hp` password flags, or volume-split flags (`-v500m`). Large archives written to `%TEMP%`, `C:\Windows\Temp`, `$Recycle.Bin`, or web-root directories.
- Volume against baseline. Model bytes-out per host and per user (daily and hourly). Alert on deviations measured in standard deviations, not fixed thresholds — a 2 GB upload is noise for a build server and a siren for a receptionist's laptop.
- Byte-ratio inversion. Most endpoints download far more than they upload. A host whose upload:download ratio inverts over a window is staging-and-sending.
- Destination character. Personal cloud storage, file-sharing services, newly seen FTP/SFTP endpoints, hosting-ASN IPs with no prior history for the host. Distinguish corporate-tenant SaaS from personal accounts of the same service where the proxy allows it.
- Transfer shape. Many sequential flows of near-identical size (chunked uploads, deliberate size-limit evasion) to one destination; long single flows with sustained outbound throughput.
- DNS volume. Aggregate bytes of query traffic per second-level domain; tunneled exfil produces sustained high query volume with high-entropy labels.
- Time and identity context. Off-hours bulk transfers, and any egress anomaly from a user with a resignation or termination flag.

---

### 4. Key Indicators

- Archiver processes run with password/encryption flags or volume-splitting against network shares or document trees.
- Rclone, MEGAsync, MEGAcmd, WinSCP, FileZilla, or `curl`/`bitsadmin` uploads appearing on hosts with no history of them.
- Outbound byte volume ≥ 3–5σ above the host's or user's rolling baseline.
- Upload:download byte ratio inverted (≥ 2–3:1) over a multi-hour window.
- Repeated outbound flows of uniform size (e.g., every chunk 250 MB ± <1%) to a single destination.
- Uploads to MEGA, anonymous file-sharing sites, or personal instances of Dropbox/Google Drive/OneDrive.
- FTP/SFTP sessions to destinations the host has never contacted, especially external IPs with no rDNS.
- Sustained elevated outbound volume on an existing C2 channel (beacon that suddenly transmits megabytes upstream).
- DNS query volume to a single domain orders of magnitude above fleet norms.
- Bulk transfer activity between 00:00 and 05:00 local for a user with a daytime-only baseline.
- Egress anomaly from an employee with a pending departure date.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Exfiltration - Egress Volume Anomaly with Staging Correlation",
  "description": "Detects outbound byte volume exceeding per-host/per-user baseline toward non-sanctioned destinations, escalating on staging artifacts, personal cloud destinations, uniform chunking, off-hours timing, or departing-employee context.",
  "data_source": ["Zeek.conn", "Firewall.Conn", "Proxy.Access", "EDR.ProcessEvents", "DNS.Query", "HR.IdentityContext"],
  "logic": {
    "window": "24h",
    "group_by": ["src_ip", "user", "dst_domain"],
    "where": {
      "direction": "outbound",
      "dst_scope": "external",
      "dst_category_not_in": ["sanctioned_saas", "sanctioned_backup", "corporate_cdn"]
    },
    "having": {
      "bytes_out_gte": 500000000,
      "bytes_out_baseline_stddev_gte": 4,
      "upload_download_ratio_gte": 2
    },
    "escalate_if_any": [
      "src.archive_created_last_24h == true and archive.password_protected == true",
      "dst.category in ['personal_cloud_storage', 'file_sharing'] or dst.tenant == 'non_corporate'",
      "flow.uniform_chunk_count_gte == 10 and flow.chunk_size_cv <= 0.02",
      "event.local_hour not in user.baseline_active_hours",
      "user.hr_status in ['resignation_notice', 'termination_pending', 'contract_ending']",
      "dst.protocol in ['ftp', 'sftp'] and src.has_history_with_dst == false",
      "src.process in ['rclone.exe', 'megasync.exe', 'winscp.exe'] and src.process_first_seen_on_host == true"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1560", "T1074", "T1041", "T1048", "T1567.002", "T1030", "T1020", "exfiltration"]
}
```

---

### 6. Example Event Data

```
Sysmon EID 1 (staging)
UtcTime: 2025-06-18 01:47:12
Image: C:\Users\d.reyes\Downloads\7z.exe
CommandLine: 7z.exe a -p******** -v250m C:\Windows\Temp\fin_q2.7z "\\fs01.corp.local\Finance\" "\\fs01.corp.local\Legal\Contracts\" -r
User: CORP\d.reyes   ParentImage: C:\Windows\System32\cmd.exe

Zeek conn.log (chunked, uniform, off-hours)
2025-06-18T02:03:41Z  10.22.4.61  49822  203.0.113.45  443  tcp  ssl  orig_bytes=262144108  resp_bytes=48211
2025-06-18T02:09:17Z  10.22.4.61  49867  203.0.113.45  443  tcp  ssl  orig_bytes=262144090  resp_bytes=47986
2025-06-18T02:14:55Z  10.22.4.61  49901  203.0.113.45  443  tcp  ssl  orig_bytes=262144112  resp_bytes=48307
2025-06-18T02:20:32Z  10.22.4.61  49944  203.0.113.45  443  tcp  ssl  orig_bytes=262144095  resp_bytes=48120

Proxy access log
2025-06-18T02:03:40Z  user=d.reyes  src=10.22.4.61  dst=gfs270n085.userstorage.mega[.]co[.]nz  method=POST  category=personal-cloud-storage  bytes_out=262144108
```

Host baseline for `10.22.4.61`: mean daily bytes-out 180 MB; this window: 4.2 GB. User `d.reyes`: resignation effective 2025-06-27.

---

### 7. Investigation Steps

1. **Quantify the egress.** Total bytes out, destination(s), protocol, flow count, chunk-size distribution, start/stop times. Compare against the host's and user's 30-day baseline.
2. **Find the staging.** Search EDR for archiver executions, large file writes to temp/staging paths, and file-share enumeration in the 24–72h before the transfer. Recover archive names, sizes, and password flags.
3. **Identify what was taken.** Map staged paths back to source shares and data classification. File-server audit logs and archive contents (if recoverable) define the breach scope.
4. **Attribute the channel.** Corporate tenant or personal account? Known C2 destination? New FTP endpoint? Pull TLS SNI, proxy category, and destination history for the host.
5. **Establish the actor.** Interactive insider (console session, business hours, single host) vs. external actor (preceded by beaconing, lateral movement, credential theft, activity across multiple hosts).
6. **Check identity context.** HR status, resignation date, recent access-pattern changes, badge/VPN records for the transfer window.
7. **Sweep for parallel exfil.** Same destination, same tooling hash, same chunk signature across the fleet — double-extortion crews commonly stage from multiple hosts.
8. **Preserve evidence early.** Flow records, proxy logs, and cloud-provider logs age out; snapshot them before containment discussion slows things down.

---

### 8. False Positive Considerations

- Sanctioned backup and sync agents (Veeam, Druva, corporate OneDrive/Drive sync) producing large, regular uploads.
- Developers pushing container images, build artifacts, or large repos to registries and code hosts.
- Media, design, and research teams legitimately uploading large files to vendor portals.
- OS/application telemetry, crash-dump, and log-shipping bursts.
- Cloud migrations and IT-driven data-center moves scheduled off-hours.
- Video conferencing and screen-sharing inflating upload ratios (well-known destinations; exclude by category, not volume).

---

### 9. Tuning Guidance

- Baseline per host role and per user, not fleet-wide. Maintain separate profiles for servers, developer workstations, and standard endpoints.
- Suppress on **destination + process + identity** tuples, never on volume alone — a backup agent uploading to a new destination should still fire.
- Treat corporate-tenant SaaS and personal accounts of the same service as different destinations; enforce tenant restrictions at the proxy to make the distinction observable.
- Weight staging + egress correlation heavily: archiver-with-password followed by an egress anomaly on the same host within 24h should be near-zero-FP.
- Lower all thresholds for users on HR departure watchlists and for hosts holding regulated data.
- For DNS-exfil logic, alert on per-domain aggregate query bytes and label entropy; exclude major CDN and telemetry domains by list.

---

### 10. Response Actions

**Immediate**

- Isolate the source host; block the destination (domain, IP, tenant) at proxy/firewall/DNS.
- Suspend the associated account's sessions and cloud tokens if insider activity is suspected.
- Preserve flow records, proxy logs, EDR telemetry, and any staged archives before they are deleted.
- If an external actor is suspected, assume ransomware deployment is imminent — check backups and privileged-account integrity now.

**Short-term**

- Scope the stolen data: staged paths, archive contents, file-server audit trails.
- Issue legal preservation hold and engage HR/legal for insider cases; engage IR retainer and counsel for external double-extortion cases.
- Request takedown/content logs from the receiving cloud provider where possible.
- Sweep the fleet for the same tooling, destinations, and chunk signatures; reset credentials touched by the actor.

**Long-term**

- Enforce egress controls: category blocks for personal cloud storage and file sharing, tenant restrictions for sanctioned SaaS, default-deny outbound FTP/SFTP.
- Deploy DLP on endpoints and egress points for classified data paths.
- Block or alert on unapproved transfer tooling (Rclone, MEGAsync) via application control.
- Build a standing departing-employee monitoring workflow with HR-fed watchlists.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Staging (password-protected archive) and egress anomaly correlate on the same host within 24 hours.
- Confirmed upload of internal data to personal cloud storage or an unknown external endpoint.
- Egress follows established C2 activity or lateral movement (probable double-extortion staging).
- Volume exceeds baseline from a host holding regulated or crown-jewel data.
- The user has a pending departure and the destination is personal or unsanctioned.
- Multiple hosts exfiltrate to the same destination or with the same tooling.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Source Host / User:
HR Status (departing?):
Destination(s) / Category / Tenant:
Protocol / Tooling:
Total Bytes Out / Baseline Deviation:
Chunking Pattern (size / count):
Transfer Window (off-hours?):
Staging Observed:
  - Archiver / Flags:
  - Archive Paths / Sizes:
Data Scoped (shares, classification):
Actor Assessment (insider / external):
Related C2 or Lateral Movement:
Fleet Sweep Findings:
Containment Actions:
Legal / HR Engaged:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Exfiltration is a chain — collect, stage, send — and the chain is the detection. Staging artifacts (password-protected archives, volume splits) plus an egress anomaly (baseline deviation, ratio inversion, uniform chunking, off-hours timing) on the same host is a near-certain confirmation. Destination character separates the cases: personal cloud with a departing employee is an insider matter for HR and legal; hosting infrastructure behind existing C2 means double-extortion is in progress and encryption is next. Either way, scope the stolen data immediately — response obligations are driven by what left, not by what alerted.

---

*GreyNOC — detection-engineering-first security operations.*
