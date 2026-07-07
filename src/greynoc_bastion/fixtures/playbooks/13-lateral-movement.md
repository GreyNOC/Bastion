# GreyNOC Security Playbook

## Lateral Movement Detection & Response

---

### 1. Overview

Lateral movement is host-to-host propagation inside the network after initial access: SMB admin-share abuse with remote service creation (the PsExec pattern), WMI and WinRM remote execution, RDP session chains, SSH between Linux hosts, DCOM activation, and authentication-material abuse (pass-the-hash, pass-the-ticket). It is the phase where a single compromised endpoint becomes domain-wide compromise, and it is where ransomware operators spend most of their hands-on-keyboard time.

The detection problem is a graph problem, not a per-host problem. Every remote authentication is an edge between two nodes; legitimate edges are repetitive and predictable (admins to servers, servers to servers). Attackers create *new* edges — especially workstation-to-workstation — and fan out from a pivot host. Modeling the authentication graph and alerting on first-time edges, fan-out, and logon-type anomalies catches lateral movement regardless of which specific tool the attacker uses.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| Remote Services: Distributed Component Object Model | T1021.003 | Lateral Movement |
| Remote Services: SSH | T1021.004 | Lateral Movement |
| Remote Services: Windows Remote Management | T1021.006 | Lateral Movement |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | Defense Evasion / Lateral Movement |
| Use Alternate Authentication Material: Pass the Ticket | T1550.003 | Defense Evasion / Lateral Movement |
| Lateral Tool Transfer | T1570 | Lateral Movement |
| Windows Management Instrumentation | T1047 | Execution |
| System Services: Service Execution | T1569.002 | Execution |

---

### 3. Detection Strategy

Individual remote logons look benign; the signal emerges when authentications are treated as edges in a host-to-host graph and compared against baseline.

- Edge novelty. Maintain a rolling baseline (30–90 days) of `(src_host, dst_host, account)` authentication edges. A first-time edge is the core primitive; several first-time edges from one source in a short window is the alert.
- Fan-out. Count distinct destination hosts per source host per window. A workstation touching 5+ hosts it has never authenticated to is a pivot, a scanner, or a misconfiguration — all worth triage.
- Segment awareness. Workstation-to-workstation traffic (SMB 445, RDP 3389, WinRM 5985/5986, SSH 22) is rare in most environments and high signal by itself.
- Logon-type anomalies. Windows 4624 type 3 (network) is the lateral workhorse; type 10 (RemoteInteractive) maps RDP chains; type 9 (NewCredentials, `seclogo`) is the classic pass-the-hash artifact. 4648 (explicit credentials) shows an account running as someone else.
- Execution correlation. Pair the inbound edge with what happened next on the destination: 5140/5145 `ADMIN$`/`C$`/`IPC$` access, 7045 service install, `WmiPrvSE.exe` or `wsmprovhost.exe` spawning shells, DCOM activation via `mmc.exe`/`DllHost.exe` child processes.
- Kerberos anomalies. Pass-the-ticket shows as TGS use without a corresponding TGT request from that host, or tickets with mismatched account/host pairs.

---

### 4. Key Indicators

- First-time authentication edge between two internal hosts, especially with a privileged or service account.
- One source host authenticating to many destinations within minutes (fan-out), or a chain A→B→C→D of first-time edges (RDP or SSH hopping).
- Workstation-to-workstation SMB, RDP, WinRM, or SSH connections.
- 4624 logon type 3 with `NTLM` in a Kerberos-preferred environment; logon type 9 with logon process `seclogo` (pass-the-hash via `runas /netonly` or Mimikatz).
- 4648 explicit-credential logons from a user context that should not hold the target credentials.
- 5140/5145 access to `ADMIN$`, `C$`, or `IPC$`, particularly writes of executables or scripts (lateral tool transfer).
- 7045 service installs with random-looking names, `%SystemRoot%` or `Temp` image paths, or names matching PsExec-like tooling (`PSEXESVC`, `csexecsvc`, one-off GUIDs).
- `WmiPrvSE.exe`, `wsmprovhost.exe`, or `mmc.exe` spawning `cmd.exe`/`powershell.exe` on the destination host.
- SSH logins between Linux hosts using accounts or key fingerprints never seen on that edge before; the same file hash appearing on multiple hosts within minutes (lateral tool transfer over SMB or SCP).

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Lateral Movement - First-Time Edge Fan-Out with Remote Execution",
  "description": "Detects a source host creating multiple first-time authentication edges to internal hosts within a window, escalating when remote-execution or credential-abuse artifacts follow on the destinations.",
  "data_source": ["Windows.Security", "Windows.System", "Sysmon.Operational", "Zeek.smb_files", "Linux.AuthLog"],
  "logic": {
    "window": "60m",
    "group_by": ["src_host"],
    "where": {
      "event_id_in": [4624, 4648, 5140, 5145],
      "logon_type_in": [3, 9, 10],
      "dst_host_is_internal": true,
      "edge_seen_in_baseline": false
    },
    "having": {
      "distinct_dst_hosts_gte": 3,
      "distinct_first_time_edges_gte": 3
    },
    "escalate_if_any": [
      "dst.event_7045_within_5m == true",
      "src.role == 'workstation' and dst.role == 'workstation'",
      "share_name in ['ADMIN$','C$'] and file_written_executable == true",
      "logon_type == 9 and logon_process == 'seclogo'",
      "auth_package == 'NTLM' and account.is_privileged == true"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1021.001", "T1021.002", "T1021.006", "T1550.002", "T1570", "T1047", "T1569.002", "lateral_movement"]
}
```

---

### 6. Example Event Data

```
Windows Security / System (forwarded)
2025-06-18T02:41:07Z  4624  host=FS-01     logon_type=3  user=CORP\svc-backup  src_ip=10.20.31.42 (WKS-1042)  auth=NTLM
2025-06-18T02:41:09Z  5145  host=FS-01     share=\\*\ADMIN$  target=PSEXESVC.exe  access=WriteData  src_ip=10.20.31.42
2025-06-18T02:41:11Z  7045  host=FS-01     service=PSEXESVC  image=%SystemRoot%\PSEXESVC.exe  account=LocalSystem
2025-06-18T02:44:38Z  4648  host=WKS-1042  user=CORP\d.whitfield  target_user=CORP\adm-jharper  target_server=SQL-03
2025-06-18T02:44:52Z  4624  host=SQL-03    logon_type=3  user=CORP\adm-jharper  src_ip=10.20.31.42  auth=NTLM
2025-06-18T02:49:15Z  4624  host=WKS-0077  logon_type=10 user=CORP\adm-jharper  src_ip=10.20.31.42

Edge baseline (30d) for WKS-1042: {DC-02:kerberos, PRINT-01:smb}
New edges this window: FS-01, SQL-03, WKS-0077  →  3 first-time edges in 8 minutes
```

---

### 7. Investigation Steps

1. **Map the edges.** Pull all remote authentications from the source host over the last 24–72h. Build the src→dst list with account, logon type, auth package, and first-seen status per edge.
2. **Establish the pivot's own compromise.** The source host was reached somehow — walk back its inbound edges, recent alerts, phishing deliveries, and process history to find the preceding hop or initial access.
3. **Correlate execution on each destination.** For every touched host, check 5140/5145 share access, 7045 service installs, WMI/WinRM child processes, scheduled task creation, and new binaries written in the window.
4. **Classify the credential.** Determine which account moved and how it was obtained: NTLM where Kerberos is expected, logon type 9, or 4648 mismatches point to hash/ticket theft rather than an interactive user.
5. **Check for tool transfer.** Hash any files written to admin shares or dropped via SCP; sweep the fleet for the same hash and staging paths.
6. **Trace the chain forward.** For RDP/SSH chains, repeat the edge analysis from each destination — lateral movement investigations recurse until the frontier produces no new hosts.
7. **Assess blast radius toward tier 0.** Flag any edge terminating at domain controllers, backup infrastructure, hypervisors, or PKI — these change containment priority immediately.

---

### 8. False Positive Considerations

- IT administrators and helpdesk staff performing legitimate remote support (PsExec, WinRM, RDP) — often indistinguishable by tooling, distinguishable by account, source host, and change-ticket correlation.
- Vulnerability scanners and compliance tools authenticating to every host from a fixed scanner IP.
- SCCM/Intune, patching, and software-deployment infrastructure creating services and writing to admin shares at scale.
- Backup agents and monitoring platforms with scheduled fan-out authentication patterns.
- New employees, re-imaged machines, or infrastructure migrations generating bursts of legitimately new edges.

---

### 9. Tuning Guidance

- Whitelist by **triple**, not by host: suppress `(src_host, account, tool)` combinations for known admin infrastructure, never a bare source IP — an attacker on the SCCM server must still alert.
- Designate jump hosts / PAWs explicitly; lateral protocols originating anywhere else in the workstation VLAN should alert at a lower threshold (or threshold of 1 for workstation-to-workstation).
- Seed the edge baseline for at least 30 days before enforcing first-time-edge logic; re-seed after major migrations to avoid a novelty flood.
- Scale fan-out thresholds by role: 3 new edges from a workstation is suspect; a domain controller or scanner needs far higher bars.
- Treat logon type 9 with `seclogo` and 7045 events with non-standard image paths as near-zero-FP signals — route them to their own high-severity rules rather than diluting them in the aggregate.

---

### 10. Response Actions

**Immediate**

- Isolate the pivot (source) host; do not start with the destinations — the pivot holds the credentials and tooling.
- Disable or reset accounts observed moving laterally; for pass-the-hash/ticket, reset the password twice (or rotate the krbtgt account twice for golden-ticket suspicion) and revoke Kerberos tickets.
- Block the lateral protocol path at the internal firewall/EDR (SMB/WinRM/RDP from the affected segment) while triage proceeds.
- Preserve memory and disk from the pivot before remediation destroys credential artifacts.

**Short-term**

- Sweep every destination host for persistence: services, scheduled tasks, WMI subscriptions, new local accounts, `authorized_keys` changes.
- Remove transferred tooling fleet-wide by hash and path.
- Reset credentials for every account that logged on to any touched host during the intrusion window.
- Review DC and tier-0 logs for any edge from the involved hosts or accounts.

**Long-term**

- Enforce tiered administration: admin accounts usable only from PAWs, no workstation-to-workstation admin protocols.
- Deploy LAPS so local admin hashes are not reusable across hosts; disable NTLM where feasible.
- Enable SMB signing and restrict admin-share access; require WinRM/RDP through bastion hosts with MFA.
- Keep the authentication-edge baseline as a permanent hunting dataset, not just an alerting input.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- A first-time edge terminates at a domain controller, backup server, hypervisor, or PKI host.
- Remote execution artifacts (7045, WMI/WinRM child shells) confirm the edge was used to run code, not just authenticate.
- Pass-the-hash or pass-the-ticket indicators are present (logon type 9 / `seclogo`, NTLM for a privileged account, TGS-without-TGT).
- The movement chain spans three or more hosts, or fan-out exceeds five first-time edges from one source.
- Lateral tool transfer is confirmed (same executable staged on multiple hosts).

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Pivot (Source) Host:
Accounts Used:
  - Privileged?:
Destinations Touched (host / first-time? / execution?):
Lateral Technique(s) (SMB svc / WMI / WinRM / RDP / SSH / DCOM):
Credential Abuse Indicators (PtH / PtT / 4648):
Tools Transferred (hash / path):
Chain Depth / Fan-Out Count:
Tier-0 Exposure:
Preceding Hop / Initial Access:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Model authentication as a graph and alert on the geometry: first-time edges, fan-out from a single pivot, workstation-to-workstation protocol use, and logon-type anomalies (4624 type 3/9/10, 4648, 5140/5145, 7045). The tool varies — PsExec, WMI, WinRM, RDP, SSH, DCOM — but the graph behavior does not. On confirmation, isolate the pivot first, treat every touched host as compromised until swept, and recurse the edge analysis until the chain stops producing new hosts.

---

*GreyNOC — detection-engineering-first security operations.*
