# GreyNOC Security Playbook

## Ransomware Detection & Response

---

### 1. Overview

Ransomware is the impact stage of an intrusion, not its beginning. By the time files are being encrypted, the adversary has already gained access, moved laterally, and — in most modern campaigns — staged and stolen data for double extortion. Encryption is the last, loudest, and least recoverable event in the chain.

The detection priority is therefore inverted from intuition: **precursors are worth far more than the encryption itself.** Recovery-inhibition commands (shadow-copy deletion, backup-catalog destruction, boot-recovery tampering), mass service stops that free locked files, and defensive-tool tampering all fire *seconds to minutes before* bulk encryption begins. Detecting and containing at the precursor stage can save the estate; detecting at the encryption stage usually means measuring the blast radius.

> **Notation:** high-signal destructive commands in this playbook are written with an inserted `·` break inside key tokens (for example, `de·lete`) so the file itself is inert text and does not trip endpoint AV content signatures. Strip the `·` to recover the literal command.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Data Encrypted for Impact | T1486 | Impact |
| Inhibit System Recovery | T1490 | Impact |
| Service Stop | T1489 | Impact |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| File and Directory Discovery | T1083 | Discovery |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement |

---

### 3. Detection Strategy

The reliable signal is a short, dense burst of preparatory actions on a single host — often scripted, often running as SYSTEM or a freshly-compromised admin — immediately preceding a file-modification storm.

- Recovery inhibition. Shadow-copy deletion (`vssadmin`, `wmic shadow·copy`, `Get-WmiObject Win32_Shadow·copy`), backup-catalog destruction (`wbadmin`), and boot-recovery tampering (`bcdedit`) are near-universal precursors. Any one is high-signal; several in sequence is near-certain.
- Service-stop bursts. Ransomware stops databases, mail servers, and backup agents to unlock their files before encrypting. A single process stopping many services (SQL, Exchange, Veeam, backup, AV) in seconds is anomalous.
- Defensive-tool tampering. Attempts to disable EDR/AV, clear real-time protection, or stop security services immediately before impact.
- Mass file modification. High-rate writes/renames across many directories, a Shannon-entropy spike in file contents (plaintext → ciphertext), and a new uniform extension appearing across the tree.
- Ransom-note fan-out. Identically-named files (e.g., `README`, `HOW_TO_RECOVER`, `!restore!`) written into many directories in a short window.
- SMB write storms. Encryption reaching file shares appears as one host writing/renaming across many remote paths on `FS-01` — visible in `5145` share-access auditing without endpoint telemetry.
- Canary tripwires. Decoy files seeded in shares; any modification of a canary is a zero-baseline alert.

---

### 4. Key Indicators

- Shadow-copy deletion or resize commands (`vssadmin de·lete shadows`, `wmic shadow·copy de·lete`).
- Backup-catalog destruction (`wbadmin de·lete catalog`) or boot-recovery disable (`bcdedit /set {default} recovery·enabled no`, `bootstatuspolicy ignoreallfailures`).
- One process stopping ≥ N services in a short window, especially DB / backup / mail / AV service names.
- EDR/AV service stop, tamper-protection toggle, or exclusion-path addition immediately before file activity.
- File-modification rate on a host far above its baseline, with rising content entropy.
- A new, previously-unseen file extension appearing across many directories.
- Identical ransom-note filenames created across many folders.
- A single source host renaming/writing files across many SMB shares (`5140`/`5145` fan-out).
- Discovery bursts (`5145` share enumeration, recursive directory listing) minutes before the storm.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Ransomware - Recovery Inhibition Precursor Burst",
  "description": "Detects recovery-inhibition and service-stop activity on a single host consistent with pre-encryption staging. Command substrings are defanged with a middle-dot break; strip the break when implementing.",
  "data_source": ["EDR.ProcessEvents", "Sysmon.EID1", "WindowsEvent.Security", "WindowsEvent.System"],
  "logic": {
    "window": "5m",
    "group_by": ["host", "user"],
    "where": {
      "event_type": "process_create",
      "commandline_contains_any": [
        "de·lete shadows",
        "shadow·copy de·lete",
        "resize shadowstorage",
        "de·lete catalog",
        "recovery·enabled no",
        "bootstatuspolicy ignoreallfailures",
        "Win32_Shadow·copy"
      ]
    },
    "having": {
      "distinct_precursor_techniques_gte": 1
    },
    "escalate_if_any": [
      "service_stop_count_5m >= 5 and service_names_match('sql|exchange|veeam|backup|defender|sophos|sentinel')",
      "edr_tamper_event == true or av_realtime_protection_disabled == true",
      "file_modify_rate_per_min > host_baseline_p99 and content_entropy_rising == true",
      "distinct_new_extension_across_dirs_gte 50",
      "identical_note_filename_across_dirs_gte 10"
    ]
  },
  "severity": "critical",
  "tags": ["T1490", "T1489", "T1562.001", "T1486", "impact", "ransomware"]
}
```

---

### 6. Example Event Data

```
EDR ProcessEvents  —  host: FS-01 (10.20.8.11)  user: CORP\svc-backup (SYSTEM context)
2025-08-19T02:41:07Z  parent: rundll32.exe  ->  cmd.exe /c "vssadmin.exe de·lete shadows /all /quiet"
2025-08-19T02:41:08Z  parent: cmd.exe       ->  wmic.exe shadow·copy de·lete
2025-08-19T02:41:09Z  parent: cmd.exe       ->  wbadmin.exe de·lete catalog -quiet
2025-08-19T02:41:10Z  parent: cmd.exe       ->  bcdedit.exe /set {default} recovery·enabled no
2025-08-19T02:41:12Z  net.exe stop "MSSQLSERVER" /y
2025-08-19T02:41:12Z  net.exe stop "Veeam Backup Service" /y
2025-08-19T02:41:13Z  net.exe stop "Sophos Endpoint Defense Service" /y   (access denied - tamper protection)

Windows Security 5145  —  FS-01 share write fan-out
2025-08-19T02:41:40Z  src: WKS-1042 (10.20.14.42)  share: \\FS-01\Finance   rel: Q3\*.xlsx.locked   access: WriteData
2025-08-19T02:41:41Z  src: WKS-1042 (10.20.14.42)  share: \\FS-01\Finance   file: HOW_TO_RECOVER.txt  access: WriteData
2025-08-19T02:41:41Z  src: WKS-1042 (10.20.14.42)  share: \\FS-01\HR        file: HOW_TO_RECOVER.txt  access: WriteData
```

---

### 7. Investigation Steps

1. **Freeze the precursor window.** Pull all process-create events for the host/user in the ±10 minutes around the first recovery-inhibition command. This is the scripted core of the attack.
2. **Identify the launching process and its parent.** Ransomware is frequently launched via `rundll32`, `mshta`, PsExec-style service, a scheduled task, or a signed-binary proxy. Walk the lineage back toward the pivot.
3. **Determine the account and its context.** SYSTEM, a domain admin, or a service account? A compromised privileged account changes containment scope immediately.
4. **Map file impact.** Which paths, which shares, how many files, which new extension. Distinguish local-only encryption from SMB fan-out reaching `FS-01` and other shares.
5. **Confirm or rule out prior exfiltration.** Modern ransomware steals before it encrypts. Check egress volume, archive creation, and cloud/FTP uploads in the preceding hours/days (see the Data Exfiltration playbook).
6. **Trace lateral movement.** Correlate with remote service creation, WMI/WinRM execution, and admin-share access to find every host the actor touched — encryption almost always spans more than the first host.
7. **Recover the entry point.** Walk the chain back to initial access (phishing, exposed RDP/VPN, exploited public app) to scope the intrusion and close the door.

---

### 8. False Positive Considerations

- Legitimate backup software managing or pruning shadow copies and catalogs on a schedule.
- Administrators running `bcdedit` during genuine recovery, imaging, or boot-repair work.
- Storage/maintenance jobs stopping database or backup services for planned maintenance windows.
- Software deployment or migration tools performing bulk file writes/renames.
- Disk-encryption rollout (e.g., BitLocker enablement) producing large-scale file changes — verify it is the sanctioned tool, on schedule, by the expected account.

---

### 9. Tuning Guidance

- Treat recovery-inhibition commands as **allowlist-only**: enumerate the exact backup/maintenance processes and accounts permitted to run them, and alert on everything else rather than suppressing the technique broadly.
- Require **process context** for service-stop rules — the same `net stop` is benign from an admin console and critical from `rundll32` running as a freshly-elevated account.
- Baseline **per-host file-modification rate** and alert on p99 deviation plus rising entropy; static thresholds misfire on file servers.
- Seed **canary files** in high-value shares; a canary modification needs no threshold and no tuning.
- Keep precursor detectors at the **base layer** and combine them at the correlation layer — do not suppress a base detector to reduce noise, or you go blind to the next intrusion.

---

### 10. Response Actions

**Immediate**

- Isolate the encrypting host(s) from the network — contain, do not power off; preserve memory and volatile keys where feasible.
- Block the responsible account: disable, reset, and revoke sessions/tokens.
- Sever access to file shares (`FS-01`) from the source host to halt SMB fan-out.
- Preserve evidence: memory, the launching binary, ransom note, and a sample encrypted file.

**Short-term**

- Sweep the fleet for the same binary hash, launching process, and precursor command pattern — assume more than one host is affected.
- Identify and disable the delivery/persistence mechanism (scheduled task, service, GPO, PsExec source).
- Assess whether backups and shadow copies survived; validate restore integrity before relying on them.
- Confirm scope of prior data exfiltration to inform breach-notification and extortion posture.

**Long-term**

- Enforce offline / immutable backups and test restores regularly; segment backup infrastructure credentials from production admin.
- Restrict and monitor recovery-inhibition tooling; deploy tamper-protected EDR with rollback where available.
- Segment the network to limit SMB lateral reach; enforce SMB signing and constrain admin-share access.
- Close the initial-access vector class (phishing-resistant MFA, RDP/VPN exposure reduction, patch cadence for public-facing apps).

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Any recovery-inhibition command runs outside the sanctioned backup process/account.
- A single process stops multiple database, backup, or security services in a short window.
- EDR/AV tamper or real-time-protection disable is observed on a production host.
- A file-modification storm with rising entropy or a new uniform extension is detected.
- Ransom notes appear across multiple directories, or a canary file is modified.
- Encryption or precursor activity is observed on more than one host, or reaches a file server / domain controller.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Affected Host(s):
Account / Context (SYSTEM / admin / service):
Launching Process / Parent / Lineage:
Precursor Commands Observed (recovery inhibition / service stop / tamper):
File Impact (paths / share fan-out / new extension / count):
Ransom Note Filename / Family (suspected):
Prior Exfiltration Confirmed (yes/no):
Lateral Movement / Other Affected Hosts:
Initial Access Vector:
Backup / Shadow Copy Status:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Detect early or measure the damage. The recoverable window is the burst of precursors — shadow-copy deletion, backup-catalog destruction, boot-recovery tampering, mass service stops, and defensive-tool tampering — that fires seconds before encryption. Alert on those as high-signal events with process context, seed canaries in valuable shares, and assume any confirmed encryption spans multiple hosts and was preceded by data theft. By the time the extension changes across the tree, the decision has moved from prevention to recovery.

---

*GreyNOC — detection-engineering-first security operations.*
