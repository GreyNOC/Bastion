# GreyNOC Security Playbook

## Active Directory Credential Theft Detection & Response

---

### 1. Overview

Active Directory credential theft covers the family of on-host and directory-level attacks used to harvest or forge authentication material after initial access: Kerberoasting (offline cracking of service-account tickets), AS-REP roasting (accounts without Kerberos preauthentication), DCSync (abusing directory replication to pull password hashes remotely), LSASS memory dumping, NTDS.dit theft via volume shadow copy, and golden-ticket forgery with a stolen `krbtgt` hash.

These techniques are the pivot point of almost every domain compromise. They convert a single foothold into domain-wide credentials, and several of them (Kerberoasting, AS-REP roasting, DCSync) generate no malware artifacts at all — they are legitimate protocol operations issued by the wrong principal. Detection therefore lives in domain controller Kerberos telemetry (4768/4769), directory replication auditing (4662/DRSUAPI), and host process telemetry (Sysmon).

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| OS Credential Dumping: NTDS | T1003.003 | Credential Access |
| OS Credential Dumping: DCSync | T1003.006 | Credential Access |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Credential Access |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Credential Access |

---

### 3. Detection Strategy

Each sub-technique has a distinct telemetry seam; the common thread is a legitimate operation performed by an implausible principal, at implausible volume, or with downgraded cryptography.

- Kerberoasting. Watch Event 4769 on DCs for a single account requesting TGS tickets for many distinct SPN-bearing accounts in a short window, especially with RC4 (`TicketEncryptionType 0x17`) requested in an AES-capable domain. Tooling (Rubeus, Impacket `GetUserSPNs`) enumerates fast; the fan-out is the signal.
- AS-REP roasting. Event 4768 with `PreAuthType 0` for accounts flagged `DONT_REQ_PREAUTH`. Inventory these accounts — any TGT request for them from a non-baseline source is suspect.
- DCSync. DRSUAPI `DsGetNCChanges` replication requests (Event 4662 with replication GUIDs `1131f6aa`/`1131f6ad`) from any principal that is not a domain controller computer account or known AAD Connect/replication service account.
- LSASS access. Sysmon Event 10 with `TargetImage` lsass.exe and read-memory access masks (`0x1010`, `0x1410`, `0x1fffff`) from non-allowlisted source images; rundll32 loading `comsvcs.dll` with `MiniDump`; procdump/rdrleakdiag/Mimikatz command lines.
- NTDS.dit theft. `vssadmin create shadow`, `ntdsutil "ifm"`, `esentutl /y` touching `ntds.dit`, or diskshadow scripts on domain controllers.
- Golden ticket. TGS activity for accounts with no corresponding 4768 TGT issuance, tickets with anomalous lifetimes (e.g., 10 years vs. domain policy), or RC4-encrypted tickets for privileged accounts in an AES-only domain.

---

### 4. Key Indicators

- One source account/host generating 4769 events for ≥ 10 distinct SPN-bearing service accounts within minutes.
- `TicketEncryptionType 0x17` (RC4) requested where AES is the domain norm — classic downgrade for offline cracking.
- 4768 with `PreAuthType 0` for a `DONT_REQ_PREAUTH` account from a workstation that has never authenticated as it.
- 4662 with DS-Replication-Get-Changes / Get-Changes-All GUIDs from a user account or member server IP.
- Sysmon EID 10 on lsass.exe from Office apps, browsers, script hosts, or unsigned binaries; `comsvcs.dll, MiniDump` in a rundll32 command line.
- Shadow-copy or `ntdsutil` activity on a DC outside backup windows.
- Kerberos tickets whose lifetime exceeds domain policy, or TGS-without-TGT sequences for privileged accounts.
- Honeytoken SPN or preauth-disabled decoy account receiving any ticket request.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "AD Credential Theft - Kerberoast SPN Fan-Out",
  "description": "Detects a single principal requesting service tickets for many distinct SPN-bearing accounts in a short window, with escalators for encryption downgrade, AS-REP roasting, and DCSync from non-DC principals.",
  "data_source": ["Windows.Security.4769", "Windows.Security.4768", "Windows.Security.4662", "Sysmon.EID10"],
  "logic": {
    "window": "10m",
    "group_by": ["requesting_account", "src_ip"],
    "where": {
      "event_id": 4769,
      "service_name_not_in": ["krbtgt"],
      "service_name_not_like": "*$",
      "ticket_options_valid": true
    },
    "having": {
      "distinct_service_accounts_gte": 10,
      "failure_code": "0x0"
    },
    "escalate_if_any": [
      "ticket_encryption_type == '0x17' and domain_aes_enabled == true",
      "service_name in honeytoken_spn_list",
      "same_src has event_id 4768 with preauth_type == 0 in window",
      "same_src has event_id 4662 with properties contains '1131f6aa' and src_host not in domain_controllers"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1558.003", "T1558.004", "T1003.006", "credential_access", "active_directory"]
}
```

---

### 6. Example Event Data

```
Event 4769 (DC-01, corp.com)
2025-06-19T02:41:07Z  ServiceName: svc-sql01     Account: CORP\j.chen  ClientAddress: 10.20.14.42  TicketEncryptionType: 0x17
2025-06-19T02:41:08Z  ServiceName: svc-backup    Account: CORP\j.chen  ClientAddress: 10.20.14.42  TicketEncryptionType: 0x17
2025-06-19T02:41:08Z  ServiceName: svc-sharepoint Account: CORP\j.chen ClientAddress: 10.20.14.42  TicketEncryptionType: 0x17
2025-06-19T02:41:09Z  ServiceName: svc-iis-app   Account: CORP\j.chen  ClientAddress: 10.20.14.42  TicketEncryptionType: 0x17
   ... 14 more distinct SPNs in 40 seconds ...

Sysmon EID 10 (WKS-1042, 10.20.14.42)
2025-06-19T02:52:31Z  SourceImage: C:\Users\jchen\AppData\Local\Temp\up.exe  (unsigned)
                      TargetImage: C:\Windows\System32\lsass.exe
                      GrantedAccess: 0x1010   CallTrace: ...dbghelp.dll...
```

---

### 7. Investigation Steps

1. **Confirm the fan-out.** Pull all 4769s for the requesting account/source over 24h. Count distinct SPNs, check encryption types, and compare against the account's normal service-ticket profile.
2. **Classify the requester.** Is the account a user, service account, or machine account? Does the source host belong to that user? An interactive user enumerating 15 SPNs is not organic behavior.
3. **Check for companion techniques.** From the same source, search for 4768 `PreAuthType 0` events, 4662 replication GUIDs, Sysmon EID 10 against lsass, and shadow-copy commands. Credential theft techniques cluster.
4. **Profile the source host.** EDR/Sysmon process telemetry around the event window: Rubeus/Impacket artifacts, PowerShell with `KerberosRequestorSecurityToken`, unsigned binaries, new scheduled tasks.
5. **Assess the targeted accounts.** Which SPN accounts were requested, what privileges do they hold, and how strong are their passwords (age, length, cracking feasibility)?
6. **Hunt for forged tickets.** For any privileged account touched, look for TGS use without matching TGT issuance, anomalous ticket lifetimes, or RC4 tickets post-incident — indicators the theft already succeeded.
7. **Establish the foothold.** Walk back to initial access on the source host; credential theft is mid-kill-chain, never the start.

---

### 8. False Positive Considerations

- Vulnerability scanners and AD assessment tools (PingCastle, BloodHound run by internal teams, Nessus credentialed scans) legitimately enumerate SPNs and request tickets.
- Legacy applications and appliances hard-coded to RC4, generating persistent 0x17 tickets.
- AAD Connect, Riverbed, and backup/DR replication accounts performing legitimate DsGetNCChanges.
- AV/EDR, backup agents, and crash-dump tooling (WerFault, procexp) opening lsass handles.
- Scheduled DC backups using VSS or `ntdsutil ifm` during maintenance windows.

---

### 9. Tuning Guidance

- Inventory and allowlist legitimate replication principals by account SID **and** source IP; alert on any DsGetNCChanges outside that tuple rather than suppressing broadly.
- Baseline per-account service-ticket diversity; thresholds of 10 distinct SPNs/10m work for user accounts but must be raised for middleware service accounts.
- Migrate service accounts to AES and set RC4 requests to high severity once the domain baseline is clean — the downgrade signal is nearly free fidelity.
- Deploy honeytoken accounts: one SPN-bearing account and one preauth-disabled account with no legitimate use. Any 4769/4768 touching them is escalation-grade.
- For lsass access, allowlist by signed image path + access mask, not process name; attackers routinely rename tools to `procexp64.exe`.
- Suppress known backup-window VSS activity on DCs by schedule and initiating account, not by host alone.

---

### 10. Response Actions

**Immediate**

- Isolate the source host and disable (do not just reset) the requesting account pending investigation.
- Reset passwords for all SPN-bearing accounts whose tickets were requested; treat them as compromised if passwords are weak or old.
- If DCSync or NTDS theft is confirmed, treat every domain credential as compromised and invoke domain-compromise procedures.
- Capture memory and disk from the source host before remediation.

**Short-term**

- Rotate the `krbtgt` account password **twice** (with replication settling between resets) if golden-ticket forgery or krbtgt hash exposure is suspected.
- Reset privileged and Tier 0 account credentials; revoke active Kerberos tickets and cached sessions.
- Sweep the fleet for the tooling and technique indicators (comsvcs MiniDump, procdump against lsass, Rubeus artifacts, replication requests from non-DCs).
- Review ACLs granting replication rights (DS-Replication-Get-Changes-All) and strip any non-essential grants.

**Long-term**

- Enforce long random passwords (25+ chars) or gMSAs for all SPN-bearing service accounts.
- Eliminate `DONT_REQ_PREAUTH` flags; require justification and compensating monitoring for any that remain.
- Enable Credential Guard and LSASS RunAsPPL across the estate.
- Enforce AES-only Kerberos where legacy systems allow; monitor the exceptions.
- Implement tiered administration so workstation compromise cannot reach Tier 0 credentials.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- DsGetNCChanges replication is confirmed from any non-DC, non-allowlisted principal (assume full directory hash compromise).
- LSASS memory access or dump artifacts are confirmed on a domain controller or Tier 0 asset.
- A honeytoken SPN or preauth-disabled decoy account receives any ticket request.
- Kerberoast fan-out includes privileged service accounts (SQL sysadmin, backup, SCCM, Exchange) with crackable password characteristics.
- Golden-ticket indicators are present: TGS-without-TGT, anomalous ticket lifetime, or RC4 downgrade for privileged accounts.
- NTDS.dit staging or exfiltration (VSS copy, `ntdsutil ifm`) is observed outside sanctioned backup activity.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Requesting Account / Source Host:
Technique(s) Observed (Kerberoast / AS-REP / DCSync / LSASS / NTDS / Golden Ticket):
Distinct SPNs Requested:
Encryption Types Observed:
Replication Requests From Non-DC (yes/no):
LSASS Access Source Image / GrantedAccess:
Privileged Accounts Exposed:
krbtgt Rotation Required (yes/no):
Foothold / Initial Access:
Fleet Sweep Findings:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

The detection surface is a legitimate protocol used by the wrong principal: service-ticket fan-out with RC4 downgrade, TGT requests for preauth-disabled accounts, replication from non-DCs, and lsass handles from unsigned binaries. Honeytokens and encryption-downgrade signals provide near-zero-FP escalators on top of volumetric rules. Scope aggressively on confirmation — DCSync or NTDS theft means the entire directory is compromised, and the response is krbtgt rotation and domain-wide credential reset, not single-account cleanup.

---

*GreyNOC — detection-engineering-first security operations.*
