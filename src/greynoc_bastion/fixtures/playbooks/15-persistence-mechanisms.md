# GreyNOC Security Playbook

## Persistence Mechanism Detection & Response

---

### 1. Overview

Persistence is how an attacker survives reboots, credential rotation, and half-finished remediation. After initial access, nearly every intrusion plants at least one foothold: a scheduled task, a Windows service, a registry run key or startup-folder binary, a WMI event subscription, a rogue account, or on Linux a cron entry, systemd unit, or injected SSH key. Miss the persistence and you re-image the beacon host only to watch the attacker walk back in.

The detection problem is volume, not visibility. Task creation (4698), service installation (7045), run-key writes, and account creation (4720) fire constantly in any managed environment — installers, GPO, patch agents, and config management generate them all day. The signal is not the event class; it is novelty within it: a binary path never seen in the fleet, an unsigned image, an odd parent process, a creation at 02:47 local. Baseline first, then alert on deviation.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence / Privilege Escalation |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Persistence / Privilege Escalation |
| Create or Modify System Process: Windows Service | T1543.003 | Persistence / Privilege Escalation |
| Event Triggered Execution: Windows Management Instrumentation Event Subscription | T1546.003 | Persistence / Privilege Escalation |
| Create Account: Local Account | T1136.001 | Persistence |
| Create Account: Domain Account | T1136.002 | Persistence |
| Account Manipulation | T1098 | Persistence / Privilege Escalation |
| Scheduled Task/Job: Cron | T1053.003 | Persistence / Privilege Escalation |

---

### 3. Detection Strategy

Treat persistence telemetry as an inventory problem: enumerate every autostart artifact, baseline what is normal per host and fleet-wide, and score new artifacts on novelty rather than alerting on raw event volume.

- Collect the full artifact surface: Security 4698 (task created) and `schtasks` command lines, System 7045 (service installed), Sysmon 12/13 for run-key writes and 11 for startup-folder file creates, Sysmon 19/20/21 for WMI EventFilter / CommandLineEventConsumer / FilterToConsumerBinding, Security 4720 (account created) and 4732/4728 (added to local/global privileged group), and Linux auditd/osquery for crontab writes, new systemd unit files, and `authorized_keys` modification.
- Score novelty, not existence. First-seen binary path in the fleet, unsigned or untrusted-signer image, execution from user-writable paths (`AppData`, `Temp`, `ProgramData`, `C:\Users\Public`, `/tmp`, `/dev/shm`), and creation outside the host's business hours are each independent escalators.
- Weight parent-process context heavily. A scheduled task registered by SCCM is noise; the same task registered by `winword.exe`, `mshta.exe`, or an unsigned binary in `Temp` is a finding.
- Alert on WMI subscription persistence unconditionally. Legitimate FilterToConsumerBinding creation is rare enough in most fleets that baseline exceptions can be enumerated by hand.
- Chain artifacts in time. Account creation followed within minutes by privileged group addition, or a service install minutes after a task creation on the same host, is a stronger signal than either alone.

---

### 4. Key Indicators

- Scheduled task or service whose image path has never been seen on any other host in the fleet.
- Unsigned service binary, or signer not in the org's trusted-publisher set (7045 with `ImagePath` outside `Program Files`/`System32`).
- Task or service command line invoking `powershell -enc`, `mshta`, `rundll32`, `regsvr32`, `wscript`, or a LOLBin with a remote payload.
- Run-key or startup-folder write pointing at a user-writable path, especially by a non-installer parent process.
- Sysmon 19/20/21 activity: any new EventFilter, CommandLineEventConsumer, or FilterToConsumerBinding not attributable to management software.
- 4720 followed by 4732/4728 into Administrators, Remote Desktop Users, or Domain Admins within a short window; account names mimicking service conventions (`svc_backup2`, `adm_helpdesk`).
- Task/service/account creation during off-hours for that host's baseline, or by an interactive session on a server that rarely sees one.
- Linux: crontab entries fetching over HTTP, systemd units in `/etc/systemd/system` with `ExecStart` in `/tmp` or `/dev/shm`, `authorized_keys` written by a web-server or database uid.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Persistence - Novel Autostart Artifact",
  "description": "Detects creation of a persistence artifact (task, service, run key, startup file, WMI subscription, account, cron/systemd/ssh-key) that is new to the fleet baseline, escalating on unsigned images, suspicious paths, odd parents, and off-hours creation.",
  "data_source": ["WinEventLog.Security", "WinEventLog.System", "Sysmon.Operational", "Linux.Auditd", "Osquery.Autoruns"],
  "logic": {
    "window": "24h",
    "group_by": ["host", "artifact_type", "artifact_key"],
    "where": {
      "event_id_in": [4698, 7045, 4720, 4732, 4728, 11, 12, 13, 19, 20, 21],
      "artifact_type_in": ["scheduled_task", "service", "run_key", "startup_folder", "wmi_subscription", "account_create", "group_add", "cron", "systemd_unit", "ssh_authorized_keys"]
    },
    "having": {
      "artifact_in_fleet_baseline": false,
      "creator_in_deployment_allowlist": false
    },
    "escalate_if_any": [
      "image.signed == false or image.signer not in org_trusted_publishers",
      "image.path in user_writable_paths",
      "parent_process in ['winword.exe', 'excel.exe', 'outlook.exe', 'mshta.exe', 'wscript.exe', 'rundll32.exe', 'powershell.exe']",
      "creation_time outside host.baseline_active_hours",
      "artifact_type == 'wmi_subscription'",
      "artifact_type == 'group_add' and group in privileged_groups and account_age_minutes < 60"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1053.005", "T1547.001", "T1543.003", "T1546.003", "T1136.001", "T1136.002", "T1098", "T1053.003", "persistence"]
}
```

---

### 6. Example Event Data

```
Security EID 4698 (scheduled task created)
Host: WKS-1042 (10.20.14.42)   2025-06-18T02:47:11Z
SubjectUser: CORP\j.doyle
TaskName: \Microsoft\Windows\AppSync\SyncCheck
Action: C:\Users\j.doyle\AppData\Roaming\syncsvc\upd.exe   (unsigned, first seen fleet-wide)
Triggers: ONLOGON + daily 02:45     Parent of schtasks.exe: winword.exe

System EID 7045 (service installed)
Host: SRV-APP-03 (10.20.8.31)   2025-06-18T02:52:40Z
ServiceName: WinTelemetryHost     StartType: auto     Account: LocalSystem
ImagePath: C:\ProgramData\wth\wth.exe -k netsvc   (unsigned)

Sysmon EID 20 (WMI consumer registered)
Host: WKS-1042   2025-06-18T02:55:03Z
Consumer: CommandLineEventConsumer "Updater"
CommandLineTemplate: powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBP...

auditd (SSH key injection)
Host: srv-web-01 (10.20.30.15)   2025-06-18T03:01:22Z
uid=www-data  syscall=openat write  path=/home/deploy/.ssh/authorized_keys
```

---

### 7. Investigation Steps

1. **Validate novelty.** Confirm the artifact (task name, service image path, run-key value, WMI binding, account) is genuinely first-seen against the fleet baseline and not a stale baseline gap.
2. **Attribute the creator.** Pull the full process tree behind the creation event: parent chain, user context, logon session type. Deployment tooling is a dead end; Office apps, LOLBins, and interactive off-hours sessions are not.
3. **Analyze the payload.** Hash and signature-check the image, decode any encoded command lines, detonate or statically review unknown binaries, and check the path against user-writable locations.
4. **Enumerate all persistence on the host.** Attackers rarely plant one mechanism. Run a full autoruns/osquery sweep — tasks, services, run keys, WMI, cron, systemd, `authorized_keys` — before any cleanup.
5. **Walk the timeline backward.** Find the execution that created the artifact and trace to initial access: phishing attachment, exploited service, stolen credential. The persistence event is mid-chain, never the start.
6. **Check for account-based fallbacks.** Review 4720/4732/4728 and group memberships on the host and domain for accounts created or modified in the surrounding window.
7. **Sweep the fleet.** Search all hosts for the same task name, image hash, service name, WMI consumer, account naming pattern, or SSH public key. Persistence findings almost always generalize.

---

### 8. False Positive Considerations

- Software installers and updaters legitimately create services, tasks, and run keys — often unsigned helper binaries in `ProgramData`.
- GPO, SCCM/Intune, and RMM tooling generating 4698/7045 in bulk during deployment windows.
- Config management (Ansible, Puppet, Chef, Salt) writing cron entries, systemd units, and `authorized_keys` as designed.
- IT provisioning creating accounts and adding them to groups (4720 + 4732) during onboarding.
- Developers and admins registering tasks or units on their own machines for legitimate automation.
- A handful of enterprise products (SCCM, some AV) use WMI subscriptions legitimately — enumerate them explicitly rather than dismissing the class.

---

### 9. Tuning Guidance

- Build the baseline before enabling alerting: 30 days of autostart-artifact inventory per host and fleet-wide, keyed on artifact name + image hash + path.
- Allowlist by tuple, not by field: creator process **and** signer **and** path together. A rule that suppresses everything signed, or everything from `ProgramData`, will suppress the attacker too.
- Scope deployment-tool suppression to the tool's service account and known execution windows; alert separately if those accounts create artifacts outside them.
- Keep WMI subscription (Sysmon 19/20/21) thresholds at or near zero — enumerate the few legitimate bindings by hand and alert on everything else.
- For account events, tune on velocity: creation-to-privileged-group time under an hour deserves a lower threshold than group changes on aged accounts.
- On Linux, baseline per-host cron and unit-file inventories with osquery diffs; alert on delta, not on content matching alone.

---

### 10. Response Actions

**Immediate**

- Isolate the affected host if the payload is unsigned/unknown or C2 activity is suspected.
- Disable (do not yet delete) the persistence artifact: stop the service, disable the task, remove the WMI binding, comment the cron entry — preserving artifacts for forensics.
- Disable rogue accounts and revoke their sessions; remove unauthorized privileged group memberships.
- Capture triage artifacts: autoruns output, the binary and its hash, relevant registry hives, WMI repository, crontabs, unit files, `authorized_keys`.

**Short-term**

- Remove all discovered persistence mechanisms on the host — after the full enumeration in step 4, not before.
- Reset credentials for the creating account and any account that logged on to the host since the foothold.
- Sweep the fleet for every indicator (task name, image hash, service name, WMI consumer, SSH key) and remediate matches.
- Re-image the host if the payload ran as SYSTEM/root or the timeline cannot be fully reconstructed.

**Long-term**

- Deploy continuous autostart inventory (osquery/autoruns pipelines) with fleet-wide first-seen diffing.
- Enforce application control / WDAC so unsigned binaries in user-writable paths cannot execute as services or tasks.
- Restrict local account creation and privileged group changes to PAM-brokered workflows; alert on any out-of-band change.
- Ensure Sysmon 19/20/21 and auditd rules for cron/systemd/`authorized_keys` are deployed fleet-wide, not just on servers.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- The persistence payload is unsigned, packed, or unknown to reputation sources, and executes from a user-writable path.
- Any WMI event subscription persistence is confirmed as non-attributable to management software.
- A newly created account is added to a privileged group (Administrators, Domain Admins, sudoers) within the same window.
- The same artifact (name, hash, key, consumer) appears on more than one host.
- Persistence creation correlates with prior alerts on the host (beaconing, credential access, lateral movement).
- The artifact was created on a domain controller, identity infrastructure, or bastion host.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Host / IP:
Artifact Type (task/service/run key/WMI/account/cron/systemd/ssh):
Artifact Name / Key / Path:
Image Path / Hash / Signed?:
Creating Process / Parent Chain:
Creating Account / Session Type:
Creation Time vs Host Baseline Hours:
Fleet First-Seen? (yes/no):
Other Persistence Found on Host:
Related Accounts / Group Changes:
Initial Access (suspected):
Fleet Sweep Findings:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Persistence events are too common to alert on raw; the detection is a baseline diff. Inventory every autostart surface — tasks, services, run keys, startup folders, WMI subscriptions, accounts, cron, systemd, SSH keys — and alert on fleet-level novelty, escalated by unsigned images, user-writable paths, suspicious parents, and off-hours creation. On confirmation, enumerate everything on the host before removing anything, then sweep the fleet: attackers plant more than one foothold, and the same artifact almost always exists elsewhere.

---

*GreyNOC — detection-engineering-first security operations.*
