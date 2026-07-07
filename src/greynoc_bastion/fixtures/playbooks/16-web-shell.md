# GreyNOC Security Playbook

## Web Shell Detection & Response

---

### 1. Overview

A web shell is a script implant (ASPX, JSP, PHP, ASHX, WAR) dropped into the webroot of a public-facing application after exploitation — typically via an unauthenticated RCE, an unrestricted file upload, or a deserialization bug. Once in place, the attacker issues commands through ordinary HTTP requests to the implant, inheriting the identity and network position of the web server itself. Common families include China Chopper (tiny eval one-liners driven by clients like AntSword/Caidao), Godzilla and Behinder (encrypted, memory-resident, AV-evasive), and bespoke one-line droppers left behind by exploit kits.

Web shells are prized because they survive reboots, blend into legitimate HTTPS traffic, and require no outbound C2 channel — the attacker connects *in*. Detection has two complementary angles: process lineage on the server (web worker processes should almost never spawn shells) and traffic shape at the edge (POSTs to scripts nobody else requests).

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Server Software Component: Web Shell | T1505.003 | Persistence |
| Exploit Public-Facing Application | T1190 | Initial Access |
| Ingress Tool Transfer | T1105 | Command and Control |
| Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |

---

### 3. Detection Strategy

The implant is small and polymorphic; the behaviors around it are not. Detect the lineage and the traffic, not the file content.

- Process lineage (EDR/Sysmon). Web-server worker processes — `w3wp.exe`, `httpd`, `nginx` workers, `php-fpm`, `tomcat`/`java` — spawning `cmd.exe`, `powershell.exe`, `sh`, `bash`, or recon/transfer LOLBins (`whoami`, `net`, `ipconfig`, `systeminfo`, `certutil`, `curl`, `wget`) is the single highest-fidelity signal in this category.
- File integrity (FIM). New or modified executable script files in webroots and upload directories, especially written by the web worker process itself rather than by a deployment pipeline or package manager.
- Traffic shape (WAF/web logs). POST requests to URIs with little or no request history, requests to scripts in upload/static directories that should never execute, no-referrer requests, and client user-agents tied to shell managers (AntSword, Caidao, Godzilla defaults).
- Response anomalies. A "static" path suddenly returning 200 with variable response sizes, or error-rate shifts (404→200 transition on a path after an upload event) mark the moment the implant landed.
- Correlation. File write in webroot → first POST to that path → child process from the worker, all within minutes, is a near-certain intrusion regardless of what the file contents look like.

---

### 4. Key Indicators

- Web worker process spawning a command interpreter or LOLBin, at any depth of the tree.
- New `.aspx`, `.ashx`, `.jsp`, `.jspx`, `.php`, or `.war` file created in a webroot, upload, or temp-deploy directory outside a change window.
- Script files written by the web worker process itself (`w3wp.exe`, `php-fpm`) rather than by CI/CD tooling.
- POST traffic to a URI requested by fewer than a handful of distinct clients, with no referrer and no corresponding GETs.
- Requests to executable scripts inside directories meant for static or uploaded content.
- Shell-manager user-agents or POST bodies with base64/encrypted blobs to a single small script.
- `certutil -urlcache`, `curl`, or `wget` executed by the web service account (ingress tool transfer).
- Web service account performing recon (`whoami`, `net user`, `nltest`) or touching credentials (LSASS, registry hives).
- Files with timestamps timestomped to match neighboring legitimate content but with mismatched `$FILE_NAME` / change journal records.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Web Shell - Worker Process Spawning Shell or LOLBin",
  "description": "Detects web-server worker processes spawning command interpreters or LOLBins, escalating when correlated with webroot file writes or anomalous POST traffic in the same window.",
  "data_source": ["EDR.ProcessEvents", "Sysmon.EID1", "Sysmon.EID11", "IIS.W3CLogs", "Nginx.AccessLogs", "WAF.Logs"],
  "logic": {
    "window": "30m",
    "group_by": ["host", "parent_process"],
    "where": {
      "event_type": "process_create",
      "parent_process_in": ["w3wp.exe", "httpd", "nginx", "php-fpm", "tomcat", "java"],
      "child_process_in": ["cmd.exe", "powershell.exe", "sh", "bash", "whoami.exe", "net.exe", "ipconfig.exe", "systeminfo.exe", "certutil.exe", "curl", "wget"]
    },
    "having": {
      "process_create_count_gte": 1
    },
    "escalate_if_any": [
      "webroot_file_write in window and file_extension in ['aspx','ashx','jsp','jspx','php','war']",
      "http.method == 'POST' and http.uri_distinct_clients_30d <= 3",
      "child_process == 'certutil.exe' and cmdline contains 'urlcache'",
      "child_cmdline contains_any ['whoami', 'net user', 'nltest']"
    ]
  },
  "severity": "high",
  "tags": ["T1505.003", "T1190", "T1105", "T1071.001", "persistence", "web_shell"]
}
```

---

### 6. Example Event Data

```
Sysmon EID 11 (file create) — WEB-DMZ-01 (10.20.8.15)
UtcTime: 2025-06-19T02:38:52Z
Image: C:\Windows\System32\inetsrv\w3wp.exe   (AppPool: CustomerPortal)
TargetFilename: C:\inetpub\wwwroot\portal\uploads\help2.aspx

Sysmon EID 1 (process create) — WEB-DMZ-01
UtcTime: 2025-06-19T02:41:07Z
ParentImage: C:\Windows\System32\inetsrv\w3wp.exe
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c "whoami & ipconfig /all"
User: IIS APPPOOL\CustomerPortal

IIS W3C log — WEB-DMZ-01
2025-06-19 02:38:52 POST /portal/upload.aspx        - 443 203.0.113.44  Mozilla/5.0        200 141ms
2025-06-19 02:41:07 POST /portal/uploads/help2.aspx - 443 203.0.113.44  antSword/v2.1      200 63ms
2025-06-19 02:41:22 POST /portal/uploads/help2.aspx - 443 198.51.100.12 antSword/v2.1      200 58ms
2025-06-19 02:44:03 POST /portal/uploads/help2.aspx - 443 198.51.100.12 antSword/v2.1      200 902ms
```

---

### 7. Investigation Steps

1. **Confirm the lineage.** Pull the full process tree under the web worker. Enumerate every child, command line, and user context since the earliest suspicious file write.
2. **Find the implant.** Diff the webroot against the last known-good deploy. Check creation-vs-modification metadata, owning process, and NTFS `$FILE_NAME` timestamps for timestomping.
3. **Reconstruct the drop.** Walk web/WAF logs backward from the first POST to the implant path to find the exploit or upload request that created it — this identifies the vulnerable application and CVE.
4. **Scope the operators.** Extract all source IPs, user-agents, and TLS fingerprints that ever touched the implant URI. Attacker infrastructure frequently rotates; pivot on UA and request-body structure.
5. **Assess post-exploitation.** Review commands executed by the web service account: recon, credential access, ingress tool transfer, lateral movement toward internal segments.
6. **Sweep for siblings.** Hash and content-pattern search all webroots fleet-wide (other servers behind the same load balancer are prime candidates). One shell is rarely the only shell.
7. **Check for deeper persistence.** Attackers who land a shell often add scheduled tasks, new local accounts, ISAPI/Apache modules, or a second dormant shell as a fallback.

---

### 8. False Positive Considerations

- Legitimate application features that shell out: PDF/image converters, git hooks, health-check scripts, diagnostics endpoints invoking `ipconfig` or `df`.
- CI/CD and deployment agents writing script files into webroots during release windows.
- Administrators debugging on the box, running commands from an app-pool-identity terminal.
- CMS plugin/theme updates (WordPress, Drupal) that legitimately write PHP into the docroot.
- Vulnerability scanners POSTing to rarely-requested paths and generating 200s on upload endpoints.

---

### 9. Tuning Guidance

- Inventory legitimate parent→child pairs per application (e.g., `php-fpm → convert`) and suppress on the *pair plus command-line pattern*, never on the parent alone.
- Gate FIM alerts on change windows: file writes to webroots outside a registered deploy are high severity; inside one, correlate with the pipeline's service account before suppressing.
- Baseline URI popularity: a 30-day distinct-client count per path makes "rarely-requested script receiving POSTs" cheap to compute and highly selective.
- Treat any execution from upload/static directories as deny-by-default — those paths should be non-executable at the web-server config level, so hits there need no volume threshold.
- Java parents are noisy (Tomcat spawns helpers legitimately); require a shell/LOLBin child *or* a webroot write correlation before alerting on `java`/`tomcat` lineage.

---

### 10. Response Actions

**Immediate**

- Isolate the web server from internal segments; keep the box up if forensics is pending, but block inbound access to the implant path at the WAF/load balancer.
- Capture the implant file, web logs, and a memory image before any cleanup (Godzilla/Behinder operate largely in memory).
- Block observed operator IPs at the edge — while treating this as scoping data, not containment.

**Short-term**

- Remove the implant and any secondary shells found in the fleet sweep; verify against a clean deploy artifact, not by eyeballing the file.
- Patch or virtual-patch (WAF rule) the exploited vulnerability; confirm the exploit request no longer succeeds.
- Reset credentials reachable from the web service account context: connection strings, service accounts, API keys stored in app config.
- Rebuild the server from a known-good image if command execution as the worker is confirmed — cleanup-in-place is rarely trustworthy.

**Long-term**

- Enforce non-executable upload and static directories at the web-server configuration layer.
- Deploy FIM on all webroots with deploy-window awareness; alert on worker-process-authored script files unconditionally.
- Run web workers under least-privilege service accounts with egress restrictions (no arbitrary outbound from the DMZ).
- Add the worker-spawns-shell lineage rule to every internet-facing server profile; it is cheap and near-zero-FP once tuned.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- A web worker process spawned a command interpreter and the command line shows recon, credential access, or tool transfer.
- A script file in the webroot was written by the worker process itself and subsequently received POST traffic.
- The implant matches a known family (China Chopper, Godzilla, Behinder) by content, client UA, or request-body structure.
- The web service account authenticated to any internal system after the suspected drop time.
- The same implant path, hash, or operator infrastructure appears on more than one server.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Server / Application / AppPool:
Implant Path(s) / Hash(es):
Suspected Family:
Drop Vector (CVE / upload endpoint):
First Write / First POST Timestamps:
Operator IPs / User-Agents:
Commands Executed via Shell:
Credential / Lateral Movement Exposure:
Fleet Sweep Findings:
Containment Actions:
Rebuild Required (yes/no):
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

The file is polymorphic; the behavior is not. Web workers spawning shells, worker-authored script files in webroots, and POST traffic to paths nobody else requests are stable signals across every shell family from a Chopper one-liner to an encrypted Behinder implant. Correlate the three within a short window for near-certain confirmation, reconstruct the drop request to find the vulnerability, and sweep every webroot in the fleet — a single shell almost always has siblings, and a confirmed one usually means rebuild, not cleanup.

---

*GreyNOC — detection-engineering-first security operations.*
