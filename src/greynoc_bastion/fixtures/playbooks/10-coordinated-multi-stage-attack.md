# GreyNOC Security Playbook

## Coordinated Multi-Stage Attack Detection & Response

---

### 1. Overview

A coordinated multi-stage attack is an intrusion in which an adversary chains discrete techniques across the kill chain — reconnaissance → initial access → execution → privilege escalation → defense evasion → credential access → lateral movement → collection → exfiltration → impact — sometimes spread over hours, sometimes days or weeks. Each individual stage may be subtle enough to pass an isolated rule; the attack is recognizable only when the stages are **stitched together** by identity, host, infrastructure, or time.

Real intrusions look like this. Single-event detections produce alerts; chain detection produces incidents. SOCs that cannot correlate stages tend to see fragments of the same campaign as unrelated low-severity alerts, and miss the intrusion until the impact stage forces it into view.

---

### 2. MITRE ATT&CK Mapping

This playbook is a **chain detector** spanning multiple tactics. Representative techniques per stage:

| Stage | Technique | ID |
|-------|-----------|----|
| Reconnaissance | Active Scanning | T1595 |
| Initial Access | Phishing | T1566 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter | T1059 |
| Persistence | Account Manipulation | T1098 |
| Privilege Escalation | Valid Accounts | T1078 |
| Defense Evasion | Impair Defenses | T1562 |
| Credential Access | OS Credential Dumping | T1003 |
| Discovery | Domain Trust Discovery | T1482 |
| Lateral Movement | Remote Services | T1021 |
| Collection | Data from Information Repositories | T1213 |
| Command and Control | Application Layer Protocol | T1071 |
| Exfiltration | Exfiltration Over Web Service | T1567 |
| Impact | Data Encrypted for Impact | T1486 |

---

### 3. Detection Strategy

Coordinated-attack detection is a correlation problem, not a signature problem. The strategy stacks three layers:

1. Strong stage detectors. Each stage in the kill chain has its own playbook (this suite covers most). Stage detectors should be production-tuned with reasonable precision individually.
2. Entity-centric correlation. Aggregate alerts and behaviors per entity (`user`, `host`, `src_ip`, `service principal`, `external infrastructure`) over a rolling window (24h–14d). Score the entity by the diversity of tactics observed rather than raw alert count.
3. Sequence-aware logic. Promote correlations that follow plausible attacker order (`external_recon → initial_access → execution → priv_esc`) and span multiple entities linked by shared infrastructure or auth chain.

Key signals that separate a coordinated chain from coincidental noise:

- Tactic diversity over a single entity within a short window. Five or more tactics on one host or identity in 24 hours is rarely benign.
- Pivot evidence: alerts on host A and host B share an actor, a parent process tree, a token, or a C2 destination.
- Time clustering with logical ordering: recon followed by access followed by execution.
- Crown-jewel involvement: any chain that touches tier-zero identity, finance systems, source code, customer data, or production secrets.

---

### 4. Key Indicators

- A single user/host accumulates alerts across **3+ MITRE tactics** within a sliding window.
- A privileged authentication immediately follows a credential-access alert on the same host.
- Beaconing host is the same host that recently triggered an Office-spawned PowerShell alert.
- New service principal is created shortly after a high-risk sign-in for an admin.
- Lateral movement (SMB/WinRM/RDP) originates from a host with a recent EDR detection.
- Mass file access / archive creation on a fileshare in the hours before an outbound data spike.
- Defender / EDR tampering events immediately precede other endpoint detections.
- External infrastructure (IP, domain, JA3) is seen across multiple unrelated alerts.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Coordinated Chain - Multi-Tactic Entity Correlation",
  "description": "Detects entities accumulating alerts across multiple ATT&CK tactics within a sliding window, with sequence and crown-jewel escalation.",
  "data_source": ["SIEM.Alerts", "EDR.Detections", "IdP.Risk", "Network.IDS", "DLP.Events"],
  "logic": {
    "window": "24h",
    "group_by": ["entity"],
    "entity_types": ["user", "host", "service_principal", "external_ip"],
    "compute": {
      "distinct_tactics": "count_distinct(alert.mitre_tactic)",
      "stage_sequence": "ordered_set(alert.kill_chain_stage)",
      "linked_entities": "graph_neighbors(entity, edges=[shared_token, shared_process_tree, shared_c2, parent_child_auth])"
    },
    "having_any": [
      "distinct_tactics >= 3",
      "stage_sequence contains_subsequence ['initial_access','execution','priv_esc']",
      "stage_sequence contains_subsequence ['credential_access','lateral_movement']",
      "stage_sequence contains_subsequence ['collection','exfiltration']"
    ],
    "escalate_if_any": [
      "entity in crown_jewel_set",
      "linked_entities count >= 3",
      "any(alert.severity == 'critical')"
    ]
  },
  "severity": "critical_when_escalated_else_high",
  "tags": ["correlation", "chain", "kill_chain"]
}
```

---

### 6. Example Event Data

```
T+00:00  IDS:    Recon scan from 198.51.100.42 against perimeter (T1595)
T+02:14  Mail:   Phishing email with HTML smuggling delivered to j.doe (T1566)
T+02:21  EDR:    winword.exe -> powershell.exe -enc ... on WS-1043 (T1059.001)
T+02:23  EDR:    LSASS access by powershell.exe on WS-1043 (T1003)
T+02:35  IdP:    Anomalous sign-in for j.doe from hosting ASN, new device (T1078)
T+02:41  IdP:    j.doe added 'svc-reporting' to Global Administrators (T1098)
T+02:48  Net:    Beaconing from WS-1043 to cdn-update[.]help every 60s ± 6s (T1071)
T+05:10  EDR:    WS-1043 -> SRV-FILES-02 SMB session, mass read on \\Finance$ (T1021/T1213)
T+05:42  Net:    Outbound 1.4 GB to mega.nz from WS-1043 (T1567)
```

A correlation engine should fuse these into a single **incident on entity `j.doe` / `WS-1043`** rather than nine independent alerts.

---

### 7. Investigation Steps

1. **Build the timeline.** Pull every alert and every key audit event for the involved entities over the chain window. Order them.
2. **Identify the foothold.** Walk backward from the first execution event to the delivery vector (email, web, exposed service, supply chain, valid-account compromise).
3. **Map the entity graph.** Identify all related users, hosts, service principals, and external infrastructure connected by shared tokens, process trees, lateral auth, or C2.
4. **Determine current attacker capability.** What credentials, roles, tokens, and persistence mechanisms does the adversary currently hold?
5. **Assess data exposure.** What was read, archived, exfiltrated, or modified? Pull DLP, fileshare audit, mailbox audit, cloud storage access, and database query logs for the window.
6. **Plan containment in priority order:** disrupt C2, revoke privileged sessions, isolate hosts, rotate credentials, remove persistence — without alerting the attacker prematurely if forensic capture is still ongoing.
7. **Prepare communications.** Engage incident response leadership, legal, and (as appropriate) regulatory and customer-notification stakeholders.

---

### 8. False Positive Considerations

- Penetration tests, purple-team exercises, or adversary-emulation campaigns that intentionally chain techniques.
- Vulnerability scanners producing recon + auth + service-enumeration alerts on the same host.
- IT staff performing authorized administrative chains (admin login → privileged role assignment → file access).
- Backup or DR processes that mimic data-collection-plus-egress patterns at scale.
- Forensic / DFIR tooling that touches LSASS, accesses many files, and writes archives during legitimate investigations.

---

### 9. Tuning Guidance

- **Tune the correlator, not the underlying detectors.** Suppressing a stage detector to clean up chain alerts blinds you to other intrusions. Add context (authorized-change ticket, known scanner ASN, known DR job) at the correlation layer.
- Maintain a **crown-jewel list** of entities (tier-zero identities, production systems, finance, source code, customer data stores). Any chain touching a crown-jewel entity escalates automatically regardless of alert count.
- Use **graph linking** aggressively: an attacker who pivots from host to host or identity to identity will share tokens, JA3s, parent processes, and infrastructure. Linking those entities catches campaigns that look fragmented per-entity.
- Make **time windows tactic-aware.** Beacon dwell can stretch for weeks; phishing-to-execution is usually minutes. A single global window misses both ends.
- Include **post-incident playback** as a tuning input: when a confirmed incident is closed, replay it through the correlator and identify which signals would have surfaced it earlier.

---

### 10. Response Actions

**Immediate**

- Stand up an incident bridge; assign IC, scribe, and stream owners (identity, endpoint, network, cloud, legal/comms).
- Isolate compromised hosts; revoke all sessions, refresh tokens, and Kerberos tickets for involved identities; rotate credentials for impacted service accounts.
- Block C2 infrastructure at DNS, proxy, and firewall.
- Preserve forensic evidence: memory, disk, packet captures, identity audit, cloud audit, mail audit.

**Short-term**

- Eradicate persistence: scheduled tasks, services, WMI subscriptions, mailbox rules, OAuth grants, app registrations, federation modifications, IAM policies.
- Rebuild compromised hosts from known-good images. Do not "clean" tier-zero systems.
- Hunt the rest of the fleet for the same TTPs and infrastructure.
- Reset credentials and rotate secrets in scope; enforce MFA reissue.

**Long-term**

- Address the root-cause foothold (patch the exploited service, harden the phishing path, fix the misconfiguration).
- Tier administrative access and adopt JIT privileged access if not already in place.
- Strengthen egress controls and outbound destination categorization.
- Build or refine correlation rules from this incident's chain so the next one fires earlier.
- Conduct a formal lessons-learned and update incident-response runbooks.

---

### 11. Escalation Criteria

Escalate to a **major incident** when **any** of the following are true:

- A chain spans 4+ MITRE tactics on a single entity, or 3+ tactics involving a crown-jewel entity.
- Confirmed credential access on a tier-zero identity (Domain Admin, Global Admin, root, Owner).
- Data exfiltration is confirmed or strongly indicated (volume, destination, content sensitivity).
- Defense evasion includes EDR/AV tampering, log clearing, or backup destruction.
- Attacker holds active C2 to multiple hosts.
- Chain implicates third-party / supply-chain infrastructure.

---

### 12. Analyst Notes Template

```
Incident ID:
Severity:
Detected At:
Incident Commander:

Affected Entities:
  - Users:
  - Hosts:
  - Service Principals:
  - External Infrastructure:

Stage Timeline (ordered):
  T+...  stage / technique / detection

Initial Access Vector:
Current Attacker Capability:
Persistence Mechanisms Identified:
Data Exposure Summary:

Containment Actions Taken:
Eradication Plan:
Forensic Evidence Captured:
External Notifications (legal / customers / regulators):

Outstanding Risks:
Lessons Learned (preliminary):
Detection Improvements Identified:
Analyst:
```

---

### 13. Summary

These are won or lost at the correlation layer. Tune strong stage detectors, aggregate per entity across a rolling window, link entities by shared infrastructure and auth chains, and promote sequences that match attacker logic. The escalators that matter most are tactic diversity on a single entity, crown-jewel involvement, and graph-linked lateral spread. A four-tactic chain is an incident on first observation; verification happens alongside containment, not before it.

---

*GreyNOC — detection-engineering-first security operations.*
