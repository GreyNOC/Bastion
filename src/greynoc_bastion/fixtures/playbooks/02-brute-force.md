# GreyNOC Security Playbook

## Brute Force Attack Detection & Response

---

### 1. Overview

A brute force attack is the iterative submission of credentials against a single account or a small set of accounts in an attempt to guess a valid password, PIN, token, or key. Unlike password spraying, brute force concentrates volume on **few accounts with many guesses** — making it noisy but effective against weak credentials, exposed services, and accounts without lockout.

Brute force remains a primary access vector for SSH, RDP, VPN concentrators, database services, web admin panels, and API keys. It is most common against externally exposed assets, misconfigured cloud workloads (SSH bound to 0.0.0.0/0 is the canonical example), and legacy applications without rate limiting.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Brute Force | T1110 | Credential Access |
| Brute Force: Password Guessing | T1110.001 | Credential Access |
| Brute Force: Credential Stuffing | T1110.004 | Credential Access |
| External Remote Services | T1133 | Initial Access |

---

### 3. Detection Strategy

Brute force is a per-target volume problem with a temporal signature. Effective detection requires:

- High failure count against a single target identity within a tight window.
- Detection of sustained attempts beyond the lockout threshold (a sign of either an attacker rotating to bypass lockout, or lockout being misconfigured).
- Source-side concentration: one source generating disproportionate auth volume, regardless of result.
- Service-aware thresholds: SSH and RDP brute force look different from web login brute force; tune per protocol.
- Pairing with post-success behavior monitoring. Catching the guess is less valuable than catching what happens after a successful guess.

---

### 4. Key Indicators

- ≥ N authentication failures against a single user/host within a short window.
- Failures followed by a success from the same source.
- Repeated TCP connections to authentication ports (22, 3389, 445, 1433, 3306, 5432) from a single source.
- Sequential or alphabetical username enumeration patterns.
- High ratio of failed-to-successful logins on a host or service.
- Authentication attempts using common default credentials (`admin/admin`, `root/toor`, `sa/sa`).
- Source IP matches scanner / botnet / TOR / known-bad reputation feeds.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Brute Force - Single Target High Failure Volume",
  "description": "Detects sustained authentication failures against a single account or host from a single source.",
  "data_source": ["Linux.Auth", "WindowsEvent.Security", "VPN.Auth", "Firewall.Conn"],
  "logic": {
    "window": "5m",
    "group_by": ["src_ip", "dst_user"],
    "where": {
      "event_type": "authentication",
      "result": "failure"
    },
    "having": {
      "failure_count_gte": 25
    },
    "enrich_with_post_success": true
  },
  "severity": "high",
  "tags": ["T1110", "credential_access", "perimeter"]
}
```

---

### 6. Example Event Data

```
Apr 22 01:14:11 edge-01 sshd[2841]: Failed password for root from 193.34.X.X port 51223 ssh2
Apr 22 01:14:13 edge-01 sshd[2843]: Failed password for root from 193.34.X.X port 51224 ssh2
Apr 22 01:14:15 edge-01 sshd[2845]: Failed password for admin from 193.34.X.X port 51225 ssh2
Apr 22 01:14:18 edge-01 sshd[2847]: Failed password for admin from 193.34.X.X port 51226 ssh2
...
Apr 22 01:18:49 edge-01 sshd[2901]: Accepted password for admin from 193.34.X.X port 51388 ssh2
Apr 22 01:18:50 edge-01 sshd[2901]: pam_unix(sshd:session): session opened for user admin
```

---

### 7. Investigation Steps

1. **Validate the volume.** Pull all auth events for the source IP and target account within ±1h of the alert.
2. **Determine outcome.** Was there a successful authentication after the failures? If yes, treat as confirmed compromise.
3. **Profile the source.** Reputation, ASN, geolocation, prior history, concurrent activity against other tenants/hosts.
4. **Assess the target.** Asset criticality, exposure (Internet-facing vs internal), account privilege level, MFA status.
5. **Inspect the protocol session** (if available): NetFlow, packet metadata, TLS JA3, or session length/byte counts on success.
6. **Review post-auth telemetry** on success: process execution, lateral movement, persistence creation, data access.
7. **Hunt for correlated activity** from the same source against neighboring assets (subnet sweep, port reuse).

---

### 8. False Positive Considerations

- Forgotten passwords after long absences (PTO, post-onboarding).
- Stale credentials cached in scripts, CI runners, or scheduled tasks.
- Vulnerability scanners with credentialed scan profiles failing against unsupported services.
- Health checks misconfigured to authenticate.
- Penetration testing or red team engagements.
- Backup software, monitoring tools, or service accounts with expired secrets.

---

### 9. Tuning Guidance

- Set thresholds per **service class**: SSH/RDP (low), web app login (medium), API (high), interactive desktop (very low).
- Exclude known scanner IPs only with explicit allowlists, never by inference.
- Use **logarithmic / decay-based scoring** to favor sustained attackers over noisy one-offs.
- Suppress alerts where the source is internal *and* the target account is the same user (self-locked-out users).
- Always retain the **post-success** signal even when failure-volume alerts are tuned down.

---

### 10. Response Actions

**Immediate**

- Block the source IP at the perimeter and at the host firewall.
- Lock or reset the targeted account; invalidate active sessions and tokens.
- Capture process and authentication state on the target host for forensics.

**Short-term**

- Enforce account lockout policies if not already in place.
- Add fail2ban / connection rate limits on exposed auth services.
- Move administrative services off the public Internet (jump host, VPN, ZTNA).
- Add MFA on any service that supports it.

**Long-term**

- Eliminate password authentication on SSH (key-based only).
- Deploy phishing-resistant MFA on remote access portals.
- Continuous external attack-surface monitoring to identify newly exposed auth endpoints.
- Dark web / paste site monitoring for the org's credentials and domains.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Brute force results in a successful authentication.
- The targeted account is privileged or service-critical.
- Post-auth activity is observed: command execution, file transfer, persistence, lateral movement.
- The same source is concurrently attacking multiple internal assets.
- Brute force is observed against an asset that should not be Internet-reachable.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Source IP / ASN / Geo:
Targeted Account(s):
Targeted Host / Service:
Failure Count:
Successful Authentication (yes/no):
Post-Auth Activity Observed:
Asset Criticality:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

The shape is many failures, few targets, one source. Post-success behavior is what determines severity: a single accepted login after a flood of failures should be handled as a compromise, with forensics following. Prevention controls (MFA, lockout, exposure reduction) will always outperform any rule written against this technique.

---

*GreyNOC — detection-engineering-first security operations.*
