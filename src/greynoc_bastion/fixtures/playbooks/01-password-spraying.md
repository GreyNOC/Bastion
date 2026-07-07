# GreyNOC Security Playbook

## Password Spraying Detection & Response

---

### 1. Overview

Password spraying is a low-and-slow authentication attack in which an adversary attempts a small number of common or weak passwords (e.g., `Spring2025!`, `Welcome1`, `Password123`) against a large list of valid usernames. Unlike brute force, the attacker pivots horizontally across accounts to stay below per-account lockout thresholds.

Spraying remains a primary initial-access technique against identity providers (Entra ID, Okta, ADFS, Google Workspace, M365). A single successful login is enough to pivot into MFA fatigue, OAuth abuse, or mailbox access. The activity shows up constantly against externally exposed authentication endpoints: VPN portals, OWA, ADFS, Citrix gateways, and SaaS IdPs.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Brute Force: Password Spraying | T1110.003 | Credential Access |
| Valid Accounts | T1078 | Initial Access / Persistence |

---

### 3. Detection Strategy

Per-user logs look benign during a spray; the attack only becomes visible when authentication failures are aggregated across the user dimension.

- Pivot from "failures per user" to "distinct users targeted per source within a sliding window."
- Watch for low failure counts per account combined with high account fan-out.
- Correlate against legacy authentication endpoints (IMAP, POP, SMTP AUTH, ActiveSync), which bypass conditional access in many environments.
- Track success-after-spray: a successful logon from the same source/IP/UA shortly after a fan-out failure pattern is the highest-value signal in this category.

---

### 4. Key Indicators

- A single source IP, user-agent, or ASN authenticating against ≥ N distinct usernames within a short window.
- Failure-to-user ratio close to 1:1 (each user fails roughly once).
- Authentication failure code consistent with bad password (not bad username).
- Unusual user-agent strings (`python-requests`, `FireProx`, `MSOLSpray`, `Go-http-client`).
- Bursts against legacy auth protocols (`Other`, `BAV2ROPC`, `IMAP4`, `POP3`).
- Geographic origin not previously seen for the tenant.
- Time-of-day pattern outside business hours of the targeted org.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Password Spray - Distinct User Fan-Out",
  "description": "Detects a single source authenticating against many distinct users with a low per-user failure rate within a sliding window.",
  "data_source": ["AzureAD.SignInLogs", "Okta.SystemLog", "ADFS.SecurityLog"],
  "logic": {
    "window": "10m",
    "group_by": ["src_ip", "user_agent"],
    "where": {
      "event_type": "authentication",
      "result": "failure",
      "failure_reason_in": ["invalid_password", "bad_credentials", "50126"]
    },
    "having": {
      "distinct_users_gte": 15,
      "avg_failures_per_user_lte": 3
    }
  },
  "severity": "high",
  "tags": ["T1110.003", "credential_access", "identity"]
}
```

---

### 6. Example Event Data

```json
[
  {"ts":"2025-04-12T03:14:02Z","user":"a.morris@corp.com","src_ip":"45.227.X.X","ua":"BAV2ROPC","protocol":"IMAP","result":"failure","reason":"invalid_password"},
  {"ts":"2025-04-12T03:14:05Z","user":"j.chen@corp.com","src_ip":"45.227.X.X","ua":"BAV2ROPC","protocol":"IMAP","result":"failure","reason":"invalid_password"},
  {"ts":"2025-04-12T03:14:08Z","user":"r.patel@corp.com","src_ip":"45.227.X.X","ua":"BAV2ROPC","protocol":"IMAP","result":"failure","reason":"invalid_password"},
  {"ts":"2025-04-12T03:14:33Z","user":"m.adams@corp.com","src_ip":"45.227.X.X","ua":"BAV2ROPC","protocol":"IMAP","result":"success","reason":"-"}
]
```

---

### 7. Investigation Steps

1. **Confirm the fan-out.** Pull all auth events for the source IP/ASN over the last 24h. Count distinct usernames and per-user failure depth.
2. **Identify successes.** Filter for `result=success` from the same source/UA. Treat any success as an active intrusion until disproven.
3. **Profile the source.** Check ASN, hosting provider, geolocation, prior tenant history, and known-bad IP feeds.
4. **Triage the targeted user list.** Look for patterns: a department, an HR export, an OSINT-scraped name list.
5. **Check protocol path.** Determine whether legacy auth (IMAP, BAV2ROPC, SMTP AUTH) was used and whether conditional access applied.
6. **Review post-auth activity** for any successful account: token issuance, OAuth grants, mailbox rule creation, MFA registration changes.
7. **Pivot on user-agent and TLS fingerprint** to find correlated activity from rotating IPs.

---

### 8. False Positive Considerations

- Misconfigured mobile mail clients hammering with stale passwords after a forced reset.
- Service accounts with expired credentials retrying across multiple endpoints.
- Internal red team or automated security testing.
- SSO migrations causing legacy clients to fail-then-succeed across many users.
- Shared NAT egress (e.g., guest Wi-Fi) producing apparent fan-out from one IP.

---

### 9. Tuning Guidance

- Baseline per-tenant: distinct-user thresholds should scale with org size.
- Exclude known service-account ranges and corporate egress IPs from "external source" logic — but alert separately if those sources begin spraying.
- Disable or block legacy auth where possible; once blocked, lower the threshold for the legacy path because *any* fan-out there is suspicious.
- Suppress single-burst events from mobile carrier ASNs only when paired with known device IDs.
- Enrich with IP reputation, ASN, and TOR/VPN tagging to escalate confidence rather than gate the alert.

---

### 10. Response Actions

**Immediate**

- Block the source IP / ASN range at the identity provider edge and perimeter.
- Force password reset on any account that succeeded; revoke all active sessions and refresh tokens.
- Require MFA re-registration for impacted accounts.

**Short-term**

- Disable legacy authentication protocols tenant-wide.
- Enable risk-based conditional access (sign-in risk, user risk).
- Notify impacted users and validate their MFA methods are not attacker-controlled.

**Long-term**

- Roll out phishing-resistant MFA (FIDO2 / passkeys) for privileged and externally-facing roles.
- Implement banned-password lists aligned with the attacker dictionary observed.
- Continuously monitor for password-spray TTPs across all federated identity surfaces.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- A successful authentication occurs from the spraying source.
- A privileged account (admin, finance, executive, service principal) is among the targets.
- Post-auth activity is observed (token use, mailbox rule, OAuth consent, device join).
- Spray activity correlates with concurrent recon or phishing campaigns against the tenant.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Source IP / ASN / Geo:
User-Agent / Protocol:
Distinct Users Targeted:
Successful Authentications (yes/no):
  - Accounts:
  - Privileged?:
Post-Auth Activity Observed:
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Aggregate across the user dimension, not the failure-per-account dimension. The reliable signal is high distinct-user fan-out from a single source with low per-user failures, particularly over legacy auth paths. Any successful login during such a pattern is an active intrusion to be contained, not an alert to be triaged.

---

*GreyNOC — detection-engineering-first security operations.*
