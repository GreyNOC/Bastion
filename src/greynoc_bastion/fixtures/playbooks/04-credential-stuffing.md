# GreyNOC Security Playbook

## Credential Stuffing Detection & Response

---

### 1. Overview

Credential stuffing is the automated submission of leaked username/password pairs — typically harvested from third-party data breaches — against authentication endpoints in the hope that users have reused credentials. It is **not** brute force (no guessing) and **not** password spraying (the attacker has the password). Each request looks like a legitimate login attempt, and a meaningful percentage will succeed.

Credential stuffing is the dominant attack against consumer-facing logins, customer portals, e-commerce checkouts, banking applications, gaming platforms, and B2B SaaS tenants. Attackers operate at scale using residential proxy networks, headless browsers, and CAPTCHA-solving services. Even a 0.1% success rate against a 10M-credential combo list yields 10,000 takeovers.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Brute Force: Credential Stuffing | T1110.004 | Credential Access |
| Valid Accounts | T1078 | Initial Access / Persistence |
| Account Access Removal | T1531 | Impact (post-takeover) |

---

### 3. Detection Strategy

Credential stuffing looks like a flood of legitimate logins. Per-account volume is low (often a single attempt per credential). Per-source volume can be low as well when the attacker uses a residential proxy network. Detection has to combine multiple weak signals:

- Login velocity anomaly at the application or tenant level (overall login attempt rate spikes).
- Failure-rate inversion. Normal traffic has low failure rates; stuffing pushes failure rates above baseline because most leaked combos do not match.
- Automation signatures: missing or anomalous browser fingerprints, headless browser indicators, unusual TLS JA3/JA4 hashes, low-entropy User-Agent populations.
- Distribution shape: many sources with one attempt each; geographically diverse sources hitting login but not other app paths.
- Successful logins immediately followed by atypical behavior: rapid profile changes, payment method updates, password resets, gift card redemptions, data exports.
- Combo-list signatures: requests carrying credentials that match known leaked-credential corpora.

---

### 4. Key Indicators

- Login request rate exceeds baseline by N standard deviations.
- Auth failure ratio rises sharply while traffic volume rises.
- High proportion of requests from residential proxies / mobile ASNs / known proxy networks.
- TLS / browser fingerprints clustering on a small set of automation signatures.
- Missing typical pre-login traffic (no homepage visit, no JS, no CSS, no analytics beacons).
- Successful logins from devices/locations the user has never used.
- Post-login behaviors associated with account takeover: contact info change, MFA disable, fund movement, content theft.
- Credential sets matching known third-party breach corpora (HIBP-style indicators).

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Credential Stuffing - Tenant Login Anomaly",
  "description": "Detects abnormal login attempt volume with elevated failure rate and automation indicators across distributed sources.",
  "data_source": ["WebApp.AuthLogs", "WAF.RequestLogs", "IdP.SignInLogs"],
  "logic": {
    "window": "15m",
    "group_by": ["application_id"],
    "metrics": {
      "login_attempts": "count",
      "distinct_src_ip": "count_distinct(src_ip)",
      "failure_rate": "failures / login_attempts",
      "automation_ratio": "count(is_headless or known_bot_ja3) / login_attempts"
    },
    "having": {
      "login_attempts_above_baseline_pct": 300,
      "failure_rate_gte": 0.85,
      "distinct_src_ip_gte": 200,
      "automation_ratio_gte": 0.4
    }
  },
  "severity": "high",
  "tags": ["T1110.004", "credential_access", "fraud"]
}
```

---

### 6. Example Event Data

```json
[
  {"ts":"2025-02-18T14:02:01Z","src":"24.116.X.X","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","ja3":"e7d705a3286e19...","user":"alex.k@example.com","result":"failure","path":"/login","prev_session":null},
  {"ts":"2025-02-18T14:02:01Z","src":"71.42.X.X","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","ja3":"e7d705a3286e19...","user":"jen.smith@example.com","result":"failure","path":"/login","prev_session":null},
  {"ts":"2025-02-18T14:02:02Z","src":"99.103.X.X","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","ja3":"e7d705a3286e19...","user":"david9@example.com","result":"success","path":"/login","prev_session":null},
  {"ts":"2025-02-18T14:02:08Z","src":"99.103.X.X","user":"david9@example.com","path":"/account/email","action":"update_email","new":"attacker@maildrop.cc"}
]
```

---

### 7. Investigation Steps

1. **Quantify the surge.** Compare current login volume, failure rate, and source diversity to baseline.
2. **Cluster the automation.** Group requests by JA3/JA4, UA, accept-headers, and request timing — confirm a small number of automation profiles.
3. **Identify successes.** Pull all `result=success` events that fall inside the surge window. Treat these as candidate takeovers.
4. **Compare against device/location history.** For each success, check whether the device fingerprint or geolocation is novel for that user.
5. **Inspect post-auth behavior.** Look for contact-info changes, MFA edits, payment changes, content access spikes, or data exports immediately after login.
6. **Cross-reference combo lists.** If feasible, check whether the credentials presented match known third-party breach corpora.
7. **Check supporting infrastructure.** Are the source IPs known residential proxy / botnet exit nodes?

---

### 8. False Positive Considerations

- Marketing or product launches driving legitimate login spikes.
- Mobile app version rollouts where many users re-authenticate at once.
- SSO reconfiguration or password rotation events.
- Synthetic monitoring or load tests against authentication endpoints.
- Legitimate aggregators (e.g., financial-account aggregator services) authenticating on user behalf.

---

### 9. Tuning Guidance

- Establish **per-application baselines** for login volume, failure rate, and source diversity. Stuffing detection on a global threshold will misfire on the largest tenants and miss smaller ones.
- Ingest **bot-management and WAF signals** as features rather than treating them as standalone alerts.
- Use **device-trust / device-fingerprinting** to make "first-seen device" a strong feature; many takeovers will be from a never-before-seen device.
- Differentiate **stuffing-without-success** (block the source set, monitor) from **stuffing-with-success** (incident).
- Combine with **post-login fraud signals** — even when pre-auth detection is uncertain, post-auth behavioral anomalies will catch successful takeovers.

---

### 10. Response Actions

**Immediate**

- Block or rate-limit the offending source set (IP / ASN / proxy network) at the WAF/edge.
- Force password reset on any account that successfully logged in during the window.
- Revoke all sessions/tokens for impacted accounts.
- Alert affected users with a security notice.

**Short-term**

- Enable or harden bot management on authentication endpoints (challenge headless / known-proxy traffic).
- Require MFA, particularly for privileged actions (email change, payment change, withdrawals).
- Rotate or revoke API keys for any account where takeover is suspected.
- Enrich detection with a leaked-credential check at login time — refuse known-leaked passwords on login and reset.

**Long-term**

- Move to phishing-resistant MFA / passkeys for sensitive applications.
- Continuous credential exposure monitoring across third-party breach corpora.
- Implement step-up authentication on high-risk actions (out-of-pattern device, sensitive transaction).
- Build a post-login behavioral fraud detection layer to catch takeovers regardless of pre-auth detection coverage.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Successful authentications during the surge window are confirmed.
- Post-login takeover behavior is observed (contact, MFA, payment, withdrawal, export).
- Customers report unauthorized access concurrently with the detected surge.
- The same automation cluster recurs against the org repeatedly within a short timeframe.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Application / Tenant:
Login Volume vs Baseline:
Failure Rate:
Distinct Source IPs / ASNs:
Automation Cluster (JA3/JA4 / UA):
Successful Logins:
  - Accounts:
  - Post-Auth Behaviors:
Containment Actions:
Customer Impact / Notifications:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

No single feature catches credential stuffing reliably; the detection works by composing volume anomalies, failure-rate inversion, automation fingerprints, and post-login behavioral signals. Sensitive profile or asset changes immediately after a novel-device login are the highest-confidence indicator a takeover occurred. Pre-auth blocking buys time; user reset, MFA enforcement, and post-login fraud controls are what actually contain the damage.

---

*GreyNOC — detection-engineering-first security operations.*
