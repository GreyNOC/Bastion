# GreyNOC Security Playbook

## Impossible Travel Detection & Response

---

### 1. Overview

Impossible travel (also called "improbable travel" or "atypical travel") detects authentication events for the same user from **two geographic locations within a time window that no human could physically traverse**. It is a powerful — but easily over-tuned — signal of stolen credentials, session hijacking, or token theft.

It is one of the few high-confidence post-authentication signals available without endpoint context. It appears most often after credential phishing, infostealer infections, or token theft, when the attacker logs in from one geography while the legitimate user is active from another.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Valid Accounts | T1078 | Initial Access / Persistence |
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access |
| Steal Web Session Cookie | T1539 | Credential Access |
| Forge Web Credentials | T1606 | Credential Access |

---

### 3. Detection Strategy

The naive form is "two countries in one hour." That is necessary but far from sufficient and generates massive noise from VPNs, mobile carriers, and cloud sign-ins. A workable detection treats geography as one feature among several:

- Compute a per-user velocity score: `distance / time` between consecutive sign-ins.
- Flag when velocity exceeds a configurable threshold (e.g., > 800 km/h sustained).
- Combine with independent risk features:
  - New ASN / hosting provider for that user.
  - New device or user-agent.
  - Sign-in from a known anonymizing service (TOR, hosting ASN, datacenter).
  - Sign-in from a country that user has never authenticated from.
  - Concurrent sessions from both locations (parallel use, not just sequential).
- Down-weight matches on mobile carrier ASNs (carrier-grade NAT egress can shift geography) or known corporate VPN egress.
- Up-weight matches followed by post-auth anomalies: mailbox rule creation, MFA changes, OAuth grants, privileged actions.

---

### 4. Key Indicators

- Two successful sign-ins for the same identity from locations exceeding a realistic travel speed.
- One of the two sign-ins originates from a hosting / VPN / TOR ASN.
- Two simultaneous active sessions from disparate geographies.
- Sudden change in device fingerprint, OS, or browser between the two sign-ins.
- Authentication via a different protocol path (e.g., legacy IMAP from one location, modern OAuth from another).
- Sign-in correlates with recent phishing exposure for the same user.
- Post-auth tenant changes (mailbox forwarding, OAuth consent, MFA registration).

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Impossible Travel - Velocity + Risk Composite",
  "description": "Detects same-user sign-ins separated by infeasible travel velocity, escalating when independent risk features are present.",
  "data_source": ["AzureAD.SignInLogs", "Okta.SystemLog", "Workspace.LoginAudit"],
  "logic": {
    "group_by": ["user_id"],
    "order_by": "ts asc",
    "compute": {
      "velocity_kmh": "distance(prev.geo, curr.geo) / hours_between(prev.ts, curr.ts)"
    },
    "where": {
      "velocity_kmh_gte": 800
    },
    "escalate_if_any": [
      "curr.asn_type == 'hosting'",
      "curr.is_anonymizer == true",
      "curr.country not in user.history.countries",
      "curr.device_id not in user.history.devices",
      "concurrent_session_with_prev == true"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1078", "T1539", "identity"]
}
```

---

### 6. Example Event Data

```json
[
  {"ts":"2025-01-08T13:42:00Z","user":"k.nguyen@corp.com","src":"24.55.X.X","geo":"Boston, US","asn":"Comcast","device":"d-93f1...","ua":"Edge/120 Win11"},
  {"ts":"2025-01-08T14:18:00Z","user":"k.nguyen@corp.com","src":"45.83.X.X","geo":"Frankfurt, DE","asn":"M247 (hosting)","device":"d-unknown","ua":"Mozilla/5.0 ... Linux"},
  {"ts":"2025-01-08T14:21:00Z","user":"k.nguyen@corp.com","action":"new_inbox_rule","rule":"forward+delete:external@maildrop.cc"}
]
```

---

### 7. Investigation Steps

1. **Compute the velocity precisely.** Some IdPs report imprecise geo; cross-check with IP-to-geo enrichment.
2. **Profile both sources.** ASN type (residential, business, mobile, hosting, VPN), reputation, prior history for this user.
3. **Compare devices.** Device IDs, OS, browser, TLS fingerprint, and any client certificate or compliant-device flag.
4. **Check session concurrency.** Were both sessions active simultaneously? Concurrent ≠ sequential.
5. **Inspect post-auth behavior** for the suspect session: mailbox rules, OAuth grants, file access, admin actions, MFA changes.
6. **Validate with the user** through an **out-of-band** channel (phone, in-person). Do not rely on email or chat that the attacker could be reading.
7. **Pivot to other users** if the suspect ASN, device, or token signature is shared.

---

### 8. False Positive Considerations

- Corporate or personal VPN egress (especially split-tunnel changes between sessions).
- Mobile carriers using carrier-grade NAT that geolocates to a different city or country.
- Cloud-based browsing services (Citrix, AWS WorkSpaces, browser isolation) that originate from a datacenter.
- Travel with cached / offline session tokens that activate on landing.
- Two devices for the same user roaming on different carriers.
- Inaccurate IP geolocation, particularly for satellite ISPs and shared IPv6 ranges.

---

### 9. Tuning Guidance

- Always combine velocity with **independent features**; never alert on velocity alone above the lowest severity tier.
- Maintain per-user **device, ASN, and geography history** to make "novelty" a strong signal.
- Suppress when both endpoints are corporate VPN egress or known telework infrastructure.
- Treat **hosting ASN + new device + new country** as a strong escalator, even if velocity is borderline.
- Differentiate **interactive sign-in** from **non-interactive token use** (refresh tokens, service principals) — both should be evaluated, but with different baselines.
- Re-baseline frequently for users whose travel patterns are inherently global (executives, consultants).

---

### 10. Response Actions

**Immediate**

- Revoke all active sessions and refresh tokens for the user.
- Force password reset and require MFA re-registration.
- Block the suspect source IP / ASN and any tokens issued to it.
- Capture full sign-in and audit logs for the affected window.

**Short-term**

- Review and remove any inbox rules, mail forwarders, OAuth grants, or app passwords created during the window.
- Audit privileged actions, file accesses, and tenant changes performed by the account.
- Notify the user via out-of-band channel and confirm legitimacy of recent activity.
- Quarantine devices used in the suspect session if managed.

**Long-term**

- Deploy phishing-resistant MFA / passkeys.
- Enforce conditional access policies that block hosting/anonymizer ASNs and unmanaged devices for sensitive roles.
- Tighten token lifetime and require continuous access evaluation (CAE) where supported.
- Add infostealer-exposure monitoring for corporate identities (token / cookie marketplaces).

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Concurrent sessions from disparate geographies for the same identity.
- Suspect sign-in originates from hosting / TOR / anonymizer ASN.
- Post-auth audit shows mailbox rule creation, OAuth consent, MFA changes, or privileged operations.
- The user is unreachable or denies the activity.
- Multiple users in the tenant trigger the rule from related infrastructure within a short window.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
User:
Sign-In A: ts / geo / asn / device / ua
Sign-In B: ts / geo / asn / device / ua
Computed Velocity (km/h):
Concurrent Sessions (yes/no):
Risk Escalators Triggered:
Post-Auth Activity Observed:
User Confirmation (out-of-band):
Containment Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Impossible travel is a high-value, high-noise signal. Geographic velocity should feed a composite score, not produce a verdict on its own. Independent risk features (hosting ASN, new device, new country, concurrent session) and post-auth behavior are what separate signal from noise. Out-of-band user verification is mandatory before clearing a true-positive-shaped event.

---

*GreyNOC — detection-engineering-first security operations.*
