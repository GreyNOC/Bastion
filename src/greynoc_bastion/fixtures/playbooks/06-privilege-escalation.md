# GreyNOC Security Playbook

## Privilege Escalation Detection & Response

---

### 1. Overview

Privilege escalation is the act of obtaining higher rights than the account or context originally granted. It can be **vertical** (a low-privileged user becoming an administrator) or **horizontal** (gaining access to a peer account or workload of similar nominal level but different scope). It applies across endpoints (UAC bypass, kernel exploits), identity systems (role assignment, OAuth grants, group changes), and cloud planes (assumed roles, IAM policy abuse, service-principal misuse).

Privilege escalation is the bridge between initial foothold and meaningful impact. Without it, an attacker is contained. With it, the blast radius opens to domain dominance on-prem, tenant takeover in cloud, and secrets or data access at scale.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Privilege Escalation (tactic) | TA0004 | — |
| Abuse Elevation Control Mechanism | T1548 | Privilege Escalation |
| Account Manipulation | T1098 | Persistence / Privilege Escalation |
| Domain Policy Modification | T1484 | Privilege Escalation |
| Domain Policy Modification: Domain Trust Modification | T1484.002 | Privilege Escalation |
| Exploitation for Privilege Escalation | T1068 | Privilege Escalation |
| Cloud Account Manipulation | T1098.003 | Persistence / Privilege Escalation |
| Token Impersonation/Theft | T1134 | Privilege Escalation |

---

### 3. Detection Strategy

There is no single rule for "privilege escalation." Coverage is built from state-change monitoring across identity, endpoint, and cloud control planes, paired with process and token telemetry at execution time.

- Identity layer: monitor every assignment to privileged roles, group changes, app role grants, federation/trust modifications, and conditional-access policy edits. Alert on any privileged-role addition; treat Global Admin, Domain Admin, Owner, `roles/owner`, and `iam:*` grants as high priority.
- Endpoint layer: detect known UAC bypass patterns, token impersonation, abuse of SUID/sudo, kernel exploit indicators, named-pipe impersonation, and process integrity-level transitions.
- Cloud layer: detect IAM policy attachments granting admin equivalence, role chain assumptions across accounts, service-account key creation, and creation of privileged service principals.
- Process lineage: detect a non-privileged parent spawning a privileged child outside known elevation paths.
- Behavioral correlation: link a recent foothold (phishing, web-shell, RCE) with a subsequent privilege change for the same actor or host within minutes to hours.

---

### 4. Key Indicators

- New member added to a privileged group or role (Domain Admins, Enterprise Admins, Global Admin, root-equivalent cloud roles).
- Service account or service principal granted privileged scopes (e.g., `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`).
- Creation of a new local administrator account on an endpoint.
- UAC bypass artifacts: registry hijacks (`fodhelper`, `eventvwr`, `sdclt`), DLL search-order abuse, COM elevation moniker abuse.
- Token manipulation: `SeImpersonate`, `SeDebug` use by non-system processes; suspicious calls to `CreateProcessWithTokenW`.
- Linux: world-writable SUID binaries appearing, `sudoers` modifications, kernel module loads, capability changes (`CAP_SYS_ADMIN`).
- Cloud: `AttachUserPolicy`, `AttachRolePolicy`, `CreateAccessKey` for another principal, `iam:PassRole` to a privileged role.
- Conditional access / MFA bypass policy edits.
- Federation trust modifications (new SAML federation, trusted realm).

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Privileged Role Assignment - Identity",
  "description": "Detects assignment of a high-privileged role/group across identity providers, with escalation when assigner or assignee is anomalous.",
  "data_source": ["AzureAD.AuditLogs", "Okta.SystemLog", "WindowsEvent.Security:4728/4732/4756", "AWS.CloudTrail"],
  "logic": {
    "where": {
      "event_type_in": ["role_assignment", "group_member_added", "policy_attached"],
      "target_role_in": [
        "Global Administrator",
        "Privileged Role Administrator",
        "Domain Admins",
        "Enterprise Admins",
        "AdministratorAccess",
        "roles/owner"
      ]
    },
    "escalate_if_any": [
      "actor.is_service_principal == true and actor.recent_creation == true",
      "actor.session.risk == 'high'",
      "target.is_service_principal == true",
      "actor.location not in actor.history.locations",
      "change_outside_business_hours == true"
    ]
  },
  "severity": "critical_when_escalated_else_high",
  "tags": ["T1098", "T1078", "privilege_escalation"]
}
```

---

### 6. Example Event Data

```json
[
  {"ts":"2025-04-02T22:11:04Z","actor":"j.doe@corp.com","action":"AddMemberToRole","role":"Global Administrator","target":"sp-svc-reporting-01","src_ip":"45.83.X.X","asn":"hosting","mfa":false},
  {"ts":"2025-04-02T22:11:48Z","actor":"sp-svc-reporting-01","action":"Add app role assignment","app_role":"RoleManagement.ReadWrite.Directory","target":"app-attacker"},
  {"ts":"2025-04-02T22:12:55Z","actor":"app-attacker","action":"AddMemberToRole","role":"Global Administrator","target":"new-admin@corp.com"}
]
```

---

### 7. Investigation Steps

1. **Confirm the change is real.** Pull authoritative audit logs (not just SIEM-derived events) and verify the role/group/policy assignment.
2. **Validate authorization.** Was a change ticket / approval present? Cross-reference with change-management records.
3. **Profile the actor.** Recent sign-in risk, location, device compliance, MFA status, prior role-management activity.
4. **Profile the target.** Is the target identity newly created? A service principal? A dormant account?
5. **Reconstruct the chain.** Walk backwards: how did the actor obtain rights to make this change? Look for prior role assignments, app consents, token theft, or compromised admin endpoints.
6. **Hunt for parallel changes.** Privilege escalation rarely happens alone — look for additional accounts created, mailbox rules, persistence mechanisms, or new federation trusts.
7. **Validate with the actor** out-of-band before clearing.

---

### 8. False Positive Considerations

- Legitimate IAM operations from Just-in-Time (JIT) / PIM-style elevation tools.
- Onboarding workflows automatically granting roles.
- Service account permission changes during planned releases.
- Break-glass account use during incident response.
- IaC pipelines (Terraform / Pulumi / Bicep) applying drift or planned changes.
- Approved penetration tests.

---

### 9. Tuning Guidance

- Always-alert (no suppression) on a small set of **crown-jewel role assignments** (Global Admin, Domain Admin, root, Owner). Tune escalators, not the base alert.
- Integrate change-management records as a feature; auto-suppress when a matching approved change exists, but **flag** when the change ticket lacks the required approver.
- Differentiate **human actor** changes from **IaC/automation** changes; expect different baselines.
- Use **just-in-time** privilege solutions to make standing privileged assignments anomalous by definition — this is the highest-leverage tuning move available.
- For endpoint detections, baseline normal admin tooling and elevation paths to suppress IT helpdesk workflows; alert on novel parents and uncommon elevation primitives.

---

### 10. Response Actions

**Immediate**

- Revoke the elevated assignment if unauthorized; remove the target principal from the privileged role/group.
- Disable or rotate credentials for the actor account; revoke sessions and refresh tokens.
- For endpoints: isolate the host from the network; suspend the user session; collect memory and disk images.
- For cloud: rotate keys, disable the principal, and snapshot affected resources.

**Short-term**

- Audit all changes performed by the actor and the elevated target since the foothold.
- Roll back unauthorized policy/role/group/federation changes.
- Force credential reset and MFA re-registration for any account used in the chain.
- Sweep for persistence: scheduled tasks, services, cron, mailbox rules, new service principals, app registrations, OAuth grants.

**Long-term**

- Move to standing-zero / JIT privilege model for all administrative roles.
- Enforce phishing-resistant MFA on all privileged accounts.
- Tier administrative access (PAW / red-forest model) to break the path from user endpoint to admin plane.
- Continuous detection on identity admin actions; monitor for the same chain of techniques recurring.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Any unauthorized assignment to a tier-zero / crown-jewel role.
- Privilege change is part of an actor chain involving prior phishing, RCE, or credential theft.
- The change cannot be tied to an approved ticket within a short verification window.
- Federation trust, conditional access, or MFA policy was modified.
- Endpoint detection of UAC bypass / kernel exploit / token impersonation in active use.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Layer (identity / endpoint / cloud):
Actor Identity:
Target Identity / Resource:
Privilege Granted:
Authorization Reference (ticket / change):
Risk Features Observed (location, device, MFA, hosting ASN):
Foothold / Predecessor Activity:
Parallel Changes Discovered:
Containment Actions:
Rollback Actions:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Privilege escalation detection spans identity, endpoint, and cloud planes; no single rule covers it. The strongest signal is a chain (foothold, actor takeover, privileged role assignment, privileged action), and the strongest preventive control is just-in-time elevation, which makes any standing privilege change anomalous by definition. Always-alert on tier-zero changes and validate against change management before clearing.

---

*GreyNOC — detection-engineering-first security operations.*
