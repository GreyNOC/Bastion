# GreyNOC Security Playbook

## Business Email Compromise Detection & Response

---

### 1. Overview

Business email compromise (BEC) is the post-authentication abuse of a legitimate cloud mailbox. The attacker holds valid credentials or a stolen session token (usually from AiTM phishing or password spraying) and operates entirely inside M365 or Google Workspace using sanctioned features: inbox rules that hide or forward mail, external auto-forwarding, delegate and SendAs permission grants, and OAuth application consents for persistent mailbox access. The end goal is almost always financial — hijacking an existing invoice thread to redirect a payment, or spearphishing internal targets and downstream vendors from the trusted mailbox.

Nothing in the kill chain triggers malware telemetry. Every action is a legitimate API operation, so detection lives in the identity and mailbox audit planes: the M365 Unified Audit Log, Exchange mailbox audit, Entra ID audit/sign-in logs, and Google Workspace admin/user log events.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Email Collection: Remote Email Collection | T1114.002 | Collection |
| Email Collection: Email Forwarding Rule | T1114.003 | Collection |
| Hide Artifacts: Email Hiding Rules | T1564.008 | Defense Evasion |
| Account Manipulation: Additional Email Delegate Permissions | T1098.002 | Persistence |
| Steal Application Access Token | T1528 | Credential Access |
| Internal Spearphishing | T1534 | Lateral Movement |
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access / Persistence |

---

### 3. Detection Strategy

The mailbox operations are authorized by design; the signal is configuration change plus session context.

- Alert on mailbox-manipulation operations: `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Set-Mailbox` (forwarding parameters), `Add-MailboxPermission`, `Add-RecipientPermission` in the UAL; Gmail filter creation and out-of-domain forwarding in Workspace user log events.
- Classify rule intent, not just rule creation: external forward/redirect actions, `DeleteMessage`, `MarkAsRead` + move, and moves to low-visibility folders (RSS Subscriptions, RSS Feeds, Conversation History, Notes, Archive) are attacker patterns.
- Watch OAuth consent grants ("Consent to application") for mail-scope permissions (`Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `offline_access`) — token-based collection survives password resets.
- Join every configuration change to its sign-in session. A rule created from a hosting ASN, new geography, or unfamiliar user-agent minutes after login is the pivot signal.
- Use `MailItemsAccessed` (E5 / mailbox audit) to detect bulk mailbox sync from a new client — remote collection often precedes rule creation.
- For internal spearphishing, watch for one mailbox sending an unusual burst of internal mail with identical subject/attachment, and for lookalike-domain participants appearing inside existing threads.

---

### 4. Key Indicators

- Inbox rule that forwards or redirects to an external address, deletes messages, or marks-as-read and moves them out of the Inbox.
- Rule names that are single punctuation characters (`.`, `,`, `..`) or empty — attackers minimize visibility in rule lists.
- Rule conditions keyed on finance vocabulary: `invoice`, `payment`, `wire`, `ACH`, `remittance`, `bank`, `statement`, or on the security team's domain.
- `ForwardingSmtpAddress` set to a free-webmail or newly registered domain; Gmail auto-forward verification mail followed by enablement.
- New FullAccess delegate or SendAs permission added outside of HR/IT provisioning workflows.
- OAuth consent to an unverified-publisher app requesting mail read/write/send with `offline_access`.
- `MailItemsAccessed` volume spike or full-mailbox sync from a client/IP never seen for the user.
- Vendor or executive lookalike domain (e.g., `corp-payments[.]com` vs `corp.com`) replying mid-thread with changed banking details.
- Rule creation within minutes of a sign-in from an anomalous ASN/geo/user-agent for that account.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "BEC - Mailbox Manipulation From Anomalous Session",
  "description": "Detects inbox rule creation, forwarding configuration, delegate additions, or mail-scope OAuth consents, escalating when rule intent is evasive or the acting session context is novel for the user.",
  "data_source": ["M365.UnifiedAuditLog", "Exchange.MailboxAuditLog", "EntraID.AuditLogs", "EntraID.SignInLogs", "GoogleWorkspace.UserLogEvents", "GoogleWorkspace.AdminAudit"],
  "logic": {
    "window": "24h",
    "group_by": ["user", "src_ip"],
    "where": {
      "operation_in": [
        "New-InboxRule",
        "Set-InboxRule",
        "UpdateInboxRules",
        "Set-Mailbox",
        "Add-MailboxPermission",
        "Add-RecipientPermission",
        "Consent to application",
        "email_forwarding_out_of_domain",
        "gmail_filter_created"
      ]
    },
    "having": {
      "config_change_count_gte": 1
    },
    "escalate_if_any": [
      "rule.forward_to_domain not in org_domains",
      "rule.actions contains_any ['DeleteMessage', 'MarkAsRead']",
      "rule.move_to_folder in ['RSS Subscriptions', 'RSS Feeds', 'Conversation History', 'Notes', 'Archive']",
      "length(rule.name) <= 2",
      "mailbox.forwarding_smtp_domain not in org_domains",
      "oauth.scopes contains_any ['Mail.ReadWrite', 'Mail.Send'] and oauth.publisher_verified == false",
      "session.asn not in user_baseline_asns or session.geo_novel == true",
      "delegate.added_outside_provisioning_window == true"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1114.002", "T1114.003", "T1564.008", "T1098.002", "T1528", "T1534", "T1078.004", "collection", "defense_evasion", "identity"]
}
```

---

### 6. Example Event Data

```
Unified Audit Log (abridged)
{"CreationTime":"2025-06-18T07:42:11Z","Operation":"New-InboxRule","UserId":"k.osei@corp.com","ClientIP":"203.0.113.54","Parameters":{"Name":",","From":"billing@vendor-invoices[.]net","MoveToFolder":"RSS Subscriptions","MarkAsRead":"True"}}
{"CreationTime":"2025-06-18T07:44:03Z","Operation":"Set-Mailbox","UserId":"k.osei@corp.com","ClientIP":"203.0.113.54","Parameters":{"ForwardingSmtpAddress":"smtp:k.osei.archive@freemail-relay[.]com","DeliverToMailboxAndForward":"True"}}
{"CreationTime":"2025-06-18T07:51:47Z","Operation":"Consent to application","UserId":"k.osei@corp.com","ClientIP":"198.51.100.23","AppDisplayName":"Mail Sync Utility","Scopes":"Mail.ReadWrite Mail.Send offline_access","PublisherVerified":"false"}

Sign-in context
2025-06-18T07:39:20Z  k.osei@corp.com  203.0.113.54  (hosting ASN, first seen for user; UA "Chrome 125 / Windows")
Baseline: user signs in exclusively from 192.0.2.0/24 corporate egress, mobile carrier ASN.
```

---

### 7. Investigation Steps

1. **Reconstruct the session.** Pull all sign-ins for the user around the configuration change. Confirm whether the acting IP/UA/ASN matches the user's baseline or an AiTM/token-replay pattern.
2. **Enumerate mailbox configuration.** Dump all inbox rules, forwarding settings (`ForwardingSmtpAddress`, `DeliverToMailboxAndForward`), delegates, and SendAs grants — not just the alerted change.
3. **Scope the collection.** Query `MailItemsAccessed` and Gmail access logs for the suspicious session: which folders, how many items, sync vs bind. Determine what the attacker read or exported.
4. **Review OAuth grants.** List service principals with mail scopes consented by the user; check publisher verification, consent time, and token activity since grant.
5. **Hunt for outbound abuse.** Search sent items and message trace for internal spearphish, replies on invoice threads, payment-detail changes, and mail to lookalike domains.
6. **Sweep the tenant.** Run the same rule/forwarding/consent queries across all mailboxes — BEC actors reuse infrastructure and hit multiple accounts per tenant.
7. **Trace the money.** If a payment thread was touched, involve finance immediately: identify any changed banking details, pending wires, and vendors contacted from the mailbox.

---

### 8. False Positive Considerations

- Users legitimately forwarding to personal mail — a policy violation, not necessarily compromise; session context disambiguates.
- Executive assistants and shared-mailbox workflows creating rules and delegate grants routinely.
- IT/HR provisioning that adds FullAccess or SendAs during onboarding, offboarding, or litigation hold.
- Legitimate mail clients and MDM enrollments generating OAuth consents with mail scopes (Apple Mail, eM Client, mobile apps).
- Power Automate / Apps Script flows that programmatically move or forward mail.
- Migration and archiving tools producing bulk `MailItemsAccessed` volumes.

---

### 9. Tuning Guidance

- Alert on **any** external auto-forward regardless of session context — tenants should disallow it by policy, making every hit actionable.
- Score rule intent: external forward + delete + hidden folder in one rule warrants immediate high severity; a simple move-to-folder rule from a baseline session does not.
- Maintain an allowlist of verified-publisher OAuth apps; alert on first-seen app IDs tenant-wide, not per-user.
- Baseline delegate additions against provisioning windows and ticketing data; escalate grants with no matching change record.
- Ensure mailbox auditing is enabled for all mailboxes (default since 2019 in M365, but verify — high-value mailboxes are sometimes excluded) and confirm `MailItemsAccessed` licensing coverage.
- Enrich every mailbox-config event with sign-in risk, ASN type, and impossible-travel flags at detection time rather than during triage.

---

### 10. Response Actions

**Immediate**

- Revoke all sessions and refresh tokens for the account; reset the password and re-verify MFA methods.
- Remove malicious inbox rules, forwarding settings, delegates, and SendAs grants.
- Disable the consented OAuth application's service principal and revoke its tokens.
- Block the attacker infrastructure (IPs, lookalike domains) at the identity provider and mail gateway.

**Short-term**

- Sweep and remediate the same indicators across every mailbox in the tenant.
- Use `MailItemsAccessed` to build a definitive list of exposed messages; assess regulatory/notification obligations.
- Recall or purge internal spearphish; warn recipients and any targeted vendors/customers out-of-band.
- Freeze pending payments touched by the mailbox and verify banking details with vendors by phone.

**Long-term**

- Disable external auto-forwarding tenant-wide; require exception approval.
- Restrict user OAuth consent to verified publishers and admin-approved scopes.
- Deploy phishing-resistant MFA (FIDO2/passkeys) for finance, executives, and admins to cut off the AiTM entry point.
- Institute out-of-band verification for all payment and banking-detail changes.
- Register or monitor lookalike domains for the org and top vendors.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- An external forwarding rule or mailbox forwarding address is confirmed attacker-created.
- The affected mailbox belongs to finance, accounts payable, an executive, or their assistants.
- Evidence of thread hijacking, payment-detail manipulation, or an actual fraudulent transfer exists.
- A mail-scope OAuth grant to an unverified application is confirmed and has active token usage.
- Internal spearphishing was sent from the compromised mailbox.
- `MailItemsAccessed` shows bulk collection or full-mailbox sync by the attacker session.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule:
Detected At:
Mailbox / User:
Attacker Session (IP / ASN / Geo / UA):
Initial Access Vector (suspected):
Inbox Rules Created (names / actions):
Forwarding Configured (destination):
Delegates / SendAs Added:
OAuth Grants (app / scopes / publisher):
Mail Accessed / Exfiltrated (scope):
Internal Spearphish Sent (yes/no):
Payment Threads Affected:
Financial Loss (confirmed / at risk):
Containment Actions:
Tenant Sweep Findings:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

BEC produces no malware artifacts — the entire intrusion is legitimate mailbox operations performed by an illegitimate session. Detection hinges on joining mailbox configuration changes (rules, forwarding, delegates, OAuth consents) to sign-in context, and on classifying rule intent: external forward, delete, and hidden-folder moves are attacker grammar. Treat any confirmed hit as a financial incident, not an IT incident — sweep the tenant, scope the collection with mailbox audit, and get finance verifying payments before the wire clears.

---

*GreyNOC — detection-engineering-first security operations.*
