# GreyNOC Security Playbook

## Phishing Detection & Response

---

### 1. Overview

Phishing is malicious email delivery designed to trick a user into surrendering credentials, executing a payload, or approving access. The current landscape spans credential-harvesting lures pointing at cloned login portals, malicious attachments and links, QR-code phishing (quishing) that shifts the click to an unmanaged mobile device, HTML smuggling that assembles payloads client-side to evade gateway inspection, and attacker-in-the-middle (AiTM) kits — Evilginx, EvilProxy, Tycoon 2FA — that proxy the real IdP login page, steal the session cookie, and bypass everything except phishing-resistant MFA.

Detection cannot stop at the gateway. A meaningful fraction of malicious mail is only identifiable *after* delivery — via user reports, post-click telemetry, and retro-hunting the mail store when new intel lands. Treat phishing as a pipeline problem: pre-delivery filtering, post-delivery hunting, and post-click identity monitoring are three distinct detection layers.

---

### 2. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Phishing | T1566 | Initial Access |
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access |
| Phishing: Spearphishing Link | T1566.002 | Initial Access |
| Phishing: Spearphishing via Service | T1566.003 | Initial Access |
| User Execution: Malicious Link | T1204.001 | Execution |
| User Execution: Malicious File | T1204.002 | Execution |
| Steal Web Session Cookie | T1539 | Credential Access |

---

### 3. Detection Strategy

No single control sees the whole kill chain; correlate mail, web, endpoint, and identity telemetry.

- Gateway-layer signals: authentication failures (SPF/DKIM/DMARC), newly registered sender domains, lookalike domains against your own brand, reply-to mismatch, and burst delivery of a common template to many recipients.
- Link-layer signals: URLs behind open redirects, URL shorteners, legitimate-service abuse (SharePoint, Google Docs, Cloudflare Workers, IPFS gateways), and QR codes embedded in image-only bodies or PDF attachments.
- Payload-layer signals: HTML/SVG attachments containing JavaScript that decodes an embedded blob (HTML smuggling), archive-within-archive attachments, LNK/ISO/IMG containers.
- Post-click identity signals: the strongest AiTM detection is not the email — it is a successful sign-in with valid MFA from an unfamiliar IP/ASN minutes after a link click, followed by session-token reuse from a second IP.
- Post-delivery: treat every user report as a hunt trigger, and every new IOC (sender, URL, hash) as a retro-hunt query against delivered mail for the prior 14–30 days.

---

### 4. Key Indicators

- Sender domain registered < 30 days ago, or a lookalike of the org's domain (`corp-com[.]help`, `c0rp.com` homoglyphs).
- SPF/DKIM/DMARC composite failure combined with a display name matching an internal executive or vendor.
- Same subject/template delivered to many recipients in a short burst, especially cross-department.
- URLs that resolve through open redirects or shorteners to a page presenting an IdP-branded login form on a non-IdP domain.
- HTML or SVG attachment with embedded `atob`/`Blob`/`msSaveBlob` logic (HTML smuggling) — payload never traverses the gateway as a file.
- Image-only email body or PDF attachment whose only actionable content is a QR code.
- Sign-in from a new IP/ASN within minutes of a recorded link click, MFA satisfied, followed by activity from a different IP on the same session token (AiTM cookie replay).
- Immediate post-login mailbox rule creation, MFA method registration, or OAuth consent from the new session.
- Cluster of user reports referencing the same sender, subject, or landing domain.

---

### 5. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Phishing - Suspicious Delivery Cluster with Post-Click Identity Risk",
  "description": "Detects burst delivery of suspicious mail (auth failures, young sender domain, or smuggling-capable attachment) and escalates when a recipient click is followed by anomalous sign-in consistent with AiTM session theft.",
  "data_source": ["EmailGateway.MessageTrace", "EmailGateway.URLClicks", "AzureAD.SignInLogs", "Proxy.WebLogs"],
  "logic": {
    "window": "60m",
    "group_by": ["sender_domain", "subject_template_hash"],
    "where": {
      "direction": "inbound",
      "any_of": [
        "auth_result in ['spf_fail','dkim_fail','dmarc_fail']",
        "sender_domain_age_days < 30",
        "attachment_type in ['html','svg','iso','img','lnk'] or attachment_contains_qr == true",
        "url_final_destination.category in ['newly_registered','uncategorized','ip_literal']"
      ]
    },
    "having": {
      "distinct_recipients_gte": 5
    },
    "escalate_if_any": [
      "click_event.recipient_count >= 1",
      "signin.new_asn_within_minutes_of_click <= 15",
      "session.token_reused_from_second_ip == true",
      "post_login.mailbox_rule_created or post_login.mfa_method_added"
    ]
  },
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1566", "T1566.001", "T1566.002", "T1566.003", "T1204.001", "T1204.002", "T1539", "initial_access", "identity"]
}
```

---

### 6. Example Event Data

```json
[
  {"ts":"2025-06-18T13:02:11Z","event":"delivery","sender":"it-support@corp-verify[.]help","recipient":"k.olsen@corp.com","subject":"Action Required: MFA Re-Enrollment","auth":"dmarc_fail","attachment":"none","url":"https://sso-corp-com[.]login-portal[.]help/auth","sender_domain_age_days":6},
  {"ts":"2025-06-18T13:02:14Z","event":"delivery","sender":"it-support@corp-verify[.]help","recipient":"d.mensah@corp.com","subject":"Action Required: MFA Re-Enrollment","auth":"dmarc_fail","attachment":"invoice.html","note":"HTML contains base64 blob + atob() decoder"},
  {"ts":"2025-06-18T13:09:47Z","event":"url_click","user":"k.olsen@corp.com","src_ip":"10.22.4.81","url":"https://sso-corp-com[.]login-portal[.]help/auth"},
  {"ts":"2025-06-18T13:12:03Z","event":"signin","user":"k.olsen@corp.com","src_ip":"203.0.113.54","asn":"hosting","result":"success","mfa":"satisfied","note":"first-seen ASN for user"},
  {"ts":"2025-06-18T13:19:40Z","event":"mailbox_rule_created","user":"k.olsen@corp.com","src_ip":"198.51.100.19","rule":"delete if subject contains 'invoice' -> RSS Feeds"}
]
```

---

### 7. Investigation Steps

1. **Scope the campaign.** Pivot on sender domain, sending IP, subject template, URL, and attachment hash across message trace. Enumerate every recipient, delivered vs. blocked.
2. **Detonate the lure.** Analyze the URL/attachment in a sandbox. Identify the final landing page, whether it proxies the real IdP (AiTM), and what it harvests. Decode HTML-smuggled payloads and extract dropped-file hashes.
3. **Identify who clicked.** Correlate gateway click telemetry, proxy logs, and DNS against the landing domain. QR lures require mobile/VPN egress logs — corporate telemetry often misses the click entirely.
4. **Identify who submitted.** For each clicker, review sign-in logs for the following 60 minutes: new IP/ASN, impossible travel, token issuance. For AiTM, MFA satisfied does **not** clear the user.
5. **Check for session-token theft.** Look for the same session/refresh token used from a second IP, or sign-ins with no corresponding MFA prompt on record.
6. **Review post-compromise actions.** Mailbox rules, MFA method registration, OAuth consents, device joins, internal phishing sent from the compromised mailbox.
7. **Retro-hunt.** Run every extracted IOC against delivered mail for the prior 30 days; earlier waves of the same campaign frequently precede the reported one.

---

### 8. False Positive Considerations

- Legitimate marketing/bulk senders with broken SPF/DKIM after an ESP migration.
- Internal phishing simulations and red-team exercises.
- Newly registered domains belonging to genuinely new vendors or event registrars.
- Security tools and mail-client link-preview services generating "clicks" the user never made.
- Legitimate QR codes in vendor invoices, event tickets, and MFA-enrollment mail.
- Users signing in from new ASNs due to travel or VPN changes coinciding with unrelated mail.

---

### 9. Tuning Guidance

- Anchor the delivery cluster on `subject_template_hash` + sender domain, not exact subject — campaign kits rotate tokens (recipient name, invoice number) within a template.
- Weight composite auth failure (SPF **and** DKIM **and** DMARC) far above single-check failure; single failures are endemic in legitimate bulk mail.
- Maintain a lookalike-domain watch (dnstwist-style permutations of your brand and top vendors) and score any match as an escalator, not a standalone alert.
- Suppress known link-scanner and sandbox IP ranges from "click" logic so pre-fetch does not count as user interaction.
- For the post-click sign-in join, keep the click-to-signin window tight (≤ 15m) and require ASN novelty; loosening either dimension floods the queue with travelers.
- Feed confirmed campaign IOCs back as retro-hunt saved searches with a 30-day lookback, run automatically on intel ingestion.

---

### 10. Response Actions

**Immediate**

- Purge/quarantine the campaign from all mailboxes (delivered, junk, and deleted items).
- Block sender domain, sending infrastructure, and landing URLs at gateway, proxy, and DNS.
- For any user who submitted credentials or shows AiTM indicators: revoke **all** sessions and refresh tokens, reset the password, and re-verify MFA methods. Token revocation is the critical step — a password reset alone does not kill a stolen session.

**Short-term**

- Remove attacker artifacts: mailbox rules, rogue MFA methods, OAuth consents, joined devices.
- Notify all recipients; confirm with clickers whether credentials were entered (assume yes for AiTM landing pages).
- Sweep endpoints of users who opened smuggled attachments for dropped payloads and persistence.
- Retro-hunt all campaign IOCs across the prior 30 days of delivered mail and close the loop on earlier waves.

**Long-term**

- Deploy phishing-resistant MFA (FIDO2 / passkeys) — the only MFA that survives AiTM proxying.
- Enforce conditional access with token protection / compliant-device binding to blunt stolen-cookie replay.
- Block or detonate high-risk attachment types (HTML, SVG, ISO, IMG, LNK) at the gateway.
- Keep the user-report button frictionless and measure report-to-purge time as a SOC KPI.

---

### 11. Escalation Criteria

Escalate to incident when **any** of the following are true:

- Any user submitted credentials to a confirmed harvesting or AiTM page.
- Session-token replay is observed (same token, second IP, or MFA-less sign-in after click).
- Post-compromise activity exists: mailbox rule, new MFA method, OAuth consent, or internal phishing sent from a victim mailbox.
- A smuggled or attached payload executed on an endpoint.
- The campaign targets privileged users (admins, finance, executives) or shows org-specific spearphishing content.

---

### 12. Analyst Notes Template

```
Incident ID:
Detection Rule / Report Source:
Detected At:
Sender Domain / IP / Auth Results:
Subject Template / Lure Type (cred-harvest / attachment / QR / AiTM / smuggling):
Landing Domain / Final URL:
Recipients (delivered / blocked):
Clickers:
Credential Submissions (confirmed / assumed):
AiTM / Token Replay Observed:
Post-Compromise Activity:
Retro-Hunt Findings (prior waves):
Containment Actions (purge / block / revoke):
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 13. Summary

Phishing detection is a three-layer pipeline: filter at delivery, hunt after delivery, and monitor identity after the click. The highest-value signal is the join between mail and identity telemetry — a click followed within minutes by a first-seen-ASN sign-in with MFA satisfied is AiTM until disproven, and the response is token revocation, not just a password reset. Treat user reports and new intel as retro-hunt triggers; the reported message is rarely the first wave.

---

*GreyNOC — detection-engineering-first security operations.*
