# GreyNOC Security Playbooks

Production-grade detection, response, and authorized-testing playbooks authored by the GreyNOC detection-engineering team. The library spans two complementary collections:

- **Detection & Response** — behavior-based SOC playbooks across the intrusion lifecycle, from initial access to impact.
- **AI · Post-Quantum · E2EE** — playbooks re-centered on the cryptographic transition: post-quantum (PQ) migration, end-to-end-encrypted (E2EE) protocol security, and AI-augmented detection, plus two dedicated to authorized bug-bounty methodology against PQ/E2EE attack surface.

Every playbook follows the same GreyNOC structure: overview, MITRE ATT&CK / ATLAS mapping, detection strategy, indicators, sample logic, example data, investigation steps, false positives, tuning, response actions, escalation criteria, an analyst-notes template, and a closing summary. Written for SOC analysts, IR, detection engineers, and authorized offensive operators. Behavior-based over signature-based; operational clarity over theory.

> **Why the crypto collection.** NIST finalized the first PQ standards in August 2024 (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), with FN-DSA (FIPS 206) and the HQC backup KEM following. Hybrid TLS (`X25519MLKEM768`, NamedGroup `0x11EC`) is now default or near-default across Chrome, Firefox, Cloudflare, Akamai, and AWS, and E2EE messengers (Signal PQXDH, iMessage PQ3) ship PQ key establishment in production. The window where "crypto detection" meant "expired certs and weak ciphers" is closed. The dominant risk is now **harvest-now-decrypt-later (HNDL)**, **downgrade of hybrid handshakes**, and **migration-defect classes** introduced while organizations swap primitives under deadline.

A visual index of the detection & response collection is available in [index.html](index.html).

---

## Detection & Response Playbooks

| # | Playbook | Focus |
|---|----------|-------|
| 01 | [Password Spraying](01-password-spraying.md) | Distributed credential access against IdPs |
| 02 | [Brute Force Attack](02-brute-force.md) | Single-target authentication abuse |
| 03 | [Distributed Port Scan](03-distributed-port-scan.md) | Multi-source coordinated reconnaissance |
| 04 | [Credential Stuffing](04-credential-stuffing.md) | Leaked-credential replay against web/SaaS |
| 05 | [Impossible Travel](05-impossible-travel.md) | Geographic velocity + risk-feature composite |
| 06 | [Privilege Escalation](06-privilege-escalation.md) | Identity, endpoint, and cloud elevation |
| 07 | [Suspicious PowerShell Execution](07-suspicious-powershell.md) | Encoded, in-memory, and parented PowerShell abuse |
| 08 | [Malware Beaconing](08-malware-beaconing.md) | Periodic C2 traffic detection |
| 09 | [AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md) | Adversary automation and owned-AI-feature abuse |
| 10 | [Coordinated Multi-Stage Attack](10-coordinated-multi-stage-attack.md) | Kill-chain correlation across entities |
| 11 | [Phishing](11-phishing.md) | Malicious email delivery, AiTM/MFA-bypass, retro-hunting |
| 12 | [Business Email Compromise](12-business-email-compromise.md) | Post-compromise mailbox rules, forwarding, OAuth abuse |
| 13 | [Lateral Movement](13-lateral-movement.md) | Host-to-host propagation and authentication-edge anomalies |
| 14 | [Active Directory Credential Theft](14-ad-credential-theft.md) | Kerberoasting, DCSync, LSASS dumping, ticket forgery |
| 15 | [Persistence Mechanisms](15-persistence-mechanisms.md) | Tasks, services, run keys, WMI subscriptions, rogue accounts |
| 16 | [Web Shell](16-web-shell.md) | Post-exploitation implants in the webroot |
| 17 | [Data Exfiltration](17-data-exfiltration.md) | Staging and egress anomalies to cloud, C2, and alt protocols |
| 18 | [Ransomware](18-ransomware.md) | Recovery-inhibition precursors and mass-encryption impact |

---

## AI · Post-Quantum · E2EE Playbooks

| #  | Playbook | Focus |
| --- | --- | --- |
| 01 | [Cryptographic Inventory & PQC Readiness](01-cryptographic-inventory-pqc-readiness.md) | CBOM discovery, AI/LLM-assisted code auditing, crypto-agility scoring |
| 02 | [Harvest-Now-Decrypt-Later Exposure](02-harvest-now-decrypt-later.md) | Bulk-capture detection, long-shelf-life data prioritization |
| 03 | [Hybrid TLS / KEM Downgrade](03-hybrid-tls-kem-downgrade.md) | PQ key-exchange stripping, negotiation downgrade, middlebox tampering |
| 04 | [E2EE Messaging Protocol Security](04-e2ee-messaging-protocol-security.md) | Double Ratchet / PQXDH / PQ3 / MLS, key-transparency & MITM detection |
| 05 | [PQ Signature & Token Integrity](05-pq-signature-token-integrity.md) | ML-DSA / SLH-DSA / FN-DSA, JWT/SAML/X.509, algorithm-confusion |
| 06 | [AI-Augmented Detection & Guardrails](06-ai-augmented-detection-guardrails.md) | LLM-assisted triage, pipeline poisoning & prompt-injection defense (ATLAS) |
| 07 | [Bug Bounty: PQC/E2EE Methodology](07-bugbounty-pqc-e2ee-methodology.md) | Authorized recon → crypto-surface mapping → validation → reporting |
| 08 | [Bug Bounty: Crypto Implementation Defects](08-bugbounty-crypto-implementation-defects.md) | Authorized hunting of migration/downgrade/oracle defect classes |
| 09 | [Post-Quantum VPN, IPsec & SSH Migration](09-pq-vpn-ipsec-ssh.md) | Hybrid KEX for IKEv2/IPsec, OpenSSH, WireGuard; tunnel downgrade detection |
| 10 | [Post-Quantum PKI & Certificate Lifecycle](10-pq-pki-certificate-lifecycle.md) | ML-DSA CA hierarchies, composite certs, CT mis-issuance, PQ-scale revocation |
| 11 | [Post-Quantum Code Signing & Firmware Integrity](11-pq-code-signing-firmware.md) | LMS/XMSS firmware & ML-DSA supply-chain signing; stateful-key hazards |
| 12 | [Post-Quantum E2EE for Real-Time Media](12-pq-e2ee-realtime-media.md) | WebRTC/DTLS-SRTP, SFrame, MLS calls; downgrade & ghost-participant detection |
| 13 | [Crypto-Agility & PQ Migration Operations](13-crypto-agility-migration-ops.md) | Agility architecture, wave rollout, rollback gates, algorithm-break runbook |
| 14 | [Quantum Risk Governance & Compliance](14-quantum-risk-governance.md) | Mosca's inequality, CNSA 2.0 / NSM-10 mandates, evidence-backed reporting |

See [CONVENTIONS.md](CONVENTIONS.md) for shared algorithm reference, named groups, documentation address space, and **rules of engagement** that bind the bug-bounty playbooks (crypto collection 07–08).

---

## How to Use

1. Read the playbook end-to-end before deploying any rule.
2. Map data sources to your environment; verify telemetry sufficiency before relying on a detection. PQ/E2EE detection in particular depends on handshake- and key-level visibility that many estates do not yet log — confirm you have it before trusting the absence of alerts.
3. Translate the JSON-shaped sample logic to your platform (KQL, SPL, EQL, Sigma, etc.); validate on historical data where possible.
4. Adopt the analyst-notes template into your case-management workflow.
5. For the bug-bounty playbooks (crypto collection 07–08), do not begin any activity without a signed authorization / program scope on file. GreyNOC operates as the submitting firm; ROE in CONVENTIONS is mandatory.
6. Revisit tuning after every confirmed true positive and false positive.

---

*GreyNOC — detection-engineering-first security operations. No fabrication: every finding, indicator, and report artifact must be reproducible from evidence.*
