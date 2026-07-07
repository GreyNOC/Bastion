# CONVENTIONS

Shared reference for the GreyNOC AI · PQ · E2EE playbook collection. Cited values reflect
the standards landscape as of mid-2026; verify against current NIST / IETF publications
before operational use, because this space is still moving.

---

## 1. Algorithm reference

**Key encapsulation (KEM) — replaces RSA / ECDH key exchange**

| Standard | Name | Basis | Parameter sets | Notes |
| --- | --- | --- | --- | --- |
| FIPS 203 | ML-KEM (Kyber) | Module-LWE lattice | 512 / 768 / 1024 | Primary KEM. ML-KEM-768 ciphertext ~1088 B |
| (2026–27) | HQC | Code-based (quasi-cyclic) | TBD | Backup KEM selected Mar 2025; diversity hedge vs. lattice break |

**Signatures — replaces RSA / ECDSA / EdDSA**

| Standard | Name | Basis | Parameter sets | Notes |
| --- | --- | --- | --- | --- |
| FIPS 204 | ML-DSA (Dilithium) | Module-LWE/SIS lattice | 44 / 65 / 87 | **ML-DSA-65 is the recommended default.** Sig ~3309 B, pubkey ~1952 B |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based | many | Conservative backup; large sigs (~7.8–49.9 KB) |
| FIPS 206 | FN-DSA (Falcon) | NTRU lattice + FFT | — | Compact sigs (~666 B); sampling-sensitive, hardest to implement safely |
| SP 800-208 | LMS / XMSS | Hash-based, stateful | — | Use **now** for firmware/code-signing per NSA guidance |

**Security levels:** L1 ≈ AES-128, L3 ≈ AES-192, L5 ≈ AES-256. Grover halves symmetric
strength, so for long-retention data prefer **AES-256** and **SHA-384** over AES-128/SHA-256.

**Naming discipline.** Use standardized names (ML-KEM, ML-DSA, SLH-DSA, FN-DSA) in all
reports, tickets, and findings. Submission names (Kyber, Dilithium, SPHINCS+, Falcon) are
acceptable only as parenthetical aliases. Never use them alone in a compliance artifact.

---

## 2. Hybrid TLS named groups

Hybrid = classical + PQ KEM run together; an attacker must break **both** to recover the
session key. Watch for these in `ClientHello` / `ServerHello` `supported_groups` / `key_share`:

| NamedGroup | Value | Composition | Client key share |
| --- | --- | --- | --- |
| X25519MLKEM768 | `0x11EC` | X25519 + ML-KEM-768 | ~1216 B |
| SecP256r1MLKEM768 | (impl-specific) | P-256 + ML-KEM-768 | — |
| SecP384r1MLKEM1024 | (impl-specific) | P-384 + ML-KEM-1024 | — |

Production support: Chrome/BoringSSL, Firefox, Cloudflare, Akamai (default Feb 2026), AWS,
OpenSSL 3.5+ (native), wolfSSL, rustls, Botan. `oqs-provider` (liboqs) is the reference
experimentation provider and is **not** FIPS-validated — flag it if seen in a production path.

Quick manual check (read-only inspection of a host you are authorized to test):
```
openssl s_client -connect HOST:443 -groups X25519MLKEM768 -tls1_3 </dev/null 2>/dev/null \
  | grep -i "Negotiated\|group"
```

---

## 3. E2EE protocol reference

| System | PQ status | Construction | Notes |
| --- | --- | --- | --- |
| Signal PQXDH | PQ initial key establishment (Level 2) | X25519 + ML-KEM, Double Ratchet | Sept 2023; PQ at handshake only |
| iMessage PQ3 | PQ initial + ongoing rekey (Level 3) | hybrid ECDH + ML-KEM, periodic PQ rekey (~every 50 epochs) | Uses signatures over MAC; Secure Enclave signing |
| MLS (RFC 9420) | classical baseline; PQ ciphersuites emerging | TreeKEM group key agreement | Group E2EE; watch ciphersuite negotiation |

**Open problem to keep in scope:** PQ *authentication* ("Level 4") is not solved at scale by
PQXDH or PQ3 — both still authenticate with classical primitives. Key-transparency systems
(iMessage Contact Key Verification, WhatsApp Auditable Key Directory) are the current
mitigations against key-substitution MITM; monitoring them is a detection opportunity (PB-04).

---

## 4. MITRE mapping conventions

- **ATT&CK** technique IDs are referenced where an enterprise technique applies
  (e.g., T1040 Network Sniffing, T1557 Adversary-in-the-Middle, T1600 Weaken Encryption,
  T1556 Modify Authentication Process, T1110 Brute Force, T1552 Unsecured Credentials).
- **ATLAS** is referenced by tactic/technique *name* for AI-system techniques (e.g., training-
  data poisoning, prompt injection, model evasion). Map to the current ATLAS technique IDs in
  your platform at deployment time; IDs are versioned and change.
- Where no clean mapping exists (much PQ-migration-defect work is pre-ATT&CK), the playbook
  says so rather than forcing a tag.

---

## 5. Example-data conventions

- Network examples use **RFC 5737** (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
  and **RFC 3849** (`2001:db8::/32`) documentation address space.
- Identities, domains, and tokens in examples are illustrative and non-attributable.
- Detection logic is **JSON-shaped pseudocode**, not a SIEM query. Translate per platform.

---

## 6. Rules of engagement (binds Playbooks 07–08)

Authorized testing only. GreyNOC operates as the submitting firm under platform programs
(e.g., HackerOne / YesWeHack) or direct written engagement.

1. **No activity without scope on file.** A signed SOW or an in-scope, in-policy bug-bounty
   program is a precondition. Out-of-scope assets, third-party dependencies not named in
   scope, and chained pivots beyond the authorized boundary are prohibited.
2. **Least-impact testing.** Prefer read-only inspection (handshake/cert/token observation)
   over anything state-changing. No DoS, no data exfiltration beyond minimal proof, no
   persistence, no lateral movement unless explicitly authorized.
3. **No fabrication.** Every reported finding must be independently reproducible from the
   evidence in the report. No speculative severity, no invented impact, no copied CVE text
   passed off as original analysis. If you cannot reproduce it, it is not a finding.
4. **Data handling.** Capture the minimum proof necessary. Never retain third-party PII,
   secrets, or message plaintext beyond what the program permits; redact in reports.
5. **Coordinated disclosure.** Follow the program's disclosure timeline. Do not publicize
   before remediation/authorization.
6. **Stop conditions.** On encountering evidence of a prior real-world compromise, customer
   PII at rest, or anything outside scope — stop, preserve, and escalate to the program owner.

---

*GreyNOC — detection-engineering-first. Reproducible or it didn't happen.*
