# 04 — E2EE Messaging Protocol Security (Double Ratchet / PQXDH / PQ3 / MLS)

## Overview

End-to-end-encrypted messaging is now post-quantum at the key-establishment layer in
production systems: Signal's **PQXDH** (hybrid X25519 + ML-KEM, Double Ratchet, Level 2) and
Apple iMessage **PQ3** (hybrid ECDH + ML-KEM with periodic PQ rekeying, Level 3). Group E2EE
via **MLS (RFC 9420)** is adding PQ ciphersuites. But a critical gap remains: **post-quantum
authentication ("Level 4") is not solved at scale** — PQXDH and PQ3 still authenticate with
classical primitives, which means **key-substitution MITM** is the durable attack class. This
playbook focuses on detecting that class via **key-transparency monitoring** and protocol-
negotiation anomalies, applicable whether you operate an E2EE service or defend users of one.

## MITRE mapping

- **T1557** — Adversary-in-the-Middle (key substitution / identity-key swap).
- **T1556** — Modify Authentication Process (subverting the trust/verification step).
- **T1606** — Forge Web Credentials / trust material (forged key bundles in a directory).
- **T1600** — Weaken Encryption (forcing a non-PQ or weaker ciphersuite in negotiation).

## Detection strategy

The cryptography is sound; the **trust distribution** is where attacks live. Three detectors:

1. **Key-transparency / directory monitoring.** E2EE security depends on getting the *right*
   public identity key. Monitor the key directory (or transparency log: iMessage Contact Key
   Verification, WhatsApp Auditable Key Directory style) for unexpected key changes, split-view
   inconsistencies, and unverifiable insertions. A silent identity-key change is the MITM tell.
2. **Safety-number / contact-key verification anomalies.** Spikes in safety-number changes,
   re-verification prompts, or "key changed" events — especially correlated across many users
   or targeting high-value identities — indicate substitution attempts or directory tampering.
3. **Protocol/ciphersuite negotiation downgrade.** Sessions negotiating non-PQ or weaker
   ciphersuites where PQ is supported; absence of expected PQ rekeying (PQ3 mixes a PQ key
   periodically — its disappearance is a signal); MLS ciphersuite downgrade in group joins.

## Indicators

- Identity public key for a contact changes without a corresponding device-add/reinstall event.
- Transparency-log split view: two observers see different directory state for the same identity
  (a hallmark of targeted MITM).
- Burst of safety-number/contact-key-verification changes across users or against a VIP cohort.
- Sessions falling back to classical-only handshake where the platform supports PQXDH/PQ3.
- PQ3-style periodic PQ rekeying not occurring on long-lived sessions that should rekey.
- New "device" added to an account from an anomalous location/time just before a key change.
- MLS group: a join/commit that downgrades the negotiated ciphersuite or adds an unexpected
  member with elevated tree position.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "identity_key_substitution",
  "trigger": {
    "event": "identity_key_changed",
    "without": ["device_add", "app_reinstall", "user_initiated_reset"],
    "scope": "single_identity OR cohort"
  },
  "amplify_if": {
    "identity.is_high_value": true,
    "transparency_log.split_view_detected": true,
    "geo_or_device.anomalous": true
  },
  "severity": "base=medium; high if amplify_if any true",
  "enrich": ["identity", "old_key_fp", "new_key_fp", "log_inclusion_proof_ref"]
}
```

```json
{
  "rule": "e2ee_pq_negotiation_downgrade",
  "trigger": {
    "platform_supports": "PQXDH | PQ3 | MLS-PQ-suite",
    "session_negotiated": "classical_only OR weaker_suite"
  },
  "or": "expected_pq_rekey_missing(session.age > rekey_interval)",
  "severity": "medium",
  "note": "key cryptography fine; trust/negotiation is the target"
}
```

## Example data

```json
{ "ts": "2026-06-27T09:41Z", "identity": "vip-user-7", "event": "identity_key_changed",
  "device_add": false, "reinstall": false, "transparency_split_view": true,
  "old_key_fp": "AA:BB:..", "new_key_fp": "C1:D2:..",
  "verdict": "high: unexplained VIP identity-key change with directory split view (MITM)" }
```

## Investigation steps

1. Correlate the key change with legitimate triggers: new device, reinstall, account recovery.
   The overwhelming majority of key changes are benign device churn — rule that out first.
2. Pull the transparency-log inclusion proof / consistency proof for the new key. A key that
   cannot be proven consistently included for all observers is the strong signal.
3. For cohort spikes, look for a common vector (a compromised directory component, a pushed
   config, a single source IP behind the changes).
4. Verify out-of-band where possible (the entire point of safety numbers / contact-key
   verification is an out-of-band channel). For VIP identities, do this actively.
5. For negotiation downgrades, identify whether client capability, server policy, or in-path
   manipulation caused the fallback (mirror PB-03's offered-vs-negotiated logic).

## False positives

- Device adds, reinstalls, OS migrations, and account recovery legitimately rotate identity
  keys — these are the dominant cause of "key changed" events. Require the *absence* of a
  legitimate trigger before escalating.
- Users with multiple devices generate frequent, benign key-verification prompts.
- Planned ciphersuite changes during a platform rollout.

## Tuning

- Baseline per-identity key-change frequency; alert on changes that lack a paired legitimate
  trigger, not on changes per se.
- Weight high-value identities (executives, journalists, IR responders, signing identities)
  far higher — targeted MITM goes after specific people, not the population.
- Tune at the correlation layer (change + no-trigger + log-inconsistency + anomaly), never by
  silencing key-change telemetry — that telemetry *is* the MITM detector.

## Response actions

- Suspected substitution: force out-of-band re-verification, invalidate the suspect key, and
  for service operators, freeze and audit the affected directory entries and their inclusion proofs.
- Directory/transparency-log integrity failure (split view) → treat as a service-side compromise:
  preserve log state, rotate signing keys for the directory, and notify affected identities.
- Negotiation downgrade: restore/enforce PQ ciphersuite policy; investigate the in-path cause.

## Escalation criteria

- Any transparency-log split-view or unprovable key insertion → incident escalation (directory
  integrity is the trust root for the whole system).
- Targeted, unexplained identity-key change against a high-value identity → incident + protective
  out-of-band verification for that individual.

## Analyst notes (template)

```
E2EE-ID:            E2EE-____
Identity / VIP?:    ____ / Y/N
Event:              key-change | verif-spike | negotiation-downgrade | rekey-missing
Legit trigger?:     device-add | reinstall | recovery | NONE
Transparency proof: included-consistent | split-view | unprovable
Old/new key fp:     ____ / ____
Out-of-band verif:  done? result ____
Classification:     benign-churn | substitution-MITM | directory-compromise | downgrade
Disposition:        ____
```

## Summary

In modern E2EE the math is the strong part; the **trust distribution** is the soft target,
and PQ authentication is still unsolved at scale. Monitor the key directory / transparency log
for unexplained identity-key changes and split views, watch for verification-event spikes
against high-value identities, and detect PQ-negotiation downgrades the same way you do for TLS.
Out-of-band verification remains the decisive control — instrument it and act on its anomalies.
