# 10 — Post-Quantum PKI & Certificate Lifecycle

## Overview

A PKI is only as quantum-safe as its longest-lived signature. Roots and intermediates sign
for decades; a root issued today with RSA or ECDSA is a standing HNDL liability the moment a
cryptographically relevant quantum computer exists. Migration therefore runs **top-down**:
roots go PQ first (they outlive everything below them), then intermediates, then leaf certs —
which short-lived, automated issuance can rotate cheaply. This playbook covers detecting
classical-only signatures on long-lived CA material, chain-validation downgrade and
algorithm-confusion against **composite/hybrid** certificates (classical + PQ signature in one
cert, per the IETF LAMPS composite ML-DSA drafts), and mis-issuance surfaced by Certificate
Transparency (CT) monitoring.

This is both a *posture* and a *detection* playbook. Its cert-by-algorithm inventory feeds the
PB-01 CBOM; its signature findings share tuning with PB-05 (PQ signatures/tokens) and PB-11
(code signing).

## MITRE mapping

- **T1649** — Steal or Forge Authentication Certificates (forged leaf, or a cert whose PQ half
  a downgrading verifier ignores, accepted as valid).
- **T1553.004** — Subvert Trust Controls: Install Root Certificate (rogue/classical-only root
  planted in a trust store to bypass PQ policy).
- **T1587.003** / **T1588.004** — Develop / Obtain Capabilities: Digital Certificates (adversary
  provisioning certs from a compromised or mis-issuing CA).
- **T1556** — Modify Authentication Process (chain-validation logic altered to accept the
  classical component of a composite cert while skipping the PQ component).
- Much PQ-migration *defect* work (classical roots, non-FIPS providers in a CA path) is
  pre-ATT&CK posture, not adversary behavior — flagged as a gap, not tagged to a technique.

## Detection strategy

Four planes, correlated against PKI policy and the CBOM baseline:

1. **Inventory by signature algorithm × expiry.** Enumerate every cert (roots, intermediates,
   leaves) with its `signatureAlgorithm`, key type, `notAfter`, and path role. Flag classical
   signatures on material whose lifetime crosses the quantum horizon — roots worst, by lifetime.
2. **Chain-validation downgrade / algorithm confusion.** A composite cert carries both a
   classical and a PQ signature; a compliant verifier must check **both**. Detect verifiers or
   paths that validate on the classical half alone (PQ component ignored, absent, or malformed
   yet still "valid").
3. **CT log monitoring.** Watch CT for mis-issued certs, unexpected/rogue CAs for your domains,
   and **algorithm confusion** (a cert logged with an OID or signature algorithm that doesn't
   match the issuing CA's stated policy).
4. **Revocation at PQ scale.** ML-DSA signatures (~3.3 KB) inflate OCSP responses and CRLs;
   SLH-DSA far more. Monitor for oversized/truncated revocation responses and validators that
   silently soft-fail (treat "unknown" as "good") under the new size.

## Indicators

- Root or long-lived intermediate signed with RSA/ECDSA and no PQ or composite companion, with
  `notAfter` beyond the migration horizon.
- Composite cert accepted by a verifier that logs only the classical algorithm as validated —
  the PQ half was never checked (algorithm confusion / downgrade).
- Composite cert whose PQ signature is malformed or stripped yet the chain still validates.
- CT entry for one of your domains from a CA not in your authorized-issuer list (rogue/mis-issuance).
- CT entry whose `signatureAlgorithm` OID conflicts with the issuer's declared policy
  (e.g., a "PQ" intermediate emitting classical-only leaves, or vice versa).
- Non-FIPS-validated PQ provider (e.g., `oqs-provider`/liboqs) in a CA signing or validation path.
- OCSP/CRL responses truncated, oversized, or soft-failed after a PQ cutover — revocation
  effectively disabled at scale.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "classical_signature_on_long_lived_ca_material",
  "for_each": "cert in pki_inventory",
  "trigger": {
    "path_role": "root | intermediate",
    "signature_algorithm": "classical (rsa* | ecdsa* | ed25519) AND NOT composite/hybrid",
    "not_after_years_remaining": "> quantum_horizon_years"
  },
  "severity": "critical if root; high if intermediate",
  "enrich": ["ca_name", "key_type", "not_after", "cbom_id (PB-01)", "issued_leaf_count"]
}
```

```json
{
  "rule": "composite_chain_validation_downgrade",
  "//": "compliant verifier MUST validate BOTH signatures in a composite cert",
  "join": "validation_event WITH cert.composite_components",
  "trigger": {
    "cert_type": "composite (classical + ML-DSA)",
    "validated_components": "classical_only",
    "pq_component_status": "ignored | absent | malformed",
    "chain_verdict": "valid"
  },
  "severity": "high",
  "enrich": ["verifier", "provider", "path", "endpoint"]
}
```

```json
{
  "rule": "ct_misissuance_or_algorithm_confusion",
  "source": "certificate_transparency_logs",
  "trigger": {
    "subject_matches": "owned_domain",
    "any_of": [
      "issuer NOT IN authorized_ca_list",
      "signature_algorithm_oid CONFLICTS issuer_policy"
    ]
  },
  "severity": "high; critical if issuer unknown",
  "enrich": ["log", "sct_timestamp", "issuer", "sig_alg", "serial"]
}
```

## Example data

```json
{ "cert": "GreyNOC Root CA G3", "role": "root", "sig_alg": "ecdsa-with-SHA384",
  "not_after": "2046-01-01T00:00:00Z", "years_remaining": 20, "composite": false,
  "cbom_id": "CBOM-0091", "verdict": "critical: classical root outlives quantum horizon; migrate to SLH-DSA first" }

{ "cert": "svc-mesh-intermediate", "role": "intermediate", "sig_alg": "composite (ecdsa-p256 + ML-DSA-65)",
  "not_after": "2031-06-01T00:00:00Z", "composite": true, "verdict": "ok: hybrid CA, both components present" }

{ "ts": "2026-07-03T09:14:00Z", "endpoint": "203.0.113.40", "verifier": "edge-proxy-02",
  "cert_type": "composite", "validated_components": "ecdsa-p256 only",
  "pq_component_status": "ignored", "chain_verdict": "valid", "provider": "oqs-provider",
  "verdict": "downgrade: PQ half unchecked by non-FIPS provider (T1556)" }

{ "ts": "2026-07-05T22:41:00Z", "log": "ct.example-log", "subject": "*.greynoc.example",
  "issuer": "Unknown CA XYZ", "sig_alg": "sha256WithRSAEncryption", "serial": "0x4f1a...",
  "src_v6": "2001:db8:ac10:5::9", "verdict": "mis-issuance: issuer not in authorized list (T1587.003/T1588.004)" }
```

## Investigation steps

1. Pull the full cert record: algorithm, key type, path role, `notAfter`, issuing CA, and how
   many leaves the CA has signed (blast radius). Cross-check the PB-01 CBOM entry.
2. For a composite downgrade alert, reproduce validation with a known-good compliant verifier
   (authorized hosts only) — confirm whether the endpoint's verifier checks **both** signatures
   or silently accepts the classical half. Identify the provider in the path.
3. For a CT alert, confirm subject ownership, then check the issuer against the authorized-CA
   list and CAA records. Unknown issuer for an owned domain is treated as mis-issuance until proven otherwise.
4. For algorithm confusion, compare the logged `signatureAlgorithm`/OID against the issuing CA's
   published profile — a mismatch is either a CA policy defect or an attempt to slip an
   unexpected algorithm past a permissive validator.
5. For revocation alerts, measure OCSP/CRL response size and test whether validators hard-fail
   or soft-fail on oversized/truncated PQ responses.

## False positives

- A short-lived leaf signed classically **under** a hybrid intermediate during a phased rollout
  — acceptable if the leaf's lifetime is short and roots/intermediates are already PQ. Score by role.
- A verifier that legitimately doesn't yet support composite certs (interop gap) — a *posture*
  finding for PB-01, not an active downgrade attack. Distinguish "can't" from "was made not to."
- CT entries from a newly authorized CA not yet added to the issuer allow-list — update the list
  by reference rather than muting the rule.
- Larger OCSP/CRL responses that are correct for PQ signature sizes — size growth alone is
  expected; the finding is truncation or soft-fail, not size.

## Tuning

- Tune on **path role**: roots and intermediates dominate risk because of lifetime. Weight the
  classical-signature detector by `notAfter`, not by cert count.
- Maintain an authorized-CA / issuer allow-list and a per-CA algorithm profile, refreshed from
  PB-01, so CT and algorithm-confusion rules only fire on genuine deviations.
- Do not suppress composite-downgrade detection to reduce noise from interop gaps — split the
  two verdicts (misconfig vs. active downgrade) and route separately.
- Baseline revocation-response sizes per issuer after the PQ cutover so truncation stands out.

## Response actions

- Classical long-lived root → schedule PQ re-root: issue a new root signed with **SLH-DSA**
  (hash-based, most conservative for the longest lifetimes), cross-sign for transition, and
  drive trust-store distribution. Roots migrate first.
- Classical intermediate → reissue as composite (classical + **ML-DSA-65**) under the PQ root;
  rotate affected leaves via automated issuance (ACME).
- Confirmed composite downgrade → treat as a validation-integrity incident (T1556): fix or
  replace the verifier/provider so both signatures are checked; replace any non-FIPS PQ provider
  in a FIPS-obligated path with a validated module.
- CT mis-issuance → revoke, notify the CA/log operator, tighten CAA, and hunt for use of the
  rogue cert. Feed the leaf inventory delta to PB-01 and code-signing scope to PB-11.

## Escalation criteria

- Any classical-only **root** whose lifetime crosses the quantum horizon → crypto-program owner
  as a tracked re-root item (highest priority in this playbook).
- Confirmed rogue/unknown CA issuing for an owned domain → incident escalation (mis-issuance).
- Active composite-downgrade (PQ half systematically ignored across a fleet of verifiers) →
  incident + engineering escalation; the PQ control is present in cert but not enforced.
- Revocation soft-failing at scale after a PQ cutover → operational incident (revocation is
  effectively off).

## Cert-agility posture (enabler)

Agility is what makes a top-down migration survivable. The controls below are posture wins that
shrink every window above:

- **Short-lived leaves + automated issuance (ACME).** The shorter the leaf lifetime, the cheaper
  an algorithm swap or emergency rotation — no manual re-issue campaign.
- **Rollover planning.** Pre-stage next-generation roots/intermediates and cross-sign so a PQ
  cutover (or a rogue-CA revocation) is a scheduled rollover, not a fire drill.
- **Roots-first sequencing.** Because roots have multi-decade lifetimes, a root left classical
  today is the single longest HNDL exposure in the PKI — sequence it ahead of leaves.

## Analyst notes (template)

```
PKI-ID:             PKI-____
Cert / role:        ____ / (root | intermediate | leaf)
Signature algo:     ____  (classical | composite | pq)   Composite? Y/N
Key type / notAfter:____ / ____    Years remaining: ____
CBOM-ID (PB-01):    ____
Finding:            classical-long-lived | composite-downgrade | CT-misissuance | algo-confusion | revocation-scale
Composite check:    both-validated | classical-only | pq-absent/malformed
Provider in path:   ____   FIPS-validated? Y/N
CA / issuer:        ____   In authorized list? Y/N
Migration target:   ____ (e.g., SLH-DSA root; ML-DSA-65 composite intermediate)
Disposition:        ticketed | reissue/re-root | incident | accepted-risk | escalated
```

## Summary

PKI migration is a lifetime problem: sign the longest-lived material with PQ first, because a
classical root issued today is a decades-long exposure. Inventory every cert by signature
algorithm and expiry into the CBOM, enforce that composite certs are validated on **both**
signatures (not just the classical half), and watch CT for mis-issuance and algorithm
confusion. Use short-lived certs and ACME as agility enablers so leaf rotation is cheap and the
hard problem — roots and intermediates — gets the attention it deserves.
