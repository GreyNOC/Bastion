# 05 — PQ Signature & Token Integrity (ML-DSA / SLH-DSA / FN-DSA · JWT/SAML/X.509)

## Overview

Signatures authenticate certificates, tokens, code, and federation trust chains. The PQ
replacements are **ML-DSA** (FIPS 204, the recommended default — ML-DSA-65), **SLH-DSA**
(FIPS 205, conservative hash-based backup), and **FN-DSA** (FIPS 206, compact NTRU-lattice
signatures for bandwidth-constrained signing); **LMS/XMSS** (SP 800-208) are recommended *now*
for firmware/code-signing. Migration introduces a fresh family of **algorithm-confusion and
downgrade** defects on top of the classic ones. This playbook detects integrity attacks on
signed material across the JWT/SAML/X.509/code-signing surface during and after PQ migration.

## MITRE mapping

- **T1606** — Forge Web Credentials (forged/confused JWT/SAML signatures).
- **T1556** — Modify Authentication Process (algorithm confusion, `alg:none`, key-confusion).
- **T1553** — Subvert Trust Controls (code-signing abuse, rogue CA/cert with weak/forged sig).
- **T1600** — Weaken Encryption (forcing a downgrade from PQ/hybrid to a forgeable classical sig).

## Detection strategy

Watch for verifiers being tricked into accepting something they shouldn't, and signers/issuers
emitting weaker-than-policy material:

1. **Algorithm confusion & downgrade at the verifier.** Tokens/certs presented with an
   algorithm weaker than policy, mismatched to the key type, or `none`; hybrid signatures where
   only the classical half is actually verified; ML-DSA→ECDSA downgrade accepted silently.
2. **Verification failures and anomalies.** Spikes in signature-verification failures (probing
   for a confusion bug), or *successes* on material that should have failed policy.
3. **Issuance/signing posture.** Certificates, tokens, or code signed with quantum-vulnerable
   algorithms where policy/CBOM requires PQ or hybrid; oversized-cert handling defects (ML-DSA
   chains are large — verify intermediaries don't silently drop to classical to "fit").

## Indicators

- JWT/JWS header `alg` set to `none`, or to a symmetric type (HS256) where an asymmetric key is
  expected (classic key-confusion), or to a classical type where PQ/hybrid is mandated.
- Hybrid signature accepted when only one component validates (the PQ half is ignored).
- Certificate chains where the leaf claims PQ but an intermediary verifies under classical only.
- Code-signing events using non-PQ algorithms for firmware/long-lived artifacts (policy says LMS/XMSS).
- Verification-failure bursts against an auth endpoint (confusion/forgery probing) — pairs with PB-08.
- Token signed by an unexpected key ID / issuer, or `kid` pointing at attacker-controllable JWKS.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "signature_algorithm_confusion_or_downgrade",
  "any_of": [
    "jws.header.alg == 'none'",
    "jws.header.alg.class != expected_key.class",
    "presented.alg.strength < policy.min_alg(asset)",
    "hybrid_sig.verified_components < hybrid_sig.required_components",
    "cert_chain.any_intermediary.verified_under == 'classical' AND policy == 'pq_or_hybrid'"
  ],
  "severity": "high",
  "enrich": ["issuer", "kid", "jwks_uri", "verifier", "asset.policy"]
}
```

```json
{
  "rule": "verification_failure_probe",
  "metric": "count(signature_verify_fail) per (source, endpoint)",
  "trigger": "count > baseline_p99 within 10m",
  "context": "varied alg/kid values across attempts == likely confusion probing",
  "severity": "medium; high if any subsequent verify_success on policy-invalid material"
}
```

## Example data

```json
{ "ts": "2026-06-27T11:20Z", "endpoint": "/oauth/introspect", "kid": "edge-2024",
  "presented_alg": "ES256", "policy_min": "ML-DSA-65 | hybrid",
  "result": "accepted", "verdict": "high: PQ-mandated verifier accepted classical ES256 (downgrade)" }
```

## Investigation steps

1. Pull the exact signed artifact (JWS/cert/manifest) and re-verify it independently against
   policy — confirm whether the acceptance was a real verifier defect or expected behavior.
2. For confusion/`none`/key-type mismatch: determine whether the verifier library/config
   enforces an algorithm allowlist bound to the key type. Most of these are verifier-side bugs.
3. For hybrid sigs: confirm *both* components are required and checked. A common migration
   defect is verifying only the classical half (so PQ adds size but no security).
4. Trace `kid`/`jwks_uri` to confirm the verifier only trusts expected key sources (attacker-
   controllable JWKS is a forgery path).
5. For code-signing, validate the artifact's algorithm against the firmware/code-signing policy
   and the integrity of the signing pipeline.

## False positives

- Legitimate multi-algorithm support during a migration window (a verifier *intentionally*
  accepting both classical and PQ for compatibility) — verify against the documented migration
  policy before calling it a downgrade.
- Verification-failure noise from expired tokens, clock skew, or client bugs — these are common
  and benign; the signal is *varied alg/kid probing* or a policy-invalid *success*.
- Large-cert handling warnings that are cosmetic, not security-relevant.

## Tuning

- Encode the per-asset signature policy (min algorithm, hybrid-required, allowed `kid`/issuers)
  as data the rule joins against — so "downgrade" is defined relative to policy, not guessed.
- Alert hardest on the asymmetric case that matters: a *success* on policy-invalid material is
  worse than a thousand failures. Weight accordingly.
- Don't suppress verification-failure logging to cut volume; aggregate it instead — the burst
  shape is the probing signal (see PB-08).

## Response actions

- Confirmed verifier defect (confusion/`none`/single-half hybrid/JWKS trust): patch/harden the
  verifier to enforce an algorithm-and-key-type allowlist; rotate any keys that could have been
  abused; invalidate tokens issued under the defect window.
- Code-signing on non-PQ where policy requires PQ/LMS-XMSS: re-sign affected artifacts; audit
  the signing pipeline; rotate signing keys if integrity is in doubt.
- Downgrade acceptance: enforce minimum algorithm policy at the verifier and re-test.

## Escalation criteria

- Any confirmed signature-forgery or algorithm-confusion that yields a *valid* trust decision on
  attacker-controlled material → incident escalation (authentication bypass class).
- Compromise or weak-algorithm exposure of a code-signing identity → high-severity incident
  (supply-chain blast radius).

## Analyst notes (template)

```
SIG-ID:             SIG-____
Surface:            JWT/JWS | SAML | X.509 | code-signing
Defect class:       alg:none | key-confusion | downgrade | single-half-hybrid | jwks-trust
Presented alg:      ____    Policy min: ____
Verifier result:    accepted | rejected   policy-valid? Y/N
kid / issuer / jwks: ____
Independently reproduced? Y/N
Disposition:        verifier-fix | resign | key-rotation | benign(migration-window)
```

## Summary

Signature migration adds a new confusion/downgrade surface to an old one. The decisive signals
are a verifier *accepting* policy-invalid material and hybrid signatures where only the classical
half is checked. Bind "what's acceptable" to per-asset policy, treat policy-invalid successes as
authentication bypass, and hold code-signing to the strictest bar (LMS/XMSS now, PQ/hybrid for
long-lived artifacts).
