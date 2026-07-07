# 13 — Crypto-Agility & Post-Quantum Migration Operations

## Overview

Discovery (PB-01) tells you what crypto you have; downgrade monitoring (PB-03) tells you
whether hybrid is holding. This playbook is the **operations manual for the migration itself**:
how to actually move an estate from classical to PQ/hybrid crypto without breaking production
and without silently regressing the protection you just deployed.

The precondition is **crypto-agility**: algorithm choice externalized to config/negotiation,
no hardcoded primitives, a crypto-abstraction/provider layer, and versioned cipher policy so a
primitive can be swapped **without a code change**. With that in place, migration becomes a
governed rollout — hybrid/dual-stack by default, wave-based (canary → ring → fleet), gated on
health metrics, and reversible. The same agility is what lets you survive the day a primitive
is broken (see the emergency runbook below).

This is a *program/operations* playbook. It consumes the CBOM (PB-01) for scope, the hybrid
negotiation feed (PB-03) for rollout health, and reports up to governance (PB-14).

## MITRE mapping

- **No single ATT&CK adversary technique applies** — this is a defensive migration program,
  not an attack detector (per CONVENTIONS §4). It is mapped by the adversary techniques it
  exists to **deny**, not by one it detects.
- Denies **T1600** Weaken Encryption — moving off quantum-broken key exchange removes the
  primitive an attacker would force sessions down to.
- Denies **T1557** Adversary-in-the-Middle — end-to-end hybrid negotiation removes the
  in-path downgrade payoff (the operational fix loop for PB-03 findings).
- Denies **T1040** Network Sniffing / HNDL — re-encryption of at-rest data and rotation close
  the harvest-now-decrypt-later window (data ops below; prioritized via PB-02).
- Prevents **T1562** Impair Defenses — a botched wave or template drift that silently disables
  PQ *is* a self-inflicted defense-impairment; the health gates and rollback exist to catch it.

## Detection strategy

Framed here as **migration-health monitoring and rollout gating** — not threat detection.
Every wave is instrumented and every promotion is gated:

1. **Adoption vs. target.** Per service, track `% connections negotiating hybrid` (fed from
   PB-03) against the wave's target. Below target after the soak window blocks promotion.
2. **Canary regression gates.** During a wave, compare canary error rate, handshake-failure
   rate, and p99 latency against the pre-wave baseline. Breach → automated rollback, not a page.
3. **Interop/compat exceptions.** Legacy peers that cannot speak hybrid land in an exceptions
   register with an expiry, not a silent classical fallback. Growth in the register is a signal.
4. **Key/PKI readiness.** KMS/HSM must support ML-KEM/ML-DSA and hybrid key-wrapping before a
   service enters a wave; re-encryption backlog and rotation lag are tracked as health metrics.
5. **Regression = alert.** A service that reached hybrid target and later drops (rollback,
   template drift, dependency downgrade) is the same class of finding as PB-03 §2 — surface it.

## Indicators

Signals that a migration wave is **regressing or unsafe** and should be gated or rolled back:

- Hybrid-negotiation ratio for a service in-wave stalls well below target after the soak window.
- Canary error / handshake-failure / latency delta breaches the rollback threshold vs. baseline.
- Hybrid ratio **regresses** on a service already promoted — deploy, rollback, or template drift.
- Compat-exceptions register growing, or exceptions past expiry never re-attempted.
- Non-validated PQ provider (`oqs-provider`/liboqs) reaching a FIPS-obligated production path.
- KMS/HSM lacks ML-KEM/ML-DSA or hybrid key-wrap, yet a dependent service was promoted anyway.
- Re-encryption backlog for HNDL-exposed at-rest data not shrinking while keys rotate (PB-02).
- A crypto call site still hardcoded (no provider-layer indirection) blocking config-only swap.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "migration_wave_promotion_gate",
  "for_each": "service in current_wave",
  "inputs": {
    "hybrid_ratio": "pb03.hybrid_handshakes / total_handshakes",   "//": "adoption feed",
    "target_ratio": "wave.policy.target",                          "//": "e.g. 0.95",
    "canary_err_delta": "canary.error_rate - baseline.error_rate",
    "canary_p99_delta": "canary.p99_ms - baseline.p99_ms",
    "hs_fail_delta": "canary.handshake_fail_rate - baseline.handshake_fail_rate"
  },
  "gate": {
    "promote_if": "hybrid_ratio >= target_ratio AND canary_err_delta <= 0.005 AND canary_p99_delta <= 15 AND hs_fail_delta <= 0.002",
    "hold_if":    "hybrid_ratio < target_ratio AND all deltas within threshold",
    "rollback_if":"canary_err_delta > 0.02 OR hs_fail_delta > 0.01 OR canary_p99_delta > 50"
  },
  "enrich": ["service", "wave", "cbom_priority", "kms_pq_ready", "open_exceptions"]
}
```

```json
{
  "rule": "hybrid_adoption_regression",
  "//": "same class as PB-03 §2, applied to promoted services",
  "metric": "ratio(hybrid_handshakes / total_handshakes) per promoted_service",
  "trigger": "ratio drops > 30% vs. 7-day post-promotion baseline within 1h",
  "context_join": "change_event(service) within 24h",
  "severity": "medium; high if no approved change explains the drop OR service is internet-facing"
}
```

## Example data

```json
{ "ts": "2026-07-06T09:14Z", "service": "checkout-api", "wave": "ring-2",
  "hybrid_ratio": 0.71, "target_ratio": 0.95, "canary_err_delta": 0.001,
  "canary_p99_delta": 8, "hs_fail_delta": 0.0004, "kms_pq_ready": true,
  "open_exceptions": 3, "decision": "hold: adoption below target, health nominal",
  "canary_host": "192.0.2.41" }

{ "ts": "2026-07-06T11:42Z", "service": "session-gw", "wave": "canary",
  "hybrid_ratio": 0.44, "target_ratio": 0.95, "canary_err_delta": 0.031,
  "canary_p99_delta": 62, "hs_fail_delta": 0.014, "kms_pq_ready": true,
  "canary_host": "2001:db8:0:12::10",
  "decision": "rollback: error+latency+handshake gates breached" }
```

## Investigation steps

Triaging a **stalled or regressed rollout**:

1. Classify the state: *stalled* (adoption below target, health fine) vs. *regressed* (was at
   target, now dropping) vs. *unhealthy* (health gate breached). Each has a different owner.
2. Stalled → is the shortfall legacy peers (expected — check the exceptions register) or a
   path element terminating PQ early? Pivot to PB-03 to confirm where hybrid stops.
3. Regressed → correlate with the most recent deploy/config change to the service or its path;
   most regressions are a rollback or template drift, not an adversary (confirm via PB-03).
4. Unhealthy → pull canary error/handshake/latency traces; separate a real PQ-induced fault
   (larger key shares, HSM latency, MTU/fragmentation) from an unrelated deploy defect.
5. Verify key-plane readiness independently: does KMS/HSM actually serve ML-KEM/ML-DSA and
   hybrid key-wrap for this service, or was it promoted on an assumption? (PB-10.)
6. For HNDL-relevant services, confirm the at-rest re-encryption job is progressing, not just
   that transport flipped to hybrid — transport-only migration leaves harvested data exposed (PB-02).

## False positives

- Legacy/interop peers negotiating classical **by design** — not a regression if they hold a
  live exception with an unexpired entry. The gate should read the register, not blanket-alert.
- Approved compatibility window where PQ is intentionally paused — track the approved change so
  it suppresses the regression alert by reference, not by muting the metric (cf. PB-03).
- Adoption ratio noise on a low-traffic service — require a minimum handshake volume before the
  gate fires, or a synthetic canary carries the signal instead of live traffic.
- A canary latency delta caused by an unrelated concurrent deploy — correlate the change window
  before attributing regression to the crypto swap.

## Tuning

- Tune at the **gate thresholds and per-service targets**, not by lowering PB-03 sensitivity or
  muting handshake logging — blinding the adoption feed blinds the whole program.
- Set targets per service tier: internet-facing / long-shelf-life services get aggressive
  targets and tight rollback gates; internal short-lived services can soak longer.
- Right-size the soak window per wave (canary hours, ring days) so transient deploy noise
  clears before a promotion decision.
- Re-baseline post-promotion adoption on a fixed cadence so drift toward classical is itself an
  alert, mirroring the CBOM re-baseline discipline (PB-01).

## Response actions

Rollout/rollback operations:

- **Promote** when the gate passes: advance canary → ring → fleet, carry the new baseline
  forward, and update the CBOM (PB-01) with the service's new negotiated posture.
- **Hold** on stalled adoption with nominal health: do not roll back healthy code; work the
  adoption gap (path fix per PB-03, or file/renew an interop exception with an expiry).
- **Rollback** on a health-gate breach: revert to the prior versioned cipher policy via config
  (no code change — this is the payoff of the provider layer), confirm recovery, capture the
  canary evidence, and re-plan the wave.
- **Data plane:** for HNDL-exposed services, drive rotation and **re-encryption of at-rest
  data** to close the harvest window — flipping transport is not enough (PB-02).
- **Provider hygiene:** replace any non-validated PQ provider in a FIPS-obligated path with a
  validated module before promotion (PB-01/PB-10).
- Refactor remaining hardcoded call sites behind the crypto-abstraction layer so the next swap
  is config-only; feed the exceptions register and wave status up to governance (PB-14).

## Escalation criteria

- Systemic hybrid-adoption regression across many internet-facing services after a change →
  change-management + crypto-program escalation (likely fleet-wide template/rollback defect, per PB-03).
- A service promoted without verified KMS/HSM PQ readiness now failing in production →
  escalate to the key-management owner (PB-10) and freeze further promotion of dependents.
- Confirmed active PQ-stripping surfaced during triage (not benign regression) → hand to PB-03
  and escalate as an AiTM incident.
- Compat exceptions past expiry with no migration path, on HNDL-exposed data → risk-accept
  decision escalated to the crypto-program owner (PB-14).

## Emergency algorithm-break runbook

The day a deployed primitive is announced broken (a lattice break, a validated attack on a
parameter set, or a mandated NIST/vendor deprecation), agility becomes an incident capability.
Pre-plan it so it is a config action, not a code project:

1. **Scope from the CBOM (PB-01).** Query every service, key, cert, and call site using the
   broken primitive; rank by exposure and data shelf-life (PB-02).
2. **Swap by policy, not by code.** Publish a new versioned cipher policy that removes the
   broken primitive and promotes its pre-selected successor (e.g., ML-KEM→HQC as the
   code-based diversity hedge, or the mandated ML-DSA parameter set). The provider layer picks
   it up on config reload — no redeploy for agile services.
3. **Wave it, but compressed.** Even in an emergency, run canary → fleet with the health gates
   above; a broken-primitive panic that takes production down helps no one.
4. **Hardcoded call sites are the incident.** Any site that cannot swap via config is the long
   pole — it gets the emergency engineering ticket and an interim compensating control.
5. **Data plane triage.** For the broken primitive protecting long-shelf-life at-rest data,
   assume prior ciphertext is compromised; prioritize re-encryption and rotation (PB-02).
6. **Report up.** Track the break as a governed program event through PB-14.

## Analyst notes (template)

```
MIG-ID:              MIG-____
Service / owner:     ____ / ____
Wave / target:       ____ (canary|ring|fleet) / target ratio ____
Hybrid ratio (PB-03):____   Adoption state: stalled | on-track | regressed
Canary deltas:       err ____  p99 ____ms  hs-fail ____
Gate decision:       promote | hold | rollback
KMS/HSM PQ-ready:    Y/N (ML-KEM __ / ML-DSA __ / hybrid-wrap __)   provider validated? Y/N
Open exceptions:     ____ (expired? Y/N)
Hardcoded call site: ____ (agility refactor ticket: ____)
Data plane (PB-02):  re-encryption backlog ____ / rotation lag ____
Change correlated:   ____ (approved? Y/N)
Disposition:         promoted | held | rolled-back | escalated
```

## Summary

Crypto-agility is the architecture; migration is the operation. Externalize algorithm choice
to a provider layer and versioned policy, roll out hybrid-by-default in waves gated on adoption
(from PB-03) and canary health, and make rollback a config change — never a code project. Do
not forget the data plane: re-encrypt at-rest data to close the HNDL window (PB-02), keep the
KMS/HSM ahead of the waves (PB-10), and keep the emergency algorithm-break runbook rehearsed so
the day a primitive falls is a governed swap (PB-14), not a fire.
