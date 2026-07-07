# 14 — Quantum Risk Governance & CNSA 2.0 / NSM-10 Compliance

## Overview

Detection and migration are the work; governance is proving the work is happening, to the
right priority, fast enough. This is the program layer over the technical playbooks: it turns
the CBOM (PB-01), the HNDL posture (PB-02), and migration operations (PB-13) into a defensible,
measurable, reportable **quantum-risk program** that survives an auditor, a board, and a regulator.

The core tension is timing. Nobody knows when a cryptographically relevant quantum computer
(**CRQC**) arrives, but the deadline is not the CRQC — it is the CRQC *minus* your data
shelf-life *minus* your migration time. Governance makes that arithmetic explicit and acts
before the numbers cross. Every claim is backed by CBOM + telemetry, not slideware —
reproducible or it didn't happen.

## Mosca's inequality: are you already late?

Michele Mosca's rule is the one equation this whole program turns on. Let:

- **X** = how long your data must remain confidential (data shelf-life / retention).
- **Y** = how long your migration to PQ will realistically take (discover → deploy → verify).
- **Z** = time until a CRQC exists that can break your current crypto.

**If X + Y > Z, you are already exposed** — data encrypted today under quantum-broken crypto
will still be sensitive when the machine arrives, and you cannot migrate fast enough to stop
the harvest happening now (PB-02). Z has wide error bars, so plan against the *pessimistic* Z.
If X = 15 and Y = 5, any Z below 20 years means today's decisions are already too late for that
class. Governance computes Z − (X + Y) **per data class**, not enterprise-wide, and escalates
every class where the margin is negative or thin.

## MITRE mapping

Governance work is largely **pre-ATT&CK** — there is no adversary technique for "the board
didn't fund migration." Per CONVENTIONS §4, we say so rather than forcing a tag. The primary
"mappings" here are to **compliance frameworks, not ATT&CK** (CNSA 2.0, NSM-10 / OMB M-23-02,
NIST FIPS 203/204/205 + SP 1800-38, PCI DSS 4.0). This program **governs the response** to two
threat-class techniques handled operationally elsewhere:

- **T1040** — Network Sniffing (the HNDL capture this program exists to outrun; see PB-02).
- **T1600** — Weaken Encryption (adversary or drift forcing classical-only crypto).

No other ATT&CK IDs are claimed. If a governance-gap review uncovers active exploitation,
it exits governance and enters the relevant detection playbook.

## Detection strategy

"Detection" here is continuous measurement of **program and compliance posture** — the gap
between mandated state and evidenced state, sampled on a cadence, not asserted once a year.

1. **Mandate-to-control mapping.** For each mandate (CNSA 2.0, NSM-10 / M-23-02, FIPS-validation
   obligations, PCI DSS 4.0 crypto-agility), enumerate required controls and bind each to a
   CBOM-backed evidence source. A control with no evidence source is a gap by construction.
2. **Coverage & freshness metering.** Measure what fraction of the estate the CBOM sees and how
   stale that view is. A claim over a 60%-complete, 90-day-old inventory is not a claim.
3. **KPI trend, not snapshot.** Track migration as rates (% CBOM migrated per quarter, % sessions
   negotiating hybrid) so that *stall* is itself a signal — flat lines are alerts.
4. **Vendor / supply-chain attestation.** Track whether each material SaaS and hardware vendor is
   on a credible, dated PQ roadmap. Un-attested critical dependencies are open risk.
5. **Register reconciliation.** The quantum-risk register feeds the enterprise risk register;
   drift between them (a risk tracked technically but invisible to leadership) is a failure signal.

## Indicators

Signals of governance failure or compliance gap:

- A mandated control with **no bound evidence source**, or evidence older than its freshness SLA.
- CBOM coverage below target, or coverage figure that is itself unmeasured ("we think ~most").
- A negative or thin **Mosca margin** (Z − (X + Y) ≤ 0) for any data class with no dated remediation.
- Migration KPI flat or regressing across two reporting periods (program stall).
- Quantum-risk register item **not reflected** in the enterprise risk register or board reporting.
- Material vendor with **no PQ roadmap attestation**, or an attestation with no dates / no owner.
- Non-FIPS-validated PQ provider (e.g., `oqs-provider`/liboqs) in a path carrying a FIPS-140-3
  obligation — a compliance gap even if cryptographically sound (see PB-01).
- Reliance on slideware: a compliance assertion that cannot be reproduced from CBOM + telemetry.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "mosca_margin_negative",
  "//": "act-now trigger, evaluated per data class",
  "for_each": "data_class in CBOM",
  "compute": {
    "X_shelf_life_years": "data_class.retention_years",
    "Y_migration_years":  "data_class.est_migration_years",
    "Z_time_to_crqc_years": "program.crqc_estimate_pessimistic",
    "margin": "Z_time_to_crqc_years - (X_shelf_life_years + Y_migration_years)"
  },
  "flag_if":   "margin <= 0",
  "severity":  "critical if margin < 0 AND data_class.pq_status == 'classical_only'",
  "enrich":    ["owner", "cbom_priority", "hndl_ref(PB-02)", "migration_ref(PB-13)"]
}
```

```json
{
  "rule": "compliance_gap_tracker",
  "//": "one row per (mandate, control); gap if no fresh, CBOM-backed evidence",
  "for_each": "control in mandate_control_map",
  "checks": {
    "evidence_source_bound": "control.evidence_ref != null",
    "evidence_fresh":        "now - control.evidence.last_verified <= control.freshness_sla",
    "evidence_reproducible": "control.evidence.derived_from in ['CBOM','telemetry']",
    "coverage_ok":           "cbom.coverage_pct >= control.min_coverage"
  },
  "gap_if": "any(check == false)",
  "mandates": ["CNSA_2_0", "NSM_10 / OMB_M_23_02", "FIPS_203_204_205", "PCI_DSS_4_0"],
  "//2": "deadlines below are as of 2026 — verify against current publications",
  "severity": "high if control.mandated_by_date < now AND gap_if"
}
```

## Example data

```json
{ "data_class": "clinical_records", "X": 25, "Y": 4,
  "Z_pessimistic": 12, "margin": -17, "pq_status": "classical_only",
  "verdict": "CRITICAL: already late; harvestable now, still sensitive at CRQC (PB-02)",
  "ref": "192.0.2.0/24 archive tier, cbom_priority 6" }

{ "mandate": "CNSA_2_0", "control": "pq_firmware_code_signing",
  "required_from": "2025-begin → broad by ~2030-2033", "evidence_ref": "CBOM:signing-pipeline",
  "last_verified": "2026-07-01", "freshness_sla_days": 30, "coverage_pct": 41,
  "gap": true, "why": "coverage 41% < 80% target; LMS/XMSS not yet on all firmware lines" }

{ "vendor": "saas-billing-provider", "criticality": "material",
  "pq_roadmap_attested": false, "attestation_ref": null,
  "gap": true, "action": "request dated PQ roadmap; treat as open supply-chain risk" }
```

## Investigation steps

Auditing a suspected gap:

1. Pull the mandate-to-control row and its bound evidence reference. No binding → the gap is
   confirmed before you look further; open a governance finding.
2. Reproduce the evidence from source (CBOM query, telemetry pull from PB-03/PB-13). If it
   cannot be reproduced independently, the compliance claim fails regardless of prior sign-off.
3. Check freshness against the control's SLA and CBOM coverage against its minimum. A fresh
   claim over a partial inventory is a scoped claim, not a passing one.
4. For a Mosca-margin flag: confirm X with the data owner (real retention, not nominal), Y with
   migration ops (PB-13, realistic not aspirational), Z against the program's pessimistic CRQC
   estimate. Recompute; do not trust a stale margin.
5. For a vendor gap: obtain a **dated** PQ roadmap and named owner; absence of dates equals
   absence of roadmap. Record the concentration risk if the dependency is single-source.
6. Reconcile the finding into both the quantum-risk register and the enterprise risk register,
   with owner, RACI, and next review date.

## False positives

- A control marked "gap" only because evidence is *routed* but not yet *bound* in the tracker —
  a data-plumbing defect, not a real posture gap. Fix the binding, re-evaluate.
- A thin Mosca margin on a data class whose real retention was overstated (nominal 25y but
  actually purged at 3y). Correct X at the source; don't escalate a phantom.
- A vendor "un-attested" because the attestation exists but wasn't ingested — chase the record
  before flagging the vendor.
- A mandate cited with the wrong deadline from a superseded publication. Deadlines move; verify
  against current CNSA/NIST/OMB text before calling something late.

## Tuning

- Tune at the **scoring and SLA layer**, not by suppressing gap detection. Loosening a freshness
  SLA to make a dashboard green hides real drift.
- Set Z (CRQC estimate) as a single governed program parameter with a pessimistic default and a
  documented review cadence — so every Mosca calculation moves together when the estimate does.
- Re-baseline the mandate-to-control map whenever a standard is revised (FIPS 206 / FN-DSA
  finalization, CNSA 2.0 milestone changes, PCI DSS revisions) — a stale mandate map is itself
  a silent gap.
- Weight findings by CBOM priority and HNDL exposure so leadership reporting surfaces the
  negative-margin, long-shelf-life, internet-facing classes first.

## Response actions

Governance / program actions, not incident response:

- Open a tracked remediation item per confirmed gap, each carrying mandate, control, evidence
  source to bind, owner (RACI), and dated target.
- For negative-margin classes: fast-track hybrid PQ enablement (PB-13) and re-encryption at rest
  with AES-256, ordered by Z − (X + Y) (most negative first) — the highest-leverage action here.
- Bind every "asserted" control to a reproducible CBOM/telemetry source; retire any claim that
  cannot be reproduced.
- Escalate un-attested material vendors: require a dated PQ roadmap as a contract/renewal
  condition; log concentration risk for single-source dependencies.
- Publish KPIs to leadership on a fixed cadence (% CBOM migrated, % hybrid negotiated, coverage,
  count of negative-margin classes) with trend, so stall is visible early.
- Reconcile the quantum-risk register into the enterprise risk register every cycle.

## Escalation criteria

- Any data class with a **negative Mosca margin** and classical-only crypto that has no dated
  remediation owner → escalate to the crypto-program owner and risk committee as act-now.
- A mandated control **past its required-by date** with an open, evidenced gap → compliance
  escalation (CNSA 2.0 signing milestone, NSM-10 inventory/plan obligation, PCI DSS 4.0
  crypto-agility, FIPS-validation obligation).
- CBOM coverage below the floor required to make *any* credible compliance claim → escalate the
  inventory program itself (PB-01) before further attestation.
- A material vendor refusing or unable to provide a dated PQ roadmap → escalate as
  strategic supply-chain risk to leadership.

## Analyst notes (template)

```
GOV-ID:              GOV-____
Mandate / control:   ____ / ____   (CNSA 2.0 | NSM-10 / M-23-02 | FIPS 203/204/205 | PCI DSS 4.0 | other)
Finding type:        mosca-margin | evidence-gap | coverage-gap | vendor-attestation | register-drift
Data class / owner:  ____ / ____
Mosca:  X(shelf)=__ y   Y(migration)=__ y   Z(CRQC,pessimistic)=__ y   margin(Z-(X+Y))=__
Evidence source:     ____ (CBOM | telemetry PB-03/PB-13)   reproducible? Y/N   last_verified: ____
CBOM coverage:       ____ %   freshness SLA met? Y/N
Vendor (if any):     ____   PQ roadmap attested/dated? Y/N   owner: ____
Deadline status:     required-by ____   past due? Y/N
Register:            in quantum-risk reg? Y/N   in enterprise risk reg? Y/N
Disposition:         remediation-item | accepted-risk | escalated
```

## Summary

Quantum-risk governance is the arithmetic of Mosca's inequality applied continuously and
proven with evidence. Compute Z − (X + Y) per data class, act on every negative margin, and bind
each mandated control (CNSA 2.0, NSM-10 / M-23-02, NIST FIPS 203/204/205 + SP 1800-38, PCI DSS
4.0 — deadlines as of 2026, verify against current publications) to a reproducible CBOM or
telemetry source. Everything the program claims rests on PB-01's inventory, PB-02's HNDL
posture, and PB-13's migration telemetry — governance without that evidence is slideware, and
slideware does not survive an auditor, a board, or a quantum computer.
