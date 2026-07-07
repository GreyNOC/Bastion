# 11 — Post-Quantum Code Signing & Firmware Integrity

## Overview

Most PQ migration debates hinge on *confidentiality* shelf-life — how long harvested traffic
stays sensitive (see PB-02). Code and firmware signatures are the opposite problem: the
**artifact outlives the CRQC timeline**. A firmware image, a boot loader, or an OS package
signed today with RSA/ECDSA may still be verified — and trusted — by devices in the field
after a cryptographically relevant quantum computer exists. An adversary who can forge that
signature can ship malicious firmware that a device accepts as authentic. There is no
"re-sign later" for hardware already deployed and no way to un-trust a leaked signing key
retroactively.

This is why **CNSA 2.0 makes software and firmware signing the *earliest* mandated PQ
transition**, well ahead of general traffic. For firmware and boot chains, NSA/CNSA 2.0
recommends the **stateful hash-based signatures LMS / XMSS (NIST SP 800-208) for use now** —
they are conservative, standardized ahead of the general timeline, and rely only on hash
security. For software/package/artifact signing, migrate to **ML-DSA** (or **SLH-DSA** where
conservatism outweighs signature size). This playbook detects classical-only signing on
long-support-window artifacts, signature downgrade/absence in the boot and update chains, and
the state-management failures unique to stateful hash-based schemes.

## MITRE mapping

- **T1553.002** — Subvert Trust Controls: Code Signing. Forged or downgraded signatures that
  make a malicious artifact appear trusted.
- **T1587.002** — Develop Capabilities: Code Signing Certificates. Adversary obtaining or
  forging signing capability; the endgame a CRQC enables against classical signing keys.
- **T1542.001** — Pre-OS Boot: System Firmware. Malicious firmware accepted by a boot chain
  whose signature verification is quantum-vulnerable.
- **T1601** — Modify System Image. Tampered OS/appliance images passing a weak integrity gate.
- **T1195.002** — Supply Chain Compromise: Software Supply Chain. Unsigned or PQ-unsigned
  packages, containers, and release artifacts entering the update channel.
- Note: no ATT&CK technique captures the *state-reuse* hazard of LMS/XMSS (§ below) — it is a
  crypto-implementation defect, pre-ATT&CK. Tag by impact (T1553.002) and describe the mechanism.

## Detection strategy

Four surfaces, all reconciled against the CBOM (PB-01) and the signing inventory (PB-05):

1. **Firmware & boot chain.** Enumerate UEFI Secure Boot signature algorithms, `db`/`KEK`/`PK`
   contents, TPM measured-boot (PCR) policies, and vendor firmware-update signing. Flag
   classical-only signing on long-support-window hardware; flag stateful-scheme deployments and
   verify their state hygiene (§).
2. **Software / package / artifact.** OS packages, container images, release artifacts, and
   update channels. Flag artifacts lacking a PQ signature, and update channels that will accept
   classical-only signatures indefinitely.
3. **Downgrade / absence.** Boot or update verifiers that *accept* a weaker or missing signature
   when a stronger one was expected — the signing analog of the KEM downgrade in PB-03.
4. **Supply-chain provenance.** SBOM presence and signature verification along the build/publish
   pipeline; artifacts whose provenance attestation is unsigned or classically signed only.

Score each artifact by **support-window years** × **exposure** × **signature class**
(quantum-broken classical vs. PQ vs. stateful-hash), mirroring PB-01's method. Keep every probe
read-only and run only against authorized hosts and pipelines.

## Indicators

- Firmware / boot-loader / UEFI `db` entries signed with RSA-2048/3072 or ECDSA on hardware with
  a multi-year support window and no PQ (LMS/XMSS or ML-DSA) migration path.
- Vendor firmware-update packages verified with a classical-only signature; update agent has no
  PQ verification code path even where the platform supports it.
- OS packages / container images / release artifacts published **unsigned**, or signed only with
  RSA/ECDSA where a PQ signature is now required by policy.
- A verifier that accepts a **downgraded** signature: image expected to carry ML-DSA/LMS but a
  classical-only (or absent) signature is accepted without error — a fail-open integrity gate.
- Stateful hash-based signing (LMS/XMSS) present **without** demonstrable single-active-signer
  enforcement or HSM-bound state — the reuse hazard (§).
- Provenance/SBOM attestation missing or signed with a quantum-vulnerable algorithm only.
- Non-validated PQ provider (`oqs-provider`/liboqs) in a FIPS-obligated signing path (see PB-01).

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "classical_only_signature_on_long_support_artifact",
  "for_each": "artifact in {firmware, boot_image, os_package, container, release}",
  "trigger": {
    "signature_class": "classical_only (RSA | ECDSA | EdDSA)",
    "support_window_years": ">= 3",
    "//": "firmware/boot chains routinely 5-15 yrs; artifact outlives CRQC estimate",
    "pq_signature_present": false
  },
  "severity": "high; critical if firmware/boot AND internet-reachable-update",
  "enrich": ["vendor", "device_model", "support_end", "cbom_priority", "signing_pipeline"]
}
```

```json
{
  "rule": "signature_downgrade_or_absence_at_verify",
  "join": "expected_signature_policy(artifact) WITH observed_signature(artifact)",
  "trigger": {
    "expected": "LMS | XMSS | ML-DSA-65 | SLH-DSA",
    "observed": "classical_only OR none",
    "verifier_result": "accepted"
  },
  "severity": "critical",
  "//": "fail-open integrity gate; boot/update analog of PB-03 KEM downgrade"
}
```

```json
{
  "rule": "stateful_hash_index_reuse",
  "scheme": "LMS | XMSS",
  "trigger": "same (keypair_id, ots_index) observed signing TWO distinct digests",
  "also_flag": [
    "signer_state_source == restored_snapshot | cloned_vm | copied_state_file",
    "concurrent_active_signers(keypair_id) > 1"
  ],
  "severity": "critical",
  "//": "index reuse is catastrophic for OTS security; treat key as compromised"
}
```

## Example data

```json
{ "ts": "2026-05-14T09:20Z", "artifact": "edge-router-fw-4.8.2.bin",
  "vendor": "acme-net", "support_end": "2034", "signature": "ecdsa-with-SHA384",
  "pq_signature_present": false, "update_endpoint": "198.51.100.7",
  "verdict": "high: classical-only firmware, 8-yr window, no PQ path; migrate to LMS" }

{ "ts": "2026-05-14T11:03Z", "artifact": "appliance-os-6.1.img",
  "expected_policy": "LMS", "observed_signature": "rsa-pss-sha256",
  "verifier_result": "accepted", "boot_stage": "measured_boot(PCR7)",
  "verdict": "critical: fail-open verifier accepted classical downgrade" }

{ "ts": "2026-05-14T14:47Z", "scheme": "LMS", "keypair_id": "fw-signer-01",
  "ots_index": 20481, "digests_signed": ["a1b2…","c3d4…"],
  "signer_state_source": "restored_snapshot",
  "verdict": "critical: index reuse after VM snapshot restore; revoke keypair" }
```

## Stateful hash-based signing: the state-management hazard

LMS and XMSS are attractive for firmware/boot **because** their security rests only on hash
functions — no lattice or new number-theoretic assumption — so NSA endorses them for use now.
The catch: they are **stateful one-time-signature (OTS) schemes**. Each signature consumes a
one-time key identified by an index, and **reusing any index is catastrophic** — a single
reuse can leak enough structure to let an attacker forge signatures under that keypair. Unlike
a classical key, the danger is not brute force; it is a *bookkeeping* failure.

The failure modes are operational, not cryptographic:

- **Restored VM snapshot / backup rollback.** The signer resumes from an earlier state and
  re-issues already-used indices. Snapshots and DR restores of a signing host are the classic trap.
- **Cloned or duplicated signer.** Two instances share the same keypair and each advance the
  index independently, colliding.
- **Non-atomic state advance.** State is read, a signature is issued, but the incremented index
  is not durably persisted before the next signature (crash between sign and commit).

Controls to enforce and detect:

- **HSM-bound state.** The index counter lives inside the HSM and advances atomically with each
  signature — state cannot be rolled back by restoring a VM. Prefer this over file-based state.
- **Single-active-signer enforcement.** Exactly one live signer per keypair; a lease/lock that a
  clone cannot acquire. Alert on `concurrent_active_signers > 1`.
- **Reuse detection.** Log every `(keypair_id, ots_index)` and alert on any index signing two
  distinct digests, or any index appearing below the persisted high-water mark.
- **Snapshot/DR policy.** Signing hosts are excluded from naive snapshot/rollback; recovery
  re-provisions a fresh keypair rather than resurrecting stale state.
- **Exhaustion planning.** The keypair has a finite signature budget; monitor remaining indices
  and rotate before exhaustion (an operational, not security, alert).

Treat any confirmed index reuse as **key compromise**: revoke the keypair, rotate to a fresh
one, and re-sign affected artifacts. SLH-DSA (FIPS 205, *stateless*) sidesteps this entirely at
the cost of large signatures — the right trade where state hygiene cannot be guaranteed.

## Investigation steps

1. Pull the artifact's provenance: which pipeline/HSM signed it, with what algorithm, and the
   device support-window it targets. Reconcile against CBOM (PB-01) and signing inventory (PB-05).
2. For firmware/boot findings, enumerate the trust anchors read-only: UEFI `db`/`KEK`/`PK`
   algorithms, TPM PCR/measured-boot policy, and the update agent's accepted signature algorithms.
3. For a downgrade/absence finding, determine whether the verifier *fails open* — feed it a
   correctly-signed and a downgraded artifact in an authorized test rig and observe accept/reject.
4. For LMS/XMSS deployments, verify state hygiene: is state HSM-bound? Is single-active-signer
   enforced? Query the index log for reuse or gaps against the high-water mark (§).
5. Distinguish *posture gap* (no PQ path yet — a migration item) from *active abuse* (a forged or
   downgraded signature that a verifier accepted — an incident).

## False positives

- A legacy device genuinely at end-of-support with no PQ-capable firmware — a real posture gap
  to accept/track, not a live attack. Score by remaining support window; do not reflexively page.
- Internal-only artifacts with a short lifetime and no untrusted-path exposure — classical signing
  may be acceptable for now. Score, don't blanket-escalate.
- A verifier "accepting" a classical signature during an *approved* dual-signing transition window
  (artifact carries both classical and PQ signatures) — track approved windows so they suppress by
  reference, not blanket.
- An index "gap" in an LMS log from a legitimately skipped/reserved range — a gap is not reuse;
  only a repeated index or a below-high-water-mark index is a reuse signal.

## Tuning

- Tune on the **support-window × exposure** score, not by muting signature logging. If you stop
  recording signing algorithms and verifier outcomes, you go blind to the entire downgrade class.
- Maintain an expected-signature-policy baseline per artifact class (firmware → LMS/XMSS;
  packages → ML-DSA) sourced from PB-01/PB-05, so the downgrade rule only fires when a stronger
  signature *was* required.
- For stateful schemes, alert on index reuse and concurrent-signer conditions directly — these are
  high-signal and should never be tuned down.
- Re-baseline on a cadence (firmware inventory monthly, package pipeline per release) so drift back
  toward classical-only signing is itself an alert.

## Response actions

- **Classical-only on long-support artifact (posture):** open a migration ticket carrying the
  target (firmware/boot → LMS or XMSS; packages/containers/releases → ML-DSA-65, or SLH-DSA where
  conservatism warrants). Prioritize firmware and internet-reachable update channels first.
- **Fail-open verifier (downgrade/absence):** treat as a critical integrity defect — fix the
  verifier to reject weaker-than-policy or absent signatures, then re-test with a downgraded artifact.
- **Confirmed LMS/XMSS index reuse:** treat the keypair as compromised — revoke, rotate to a fresh
  keypair, re-sign affected artifacts, and remediate the state-management root cause (§).
- **Unsigned/PQ-unsigned supply-chain artifact:** require signature + SBOM verification as a gate
  in the pipeline (PB-05); block publish on failure.
- Replace any non-validated PQ provider in a FIPS-obligated signing path with a validated module.
- Feed all findings and migration targets back into the CBOM (PB-01) and PKI trust-anchor inventory (PB-10).

## Escalation criteria

- A verifier that accepts a forged or downgraded signature on a **firmware/boot or OS image**
  path → incident escalation (T1553.002 / T1542.001); assume affected devices may be running
  untrusted images.
- Confirmed stateful-key index reuse (snapshot restore, clone, or non-atomic state) →
  crypto-program + incident escalation; the keypair is compromised.
- Systemic classical-only signing across a fleet's firmware with multi-year support windows and no
  migration plan → crypto-program escalation as a tracked CNSA 2.0 obligation (earliest mandated PQ transition).

## Analyst notes (template)

```
FWSIG-ID:           FWSIG-____
Artifact / class:   ____  (firmware | boot | os-package | container | release)
Vendor / model:     ____ / ____     Support window: ____ yrs (ends ____)
Signature observed: ____   Class: quantum-broken | pq | stateful-hash
Expected policy:    ____ (LMS | XMSS | ML-DSA-65 | SLH-DSA)
Verifier behavior:  reject | ACCEPTED-DOWNGRADE | accepted (in-policy)
Stateful scheme?    N | Y → HSM-bound state? Y/N  single-signer? Y/N  reuse? Y/N
Finding type:       posture-gap | fail-open-verifier | index-reuse | unsigned-artifact
Migration target:   ____
CBOM/PKI ref:       ____ (PB-01 / PB-10)
Disposition:        ticketed | reconfigure | incident | accepted-risk | escalated
```

## Summary

Code and firmware signatures cannot wait for the general PQ timeline because their artifacts
outlive it — a device trusts a signature for its entire support window. Sign firmware and boot
chains with stateful hash-based LMS/XMSS (SP 800-208) now per CNSA 2.0, migrate packages and
release artifacts to ML-DSA (or SLH-DSA), and gate the supply chain on PQ signature + SBOM
verification. The unique operational trap is stateful-key **index reuse** — a restored snapshot
or cloned signer destroys security silently — so bind state to the HSM, enforce a single active
signer, and treat any reuse as key compromise.
