# Changelog

All notable changes to GreyNOC Bastion are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-07-18

### Added
- **Asymmetric & post-quantum-hybrid evidence-bundle signing.** Alongside the
  existing zero-dependency HMAC scheme, `bastion evidence` now offers public-key
  signing via the optional, vetted `cryptography` backend
  (`pip install 'greynoc-bastion[pqc]'`):
  - `ed25519` — classical EdDSA (RFC 8032); third-party non-repudiation.
  - `ml-dsa-65` — ML-DSA-65 (FIPS 204); post-quantum non-repudiation.
  - `hybrid` — Ed25519 **and** ML-DSA-65, where verification requires **both**
    signatures. Defense-in-depth for the PQC transition: the bundle stays
    trustworthy unless an attacker breaks both primitives.
- New/extended CLI:
  - `bastion evidence keygen --scheme ed25519|ml-dsa-65|hybrid` writes an
    owner-only private key envelope (`--key`) and a shareable public key
    envelope (`--pub`).
  - `bastion evidence sign` auto-detects the scheme from the key file.
  - `bastion evidence verify --pubkey <evidence.pub>` verifies with the public
    key alone (the private key is never needed to verify).
  - `bastion evidence backends` reports which signing schemes are available.
- `bastion status` shows a **Signing** line; `bastion doctor` adds an
  informational `signing_backends_available` check; `app.status()` JSON gains a
  `signing_backends` block.
- `services/signing.py`: the new crypto backend. Standards-based key
  serialization (PKCS#8 / SubjectPublicKeyInfo DER in a JSON envelope), a
  non-reversible public key id, and per-scheme sign/verify. All primitives are
  delegated to `cryptography` — none are hand-rolled.

### Changed
- The evidence-bundle manifest advertises `signing.available_schemes` in
  addition to the existing `signing.scheme` field (which is retained for
  backward compatibility).
- Asymmetric signatures cover the bundle digest **and** the attested sidecar
  metadata (bundle name, `signed_at`, scheme, schema version), matching the HMAC
  scheme, so neither the archive bytes nor the attestation can be altered
  without breaking verification.

### Fixed
- **Feed cache pruning now evicts by the logical `fetched_at` recorded in each
  meta rather than by filesystem mtime.** Filesystem mtime is unreliable — equal
  under fast writes, and a backup or AV scan touching a body file could reorder
  the cache and evict genuinely-recent entries. Pruning also now tolerates a
  corrupt meta (invalid JSON, non-object, or non-numeric `fetched_at`) without
  crashing `_prune` / `put`, exactly as `get` already tolerated it — so a single
  damaged cache file can never break a live ingest.

### Security
- `cryptography` is an **optional** dependency; Flask remains the only required
  runtime dependency. A missing backend never affects the zero-dependency HMAC
  path — it degrades to a clear "install `greynoc-bastion[pqc]`" message.
- Asymmetric private keys are written owner-only (POSIX `0600` / Windows ACL)
  using the same atomic, fail-closed write path as the HMAC key. Public key
  envelopes carry no private material.
- CI now installs the `[pqc]` extra so the asymmetric / post-quantum signing
  tests actually run in the pipeline (they would otherwise skip on a lean
  install), with a dedicated leg that verifies graceful degradation when the
  backend is absent.

## [0.2.1] — 2026-07-17

### Fixed
- Hardened Bastion flows and the exploit-timing methodology (constant-hazard
  p50/p90 derivation disclosed; KEV reported as already-observed exploitation).

## [0.2.0] — 2026-07-13

### Added
- Phase 2 + 3: case management, real authentication + RBAC with a full audit
  trail, report/workflow scheduling with an explicit local runner, local
  telemetry replay, signed (HMAC) evidence bundles, an opt-in notification
  fabric, and a cross-module orchestrator.
- A friendly CLI landing page and smoother first-run flow.

[0.3.0]: https://github.com/GreyNOC/Bastion/releases/tag/v0.3.0
[0.2.1]: https://github.com/GreyNOC/Bastion/releases/tag/v0.2.1
[0.2.0]: https://github.com/GreyNOC/Bastion/releases/tag/v0.2.0
