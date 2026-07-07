# Release process

Lightweight and honest. Bastion is pre-1.0; only the latest release is supported.

## Versioning

Semantic-ish: `MAJOR.MINOR.PATCH` in [`pyproject.toml`](../pyproject.toml)
(`[project].version`). Pre-1.0, minor bumps may include behavior changes — the
changelog/PR history is the source of truth.

## Steps

1. Ensure `main` is green in CI (lint, security lint, tests across 3.10–3.12).
2. Bump `version` in `pyproject.toml`.
3. Update docs if behavior changed (README, `docs/`, `docs/explanations/`).
4. Run the full local QA pass:
   ```bash
   ruff check src tests && bandit -r src -c pyproject.toml && pytest && pip-audit
   ```
5. Tag the release: `git tag vX.Y.Z && git push --tags`.
6. Draft the GitHub release notes from the merged PRs since the last tag.

## Build artifacts (planned)

- Wheels / sdist via `python -m build` are planned for release automation.
- A portable single-file build is planned; not yet part of the release flow.

## Evidence-bundle signing (planned — not yet implemented)

Evidence bundles today are **integrity-checked**, not **signed**:

- Every bundle's `manifest.json` records a per-entry SHA-256 and a bundle-wide
  entry map. `bastion evidence verify <bundle>` recomputes and compares them.
- The manifest carries `"signing": {"signed": false, "status": "not-implemented"}`
  so downstream tools are never misled into treating a bundle as signed.

Planned signing (Phase 3):

- A detached signature over the canonicalized `manifest.json`.
- Candidate scheme: Ed25519, with an optional post-quantum SLH-DSA hybrid for
  long-lived evidence (aligns with Bastion's harvest-now-decrypt-later stance).
- Signature stored alongside the bundle; `verify_bundle` extended to check it.
- Scaffold: `EvidenceCenter.sign_bundle()` currently raises `NotImplementedError`
  by design — we will not ship a fake or unsigned-but-"signed" artifact.

Until signing lands, treat bundles as tamper-**evident** (hash mismatch is
detectable) but not tamper-**proof** (no cryptographic authenticity).
