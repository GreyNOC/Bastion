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

## Build artifacts

Pushing a `vX.Y.Z` tag runs [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which re-runs the full QA gate (lint, types, security lint, tests on 3.10–3.12)
and then builds and publishes:

- **Wheel + sdist** — universal, pip-installable, validated with `twine check`
  and smoke-tested by installing the wheel and running `bastion --version` /
  `bastion doctor`. This is the primary distribution.
- **Portable bundles** — one self-contained `.zip` per OS (Linux/macOS/Windows).
  Unzip anywhere and run the bundled `bastion` / `bastion.cmd` launcher; the only
  requirement on the target is a Python 3.10+ interpreter (runtime deps are
  vendored). Built by [`scripts/build_portable.py`](../scripts/build_portable.py),
  which self-smoke-tests each bundle before it is uploaded.

All artifacts are attached to a GitHub Release (`gh release create --generate-notes`).
`workflow_dispatch` runs the same build without publishing (a pipeline dry run).

Build locally:

```bash
pip install ".[packaging]"
python -m build                       # dist/*.whl + dist/*.tar.gz
python -m twine check dist/*
python scripts/build_portable.py      # dist/bastion-portable-<version>-<platform>.zip
python scripts/build_portable.py --no-deps   # CLI-only bundle (vendors nothing)
```

## Evidence-bundle signing (shipped in 0.2.0)

Evidence bundles are **integrity-checked** and can now be **detached-signed**:

- Every bundle's `manifest.json` records a per-entry SHA-256 and a bundle-wide
  entry map. `bastion evidence verify <bundle>` recomputes and compares them.
- `bastion evidence keygen | sign | verify` add a **detached signature**
  (`<bundle>.sig.json`) over the bundle's SHA-256 **and** its attested metadata
  (bundle name, `signed_at`, scheme, schema version), using HMAC-SHA256 with a
  local shared key (stored `0600`, rotation is explicit). Verification is
  constant-time and reports tampering without raising.
- Trust model, stated honestly: shared-key HMAC is tamper **evidence** for
  transfer between parties who exchange the key out-of-band (e.g. air-gapped
  export) — not third-party non-repudiation.

Still planned (Phase 4):

- An **asymmetric** scheme (Ed25519, with an optional post-quantum SLH-DSA
  hybrid for long-lived evidence, aligning with Bastion's harvest-now-decrypt-
  later stance) for true public-verifiability. It needs a crypto dependency the
  project does not yet take.
