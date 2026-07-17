# Roadmap

Honest status: what is **delivered**, what is **in progress**, and what is
**planned**. Non-goals (anything offensive) are permanent — see
[SAFETY_MODEL.md](SAFETY_MODEL.md).

## Phase 0 — MVP (delivered)

- [x] Shared schema (findings, threats, identities, detections, playbooks,
      assets, evidence, reports, validation results).
- [x] Safety layer: secret masking + scrubbing, network fetch guard
      (SSRF/HTTPS/allowlist/caps/redirects), ReDoS guard, safety-status snapshot.
- [x] SQLite persistence with a Postgres-ready repository pattern and audit log.
- [x] Eight clean-room adapters + four analytical services + Report Center
      (HTML/MD/JSON/CSV/SARIF/PDF) + Evidence Center (integrity-checked bundles).
- [x] CLI and a loopback-bound dashboard.
- [x] Test suite and documentation set.

## Phase 1A — Engine fidelity (delivered)

- [x] Threat Forecast: EPSS 30-day probability plus explicitly assumed
      constant-hazard p50/p90 timing; KEV observed-exploitation status; ATT&CK inference, AI-abuse and
      post-quantum (HNDL) dimensions.
- [x] STIX 2.1 bundle export and ATT&CK Navigator layer export.
- [x] Identity Blast Radius: structural MCP/Kubernetes-Secret parsing, OWASP NHI
      mappings, cross-identity risk-path graph.
- [x] Detection Validation: rule linter, ATT&CK coverage map + gaps, host
      incident correlation with dwell time.
- [x] Assets & Exposure: known-good baseline + drift detection.
- [x] Cross-engine correlation spine (coverage-gap insight).
- [x] Shared knowledge bases (ATT&CK, AI-abuse, post-quantum, OWASP NHI).
- [x] Per-engine technical explanations ([docs/explanations](explanations/)).

## Phase 1B — Hardening & packaging (delivered)

- [x] GitHub Actions CI across Python 3.10 / 3.11 / 3.12.
- [x] Dev tooling + config: ruff, mypy, bandit, pip-audit.
- [x] Built-in dashboard server **fail-closed binding** (strictly loopback only;
      remote deployment requires a production HTTPS WSGI server).
- [x] Dashboard **token auth** (Bearer) + **CSRF** on POST actions.
- [x] CLI active-check gating (`--active` requires `BASTION_ACTIVE_CHECKS=true`)
      with a bounded, loopback-only liveness confirmation.
- [x] `bastion evidence verify` command.
- [x] Repo polish: dependabot, CONTRIBUTING, PR template, release process,
      threat model.
- [x] Guarded live-fetch fetcher wired to `netguard` (off by default): every
      request and redirect is HTTPS-only, allowlisted, SSRF-blocked, and
      size/time-capped (`bastion forecast ingest --url`).
- [x] Custom detection rule-pack loader (`BASTION_RULES_DIR` /
      `bastion detections load-custom`): linted + ReDoS-screened; accepted rules
      stay drafts until validated.
- [x] Per-source fetch caching + offline fallback for live feeds: an
      integrity-checked (SHA-256) disk cache keyed by URL. A fresh copy (within
      TTL) is served with no network request; on a transport failure a stale
      copy is served as a fallback; `--offline` / `--refresh` control the mode.
      The cache is never a policy bypass — the HTTPS+allowlist guard is
      re-checked on every ingest.
- [x] Packaged distribution: `python -m build` wheels + sdist and per-OS
      self-contained portable bundles, built, verified, and published on tag by
      [release.yml](../.github/workflows/release.yml). See
      [RELEASE_PROCESS.md](RELEASE_PROCESS.md).

Phase 1B is complete.

## Phase 2 — Scale & collaboration (delivered)

- [x] Case management (`bastion cases`, dashboard *Cases* page): open / assign /
      note / close / reopen, a persistent workqueue (unassigned-first, severity
      ordered), a triage sweep that opens cases for untracked high+ findings
      (idempotent), secrets scrubbed from titles/notes, every mutation audited.
- [x] Real authentication + RBAC + full audit trail (`bastion users`, dashboard
      login): PBKDF2-HMAC-SHA256 (600k iterations, unique salts), roles
      `viewer < operator < admin`, constant-time + timing-equalized
      verification, login throttling, last-admin protection, role changes
      effective immediately, an *Audit Trail* page, and CLI `bastion audit`.
      With **zero** accounts the dashboard keeps its original single-operator
      local-trust mode; the first account switches it to login-required.
      The static dashboard token remains the machine channel and maps to
      `operator` — account management always needs a real admin login.
- [x] Report scheduling + export delivery (`bastion schedule`, dashboard
      *Schedules* page): persisted report/workflow schedules with a local,
      explicit runner (`bastion schedule run-due`, wired to cron/systemd by the
      operator — Bastion installs no daemon), local directory delivery of
      report outputs, enable/disable/remove, all runs audited.
- [x] Live telemetry ingestion (`bastion detections replay --file`): replay the
      whole rule pack over a **local** JSONL / JSON-array log file with
      size/event caps, malformed-line tolerance, host incident correlation,
      and scrubbed, evidence-first findings for every rule that fires.
- [~] Postgres backend: **deliberately deferred.** The repository layer is the
      seam (JSON-document tables + promoted columns, no SQLite-isms in
      services), but shipping an untestable driver would violate this repo's
      "tested or absent" rule — and a Postgres dependency contradicts
      local-first for the target users (Flask stays the only runtime
      dependency). It moves to Phase 4 with a real integration-test story.

## Phase 3 — Signed ecosystem & integrations (delivered)

- [x] **Signed evidence bundles**: `bastion evidence keygen | sign | verify`.
      Detached HMAC-SHA256 signature over the whole bundle file, local key
      (owner-only POSIX mode/Windows ACL; rotation is explicit), non-reversible key ids, constant-time
      verification. Trust model stated honestly: shared-key tamper evidence
      for air-gapped transfer — not third-party non-repudiation. An asymmetric
      (Ed25519 / PQ-hybrid) scheme stays planned; it needs a crypto dependency
      this project doesn't take yet.
- [x] Pluggable notification fabric (`bastion notify test`): OFF by default;
      local JSONL file sink when enabled; opt-in HTTPS webhook sink on top,
      routed through the same egress guard as live fetching (allowlist, SSRF
      block, IP-pinning, caps, redirects refused). Payloads scrubbed; every
      dispatch audited; sink failures reported, never fatal.
- [x] Cross-module orchestrator (`bastion orchestrate`): named workflows
      (`full-sweep`, `validate-and-report`, `morning-check`) that chain the
      engines, correlation, case triage, and reporting; per-step outcomes;
      one failed step never aborts the rest; runs audited + notified.

## Phase 4 — Later (planned)

- [ ] Postgres backend behind the existing repository interface, with a real
      integration-test story (containerized Postgres in CI).
- [ ] Asymmetric bundle signing (Ed25519, optional post-quantum hybrid).
- [ ] Additional notification sinks (email) behind the same egress guard.

## Non-goals (permanent)

Anything offensive: exploitation, payload generation, credential replay, brute
forcing, public scanning, malware behavior, evasion, persistence, or attack
automation. See [SAFETY_MODEL.md](SAFETY_MODEL.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
