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

- [x] Threat Forecast: real exploit-**timing** forecast (probability + horizon
      p50/p90 + confidence + window), ATT&CK technique inference, AI-abuse and
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

## Phase 1B — Hardening & packaging (in progress)

- [x] GitHub Actions CI across Python 3.10 / 3.11 / 3.12.
- [x] Dev tooling + config: ruff, mypy, bandit, pip-audit.
- [x] Dashboard **fail-closed binding** (loopback only unless
      `BASTION_ALLOW_REMOTE_DASHBOARD=1` **and** `BASTION_DASHBOARD_TOKEN`).
- [x] Dashboard **token auth** (Bearer) + **CSRF** on POST actions.
- [x] CLI active-check gating (`--active` requires `BASTION_ACTIVE_CHECKS=true`)
      with a bounded, loopback-only liveness confirmation.
- [x] `bastion evidence verify` command.
- [x] Repo polish: dependabot, CONTRIBUTING, PR template, release process,
      threat model.
- [ ] Guarded live-fetch fetcher wired to `netguard` (still off by default),
      with per-source caching and offline fallback.
- [ ] Custom rule-pack loader (ReDoS-guarded) for user detections and NHI rules.
- [ ] Packaged distribution (portable build / wheels on release).

## Phase 2 — Scale & collaboration (planned)

- [ ] Postgres backend behind the existing repository interface.
- [ ] Case management: assign / track / close findings; persistent workqueue.
- [ ] Real authentication + RBAC + full audit trail for multi-operator use.
- [ ] Report scheduling and export delivery (local first; opt-in destinations).
- [ ] Optional live telemetry ingestion for validating detections against real
      logs (in addition to synthetic replay).

## Phase 3 — Signed ecosystem & integrations (planned)

- [ ] **Signed evidence bundles** and signed threat-intel bundles for
      tamper-evident, air-gapped transfer (see `EvidenceCenter.sign_bundle`,
      currently a documented `NotImplementedError` scaffold — not yet real).
- [ ] Pluggable notification fabric (email / Slack / webhook), routed through
      the egress guard.
- [ ] A cross-module scheduler/orchestrator for combined workflows.

## Non-goals (permanent)

Anything offensive: exploitation, payload generation, credential replay, brute
forcing, public scanning, malware behavior, evasion, persistence, or attack
automation. See [SAFETY_MODEL.md](SAFETY_MODEL.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
