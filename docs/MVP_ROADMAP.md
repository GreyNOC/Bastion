# MVP Roadmap

Phased milestones. Phase 0 is the current MVP; later phases are proposed direction.
Small, safe, working increments are preferred over large rewrites.

## Phase 0 — MVP (delivered)

The working console described in this repository.

- [x] Shared schema for findings, threats, identities, detections, playbooks,
      assets, evidence, reports, validation results.
- [x] Concentrated safety layer: masking + scrubbing, network fetch guard
      (SSRF/HTTPS/allowlist/caps/redirects), ReDoS guard, safety-status snapshot.
- [x] SQLite persistence with a Postgres-ready repository pattern and audit log.
- [x] Eight clean-room adapters (Detector-Engine, NHI, DMZ, Detections, Playbooks,
      HomeGuard, Port-Manager, GreyIQ) with failure isolation.
- [x] Four analytical services + Report Center (HTML/MD/JSON/CSV/SARIF/PDF) +
      Evidence Center (integrity-checked bundles).
- [x] CLI (`status`, `doctor`, `forecast`, `identities`, `detections`, `playbooks`,
      `assets`, `report`, `serve`).
- [x] Local dashboard (9 pages, loopback-bound, dark command-post theme) with a JSON
      health route.
- [x] Optional local AI assistant (disabled by default; command execution disabled).
- [x] Test suite covering schemas, masking, SSRF blocking, report generation,
      adapter failure handling, detection + identity fixture flows, dashboard health,
      CLI doctor, and no-full-secrets-in-output.
- [x] Documentation set (README, ARCHITECTURE, SAFETY_MODEL, OPERATOR_GUIDE,
      MVP_ROADMAP, INTEGRATION_NOTES).

## Phase 1 — Hardening & fidelity

- [ ] Guarded live-fetch fetcher wired to `netguard` (still off by default) with
      per-source caching and offline fallback.
- [ ] Richer threat scoring: hazard-model exploit timing (p50/p90) and calibration,
      porting more of Detector-Engine's predictive layer.
- [ ] STIX 2.1 and ATT&CK Navigator exporters for the Threat Forecast module.
- [ ] Custom rule-pack loader (ReDoS-guarded) for user detections and NHI rules.
- [ ] Known-good asset baselines with "clear this risk" UX and stable finding
      signatures across scans.
- [ ] Post-quantum readiness view (crypto inventory, Mosca margin) from the ported
      playbook/CBOM formulas.

## Phase 2 — Scale & collaboration

- [ ] Postgres backend behind the existing repository interface.
- [ ] Case management: assign / track / close findings with a persistent workqueue.
- [ ] Report scheduling and export delivery (local files first; opt-in destinations).
- [ ] Real authentication + RBAC + full audit trail for multi-operator use.
- [ ] Optional live telemetry ingestion for validating detections against real logs
      (in addition to synthetic replay).

## Phase 3 — Ecosystem

- [ ] Signed detection and threat-intel bundles for air-gapped transfer.
- [ ] Pluggable notification fabric (email / Slack / webhook) for defensive alerts,
      routed through the egress guard.
- [ ] A cross-module scheduler/orchestrator for combined workflows.
- [ ] Packaged desktop distribution.

## Non-goals (permanent)

Anything offensive. See [SAFETY_MODEL.md](SAFETY_MODEL.md). No exploitation, payload
generation, credential replay, brute forcing, public scanning, malware behavior,
evasion, persistence, or attack automation will be added in any phase.
