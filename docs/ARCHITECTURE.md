# Architecture

> For per-engine data-flow diagrams (Mermaid), see
> [`explanations/`](explanations/).

GreyNOC Bastion is a modular, local-first Python application. It is organized in
four layers, with a single shared schema running through all of them and a
concentrated safety layer that every other layer depends on.

```
                       ┌─────────────────────────────────────────────┐
   CLI (bastion …)  ─▶ │                 BastionApp                    │ ◀─ Web dashboard
                       │            (composition root)                 │    (Flask, 127.0.0.1)
                       └─────────────────────────────────────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
        Services                    Shared schemas              Safety layer
   (orchestration)              (one vocabulary)            (masking, netguard,
             │                          ▲                     status, redos)
             ▼                          │                          ▲
        Adapters  ───────────── speak schemas ────────────────────┘
   (clean-room source-repo logic + ported data)
             │
             ▼
        SQLite (Postgres-ready repository pattern)
```

## Layers

### 1. Shared schemas (`schemas/`)

One vocabulary used everywhere. Plain dataclasses (no heavy modelling dependency)
with deterministic, JSON-safe serialization and tolerant `from_dict`:

- `BastionFinding` — the universal, evidence-first finding envelope every module
  emits.
- `BastionThreat`, `BastionIdentity`, `BastionDetection`, `BastionValidationResult`,
  `BastionPlaybook`, `BastionAsset`, `BastionEvidence`, `BastionReport` — the typed
  records behind findings.
- Controlled enums (`Severity`, `Confidence`, `ValidationStatus`, `ThreatCategory`,
  `IdentityType`, `AssetKind`, `Exposure`, `EvidenceKind`, `ReportFormat`,
  `FindingCategory`) with tolerant `coerce()` so imported data with looser
  conventions still lands on a known term.

### 2. Adapters (`adapters/`)

Each source repo's defensive logic is isolated behind an adapter that translates it
into Bastion's schemas. Adapters:

- are **clean-room reimplementations + ported data**, not imports of the original
  packages (see [INTEGRATION_NOTES.md](INTEGRATION_NOTES.md) for why);
- are invoked by services through `BaseAdapter.guard()`, which converts adapter
  exceptions to a failed `AdapterResult`; services surface one controlled error;
- carry no offensive capability.

| Adapter | Represents | Provides |
| --- | --- | --- |
| `detector_engine_adapter` | Detector-Engine | Feed parsing (NVD/KEV/EPSS), explainable multi-signal scoring, ranked `BastionThreat`s |
| `nhi_adapter` | Non-Human-Identity-Engine | Repo scanning, secret masking, identity typing, blast-radius derivation |
| `dmz_adapter` | DMZ | Rule loading, telemetry matching (threshold/window), scenario + rule-test validation |
| `detections_adapter` | Detections | Detection lifecycle (draft → validated → deprecated); bridges drafts and the validated pack |
| `playbooks_adapter` | Playbooks | Markdown doctrine parsing → `BastionPlaybook` (MITRE, steps, draft detections) |
| `homeguard_adapter` | HomeGuard | Risky-service knowledge base, plain-English explanations, safe remediation guidance |
| `port_manager_adapter` | Port-Manager | Passive local socket-table reading, dev-server labeling, exposure classification |
| `greyiq_adapter` | GreyIQ | Prompt-injection screening + deterministic explain/summarize/ticket helpers; no model/network/command runner |

### 3. Services (`services/`)

Each service orchestrates one or more adapters, persists results, and emits the
universal `BastionFinding` shape:

- `ThreatForecastService`, `IdentityBlastRadiusService`, `DetectionValidationService`,
  `AssetExposureService` — the four analytical modules.
- `ReportCenter` — renders a report to JSON/Markdown/HTML/CSV/SARIF/PDF (with a
  zero-dependency PDF writer).
- `EvidenceCenter` — packages findings + evidence into an integrity-checked zip
  bundle; also implements detached bundle signing (keygen/sign/verify,
  shared-key HMAC-SHA256).
- `AIAssistantService` — compatibility-named wrapper for the offline report helper; disabled by
  default.
- `CaseManagementService` — findings → assignable, auditable response work with a
  persistent workqueue and an idempotent triage sweep.
- `TelemetryIngestService` — replays the rule pack over local JSONL/JSON log
  files (size- and event-capped) and emits live-telemetry findings.
- `SchedulerService` — persisted report/workflow schedules; `run-due` is the only
  executor (operator wires it to cron/systemd).
- `OrchestratorService` — named cross-module workflows (`full-sweep`, …) with
  per-step outcomes; a failed step never aborts the rest.
- `NotificationFabric` — opt-in local file sink + egress-guarded webhook sink;
  payloads scrubbed, dispatches audited, failures reported not raised.

Operator accounts + RBAC live in `auth.py` (`OperatorStore`): PBKDF2-HMAC-SHA256
hashes, roles `viewer < operator < admin`, last-admin protection. The dashboard
consumes it; with zero accounts the loopback local-trust mode is unchanged.

### 4. Composition root (`app.py`) + interfaces

`BastionApp` wires config + database + adapters + services in one place, so wiring
and safety defaults live in a single, auditable location. Both the **CLI**
(`cli.py`, stdlib `argparse`) and the **web dashboard** (`web/server.py`, Flask)
construct a `BastionApp` and talk only to it.

## Cross-cutting layers

### Safety (`safety/`)

Every hard safety rule lives here so nothing is reimplemented ad hoc:

- `masking` — mask + fingerprint secrets; scrub free text (with a high-entropy
  backstop).
- `netguard` — HTTPS-only, allowlisted, size/timeout-capped fetch evaluation with
  private/loopback/CGNAT/test-net SSRF blocking and redirect revalidation.
- `status` — a single `SafetyStatus` snapshot for the dashboard, `doctor`, and tests.

### Persistence (`db/`)

SQLite with a JSON-document-plus-indexed-columns layout (`schema.sql`). Chosen so
the MVP is flexible and the future Postgres migration is a driver swap plus optional
column/JSONB promotion. Includes an append-only `audit_log` for privileged actions.

### Config (`config.py`)

Dependency-free `.env` + environment loader. Every default is the conservative,
safe choice; loosening anything is an explicit operator action recorded in the
config's `source` provenance and surfaced on the Safety Status page.

### Utilities (`utils/`)

- `logging` — every log record passes through a scrubbing filter (defense in depth).
- `redos` — screens externally-sourced rule regexes for catastrophic backtracking
  before they are compiled or run.

## Data flow (example: `bastion report build`)

1. Services have already stored findings + typed records in SQLite.
2. `BastionApp.build_report()` loads findings, builds a `BastionReport`, recomputes
   the executive summary.
3. `ReportCenter` renders each requested format; `EvidenceCenter` packages a bundle.
4. Every renderer scrubs its output as a final backstop, so no full secret can
   appear even if an upstream producer forgot to mask.
