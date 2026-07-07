# Integration Notes

How GreyNOC Bastion was assembled from the source repositories: what each
contributed, what was deliberately excluded, and the conflicts that shaped the
architecture. This is the "audit → integration plan" record.

## Integration strategy: clean-room adapters + ported data

Bastion does **not** import the source packages directly. It reimplements their
*defensive* logic behind adapters and ports their *data* into
`src/greynoc_bastion/fixtures/`. This was a deliberate decision driven by the audit:

1. **Hard dependency conflicts.** The source repos disagree at the framework level —
   Detector-Engine uses FastAPI + `uvicorn>=0.46`, GreyIQ uses a custom ASGI stack
   pinned `uvicorn>=0.34,<0.35` (a hard conflict), DMZ/HomeGuard use stdlib
   `http.server`, and model layers split between Pydantic v2 and stdlib dataclasses.
   No single import graph satisfies all of them.
2. **CLI collision.** Detector-Engine and GreyIQ both register a `gn` console
   script. Bastion needs one namespaced CLI (`bastion`).
3. **Offensive surface.** A few repos contain code that must never enter a
   defensive-only product (see "Excluded" below). Reimplementing behind adapters
   guarantees it cannot be pulled in transitively.
4. **Safety guarantees.** Clean-room adapters let Bastion enforce masking, SSRF
   blocking, and draft-until-validated uniformly, and cover them with tests.

The result: repo-specific logic is isolated behind adapters (per the spec), the
original projects are untouched, and the valuable data (rule packs, playbooks,
knowledge bases, fixtures) is preserved verbatim.

## Contribution map

| Bastion module | Source repo | What was ported | Form |
| --- | --- | --- | --- |
| Threat Forecast | **Detector-Engine** | NVD 2.0 CVE / CISA KEV / FIRST EPSS feed parsing; explainable multi-signal scoring (exploitability, exposure, ransomware relevance, remediation priority, fused urgency); named score drivers; draft-detection generation | Reimplemented (`detector_engine_adapter.py`) + fixtures (`fixtures/threat_feeds/`) |
| Identity Blast Radius | **Non-Human-Identity-Engine** | `SECRET_KEYS` env-var knowledge base (30+ keys incl. 13 AI providers); secret masking + one-way fingerprinting; placeholder suppression; identity typing; blast-radius / permission-chain derivation; root-confined, symlink-safe traversal | Reimplemented (`nhi_adapter.py`, `safety/masking.py`) + sample project fixture |
| Detection Validation | **DMZ** | Rule/telemetry model; `value_matches` operator set; threshold/window aggregation; scenario + TP/TN rule-test validation; MITRE technique extraction | Reimplemented (`dmz_adapter.py`) + the 13-rule GNOC pack, tests, telemetry, scenarios, runbooks (`fixtures/detections`, `fixtures/telemetry`, `fixtures/scenarios`, `fixtures/runbooks`) |
| Detection lifecycle | **Detections** | Draft → validating → validated → needs_tuning → deprecated lifecycle; promotion requires a passing validation result | Reimplemented (`detections_adapter.py`) |
| Operator Playbooks | **Playbooks** | 30 defensive markdown playbooks + CONVENTIONS + README; H1/H2/MITRE/section-5-JSON/response-checklist parsing | Data ported verbatim (`fixtures/playbooks/`) + parser (`playbooks_adapter.py`) |
| Assets & Exposure | **HomeGuard** | `DEFAULT_RISKY_PORTS` (23 ports with plain-English "why"); exposure-aware severity; hedged indicator notes; safe, local-only remediation guidance | Reimplemented with ported data (`homeguard_adapter.py`) |
| Assets & Exposure | **Port-Manager** | `COMMON_PORTS` + `DEV_HINTS` dev-server labeling; `classifyAddress` scope taxonomy; passive socket-table reading (lsof/ss/netstat/`netstat -ano`) | Reimplemented in Python (`port_manager_adapter.py`) |
| Local AI Assistant | **GreyIQ** | `trust.py` prompt-injection signal set + zero-width detection; untrusted-data wrapping; deterministic explain/summarize/ticket helpers | Reimplemented as a defensive subset (`greyiq_adapter.py`) |
| Report & Evidence Center | *(new)* | Unified cross-module reporting + evidence bundles | New (`report_center.py`, `evidence_center.py`) |

## Overlaps and conflicts resolved

The audit surfaced these; Bastion resolves each as noted:

- **Three incompatible "Finding" schemas** (NHI, HomeGuard, GreyIQ) plus
  Detector-Engine's `GeneratedDetection`. → One unified `BastionFinding`.
- **Severity/scoring divergence** — GreyIQ added an `info` tier; scoring bands and
  scales disagreed across repos. → One `Severity` (info/low/medium/high/critical) and
  one explainable 0.0–1.0 scoring model.
- **`gn` CLI collision** (Detector-Engine vs GreyIQ). → One namespaced `bastion` CLI.
- **HTTP framework conflict** (FastAPI vs custom ASGI vs stdlib; a hard uvicorn pin
  clash). → One Flask dashboard, loopback-bound.
- **Duplicated report generators** (SARIF ×2, HTML ×4, Markdown ×4; PDF only in
  HomeGuard; STIX/Navigator only in Detector-Engine; CSV only in HomeGuard). → One
  Report Center emitting all formats.
- **Four separate SSRF/egress guards.** → One canonical `safety/netguard.py`.
- **Multiple secret-redaction implementations.** → One `safety/masking.py`.
- **Flat-file vs SQLite storage split.** → One SQLite layer for all modules.
- **Multiple MITRE sources of truth.** → Techniques are extracted per artifact into
  the shared schema rather than maintaining a competing catalog.

## Bugs fixed on import

- **GNOC-DISC-001 regex** (from DMZ): the rule's `match.message.value` used `\b` in a
  JSON string, which JSON parses as a **backspace** (0x08) — so `\bnet\s+user\b`
  could never match "net user". Corrected to `\\b` in
  `fixtures/detections/rules/GNOC-DISC-001.json`; verified by
  `test_detection_validation.py::test_disc_rule_regex_bug_is_fixed`.
- **Severity sort order** (from DMZ): the source sorted severities alphabetically.
  Bastion sorts by an explicit `Severity.rank`.
- **ReDoS exposure** (from DMZ, which ran rule regexes with no guard): all
  externally-sourced regexes now pass `utils/redos.py` before compilation.

## Deliberately excluded (offensive or unsafe)

These were flagged in the audit and are **not** present in Bastion:

- **GreyIQ `bughunter/` suite** — live credential replay/validation against real
  Google/GitHub/Slack/OpenAI/AWS/Stripe APIs, recon/DNS/fingerprinting, active web
  scanning, OOB/SSRF interaction, subdomain takeover, headless-Chromium proofs.
  Excluded wholesale.
- **GreyIQ `agent.py`** `run_command` (shell `subprocess`) and `net_probe` (which
  intentionally allowed RFC1918/loopback outbound); and `Finding.secret_value` which
  stored **raw** credentials. Not ported; Bastion's assistant has no command
  execution and never stores raw secrets.
- **Playbooks** `07-bugbounty-pqc-e2ee-methodology.md` and
  `08-bugbounty-crypto-implementation-defects.md` — authorized *offensive*
  methodology. Never copied into `fixtures/playbooks/`; the adapter also filters any
  `bugbounty` file defensively.
- **HomeGuard** system-mutation/surveillance modules — `firewall.py` (netsh rule
  rewrites), `quarantine.py`/`realtime.py` (move/delete user files),
  `virus_scanner.py` (reads other processes' memory), and `flow_source.py`'s
  SSH-into-router-as-root. Not ported; Bastion's asset review is read-only.
- **HomeGuard** `signed_feed.py` hardcoded DEV trust anchors. Not shipped.
- **Port-Manager** process stop/kill (SIGTERM), PowerShell `-ExecutionPolicy Bypass`
  string interpolation, and the auto-npm-install CLI shim. Omitted; only passive
  inventory concepts were ported.
- **`verify_tls: false` / `ssl.CERT_NONE`** (from DMZ outbound adapters). Dropped
  entirely — Bastion never disables TLS verification.
- **Committed build artifacts / live state** (GreyIQ `dist/`, `runtime/` session
  tokens, `elevate.exe`; stale wheels; `.venv`/`node_modules`). Never imported.

## QA/QC hardening pass

After the initial build, an adversarial multi-agent review (8 module reviewers,
each finding verified by an independent refuter) plus dynamic fuzzing surfaced
and fixed the following, all now covered by regression tests:

- **Secret-leak backstop gaps.** `affected`/`source` were not scrubbed in the
  SARIF and HTML renderers; the AWS-key regex used a capturing group that
  redacted only the `AKIA` prefix (and collapsed all AWS keys to one
  fingerprint); the prompt-injection excerpt and the CSV `source` column were
  unscrubbed; the high-entropy backstop required a digit (missing all-letter
  tokens); and the identity masking invariant let short/`*`-containing raw
  values through. All closed.
- **CSV formula injection.** Report CSV cells beginning with `= + - @` are now
  neutralized (OWASP CSV Injection).
- **Evidence-bundle zip-slip.** A `correlation_id` with `../` could produce a
  traversing archive entry; entry names are now sanitized.
- **Detection matching.** Scalar matches are now exact equality (substring
  over-matched, e.g. `200` inside `2000`); the two free-text `message` rules use
  an explicit `contains` op. Group-by now resolves `host`/`user` from nested
  `fields`. A regex refused by the ReDoS guard is logged instead of silently
  never matching.
- **ReDoS guard.** Broadened to reject the general "unbounded quantifier nested
  in a quantified group" family (e.g. `(\w+\s?)*`) that the shape heuristics
  missed; the high-entropy scrub pattern is length-bounded so it stays
  linear-time.
- **Robustness.** `from_dict` no longer crashes on non-iterable list values or
  writes `None` into a non-optional enum field (falls back to the field
  default); EPSS is clamped to [0,1] and CVSS is numerically coerced; validation
  now passes the all-clear case (nothing expected, nothing fired); DB severity
  ordering uses true rank, not alphabetical text; `verify_bundle` reports
  malformed archives instead of raising; `BASTION_HOME` is resolved to an
  absolute path; the Flask session key is per-process, not a committed constant.

## Full-capacity engine upgrade

After the MVP + QA/QC, the engines were brought to full capacity (grounded in the
upstream repos' real logic via a per-engine design pass). Added:

- **Shared knowledge bases** (`knowledge/`): a curated ATT&CK enterprise catalog
  (14 tactics, 63 techniques) with keyword inference, an AI-abuse taxonomy (OWASP
  LLM/Agentic aligned), post-quantum primitives + HNDL + Mosca-margin, and the
  OWASP NHI Top 10 map. These are the shared join vocabulary the correlation spine
  uses.
- **Threat Forecast**: a real exploit-**timing** forecast (probability + horizon
  p50/p90 + confidence + window: already-exploited / imminent / near-term / …),
  ATT&CK technique inference from CVE text, AI-abuse classification, post-quantum
  (HNDL) assessment, and STIX 2.1 + ATT&CK Navigator layer export.
- **Identity Blast Radius**: structural parsing of MCP server configs and
  Kubernetes Secret manifests, OWASP NHI Top 10 references on every identity, and a
  cross-identity **risk-path** graph (escalation chains to privileged sinks).
- **Detection Validation**: a rule **linter** (structure, MITRE-id validity,
  operator validity, ReDoS gate), an ATT&CK **coverage map** with tactic gaps, and
  host-level **incident correlation** with dwell time (chains multi-stage activity
  into one incident).
- **Assets & Exposure**: a known-good **baseline** + **drift** detection with a
  stable service signature.
- **Correlation spine** (`services/correlation.py`): the cross-engine layer that
  makes Bastion one console. It links threats ↔ detections ↔ playbooks ↔ assets by
  ATT&CK technique and host, and surfaces the highest-value operator insight —
  **forecasted techniques with no validated detection coverage** (a "coverage
  gap") and which playbook applies.

All additions are deterministic, offline, defensive-only, and keep the masked-secret
guarantee (verified by test that no secret reaches any report/export). Borderline or
offensive upstream capabilities flagged by the design pass were dropped (e.g. live
PowerShell owner-enrichment, git-history secret pull) or gated.

## Highest-value, lowest-risk imports (as identified by the audit)

1. Detector-Engine scoring/forecast concepts + feed fixtures → Threat Forecast.
2. NHI masking/fingerprinting design → the cross-cutting `safety/masking.py`.
3. DMZ detection-validation core + the 13-rule GNOC pack and TP/TN tests →
   Detection Validation.
4. The 30 defensive Playbooks + CONVENTIONS → Operator Playbooks (data-only).
5. A single canonical egress guardrail (Detector-Engine's `DefensiveHttpClient`
   merged with DMZ's link-local-as-external SSRF logic) → `safety/netguard.py`.
