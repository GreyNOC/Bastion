# GreyNOC Bastion

**A local-first defensive cyber operations platform for under-defended organizations.**

GreyNOC Bastion is a single defensive console that forecasts cyber threats, audits
non-human identities, validates detections against synthetic telemetry, maps risky
local services and exposed assets, and produces action plans tied to recorded evidence for
operators, public-sector IT teams, and infrastructure defenders.

It is built for people who defend critical systems with limited resources. It runs
on your machine, keeps your data local by default, and never performs offensive
actions.

> **Defensive only.** Bastion does not exploit, generate payloads, replay
> credentials, brute force, scan public targets, execute malware, or automate
> attacks. See [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md).

---

## What it does

Bastion unifies nine operator modules behind one console and one shared data model,
plus an optional deterministic report-formatting helper:

| Module | What it gives a defender | Source lineage |
| --- | --- | --- |
| **Threat Forecast** | CVE / CISA KEV / EPSS intel ranked by urgency. EPSS remains a 30-day probability; p50/p90 timing is derived under a disclosed constant-hazard assumption, while KEV is reported as exploitation already observed. Includes ATT&CK inference and STIX / ATT&CK Navigator export. | Detector-Engine |
| **Identity Blast Radius** | Scans repos/projects for API keys, service accounts, CI/CD tokens, OAuth apps, webhooks, model gateways, MCP servers (structural), k8s Secrets, and AI agents — **secrets always masked** — with OWASP NHI mappings and cross-identity **risk paths**. | Non-Human-Identity-Engine |
| **Detection Validation Range** | Replays synthetic telemetry, plus a rule **linter**, an ATT&CK **coverage map** with gaps, and multi-stage **incident correlation**. | DMZ + Detections |
| **Operator Playbooks** | 30 defensive playbooks (identity attacks, ransomware, lateral movement, AI-agent abuse, post-quantum readiness, E2EE) with response checklists. | Playbooks |
| **Assets & Exposure** | Passive review of local listening services with plain-English explanations and safe, local-only remediation guidance. | HomeGuard + Port-Manager |
| **Correlation** | Cross-engine spine linking threats ↔ detections ↔ playbooks ↔ assets by ATT&CK technique and host; flags **forecasted techniques with no validated detection** (coverage gaps). | (new) |
| **Case Management** | Assign / track / close response work built from findings, with a persistent workqueue, an idempotent triage sweep, scrubbed notes, and a full audit trail. | (new) |
| **Report & Evidence Center** | Reports with recorded source evidence in HTML, Markdown, JSON, CSV, SARIF, PDF, integrity-checked evidence bundles, and **detached bundle signing** (`bastion evidence keygen/sign/verify`). | (new) |
| **Schedules & Workflows** | Persisted report/workflow schedules with a local explicit runner (`bastion schedule run-due`), local delivery, and named cross-module workflows (`bastion orchestrate run full-sweep`). | (new) |
| **Offline report helper** *(optional, off by default)* | Deterministically formats finding explanations, report summaries, and ticket drafts. No model, network client, or command runner is implemented. | GreyIQ (defensive subset) |

Every finding carries the same evidence-first envelope: title, severity, confidence,
evidence, source, affected asset/repo path, why it matters, recommended action,
validation status, false-positive notes, operator notes, timestamp, and a
correlation ID.

### Exploit-timing methodology

[FIRST defines EPSS](https://www.first.org/epss/model) as the probability that a
published CVE will be exploited in the wild in the next 30 days and refreshes the
score daily. Bastion does not relabel CVSS, exposure, or ransomware relevance as a
timing probability. When EPSS is present, it derives time quantiles with a stated
constant-hazard survival model (`lambda = -ln(1-p30)/30`). These quantiles are an
operational estimate, not an independently calibrated FIRST output. When EPSS is
missing, timing is reported as insufficient data. Per the
[FIRST EPSS FAQ](https://www.first.org/epss/faq), known active exploitation takes
precedence; a CISA KEV match is therefore reported as already observed.

---

## Install

Requires Python 3.10+.

```bash
cd GreyNOC-Bastion
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

That installs the `bastion` command. (For development, `pip install -e ".[dev]"`
adds pytest.)

**Release artifacts.** Tagged releases ship a pip-installable wheel/sdist and a
self-contained portable bundle per OS:

```bash
# From a release wheel (Flask is pulled in as the only runtime dependency):
pip install greynoc_bastion-<version>-py3-none-any.whl

# Or grab the portable bundle for your OS, unzip, and run — needs only Python:
unzip bastion-portable-<version>-<platform>.zip && ./bastion-portable-*/bastion status
```

See [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md) for building these locally.

---

## Quick start

```bash
# 0. New here? Just run `bastion` — the landing page shows your safety posture
#    and the best next step for where you are (also: `bastion welcome`).
bastion

# 1. Confirm safe defaults and a healthy environment
bastion doctor

# 2. Rank threats from bundled offline fixtures (no network)
bastion forecast demo --pretty --sectors healthcare,public-sector

# 3. Scan a project for non-human identities (secrets stay masked)
bastion identities scan ./path/to/repo

# 4. Validate the bundled detection pack against synthetic telemetry
bastion detections validate --all

# 5. Review local listening services (passive; no packets sent)
bastion assets scan-local --passive

# 6. Browse operator playbooks
bastion playbooks list
bastion playbooks show 18-ransomware

# 7. Measure detection coverage and lint the rule pack
bastion detections coverage
bastion detections lint

# 8. Correlate across engines — see forecasted techniques with NO detection
bastion correlate

# 9. Export threat intel (STIX 2.1 / ATT&CK Navigator layer)
bastion forecast export --format navigator --out ./out/layer.json

# 10. Replay the rule pack over one of YOUR local log files (JSONL / JSON array)
bastion detections replay --file ./auth-events.jsonl

# 11. Work findings as cases: triage, assign, note, close — with an audit trail
bastion cases triage
bastion cases list --queue
bastion audit

# 12. Run a combined workflow, or schedule reports (local runner, no daemon)
bastion orchestrate run full-sweep
bastion schedule add nightly --every 24 --deliver-to ./out/delivered
bastion schedule run-due          # wire this line to cron / a systemd timer

# 13. Sign and verify evidence bundles for tamper-evident transfer
bastion evidence keygen
bastion evidence sign ./out/<report-id>.evidence.zip
bastion evidence verify ./out/<report-id>.evidence.zip --key ~/.greynoc-bastion/keys/evidence.key

# 14. Build a consolidated report with recorded evidence; open the dashboard
bastion report build --out ./out
bastion serve --host 127.0.0.1 --port 8788
```

Then visit **http://127.0.0.1:8788**.

---

## Safety boundary (read this)

Bastion is safe by default, and those defaults are enforced in code and covered by
tests:

- **Loopback binding.** The built-in dashboard server refuses every non-loopback bind.
  Remote deployments must use a production HTTPS WSGI server.
- **Live fetching is OFF.** When enabled it is HTTPS-only, allowlisted, size- and
  timeout-capped, redirect-validated, and always refuses private/loopback hosts.
- **No full secrets.** Discovered credentials are masked at discovery; only masked
  previews and one-way fingerprints are stored, logged, or reported. Bastion never
  validates or replays a credential.
- **No hidden telemetry.** No network connection you did not configure.
- **Offline report helper off by default.** It is deterministic; this build has no
  model/network integration and no command runner.
- **Active local checks** are private/loopback only, opt-in, bounded, and logged.
- **Generated detections stay drafts** until validated in the Range.
- **Multi-operator auth is opt-in and hash-only.** With no accounts the dashboard
  keeps its loopback local-trust mode; the first `bastion users add` switches it to
  login-required with RBAC (viewer < operator < admin). Passwords are stored only
  as salted PBKDF2 hashes; logins are throttled and audited.
- **Notifications are off by default.** When enabled they append to a local file;
  the optional webhook sink goes through the same HTTPS/allowlist/SSRF egress
  guard as live fetching.
- **Schedules never self-execute.** `bastion schedule run-due` is the only runner —
  you wire it to cron/systemd yourself.

Full model: [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md) ·
Security policy: [`SECURITY.md`](SECURITY.md).

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how adapters, services, and the
  shared schema fit together.
- [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md) — what Bastion will and will not do.
- [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) — how a defender uses each module.
- [`docs/MVP_ROADMAP.md`](docs/MVP_ROADMAP.md) — phased milestones.
- [`docs/INTEGRATION_NOTES.md`](docs/INTEGRATION_NOTES.md) — which source repo
  contributed which functionality, and what was deliberately excluded.
- [`docs/explanations/`](docs/explanations/) — per-engine technical walkthroughs
  with Mermaid flowcharts (Threat Forecast, Identity Blast Radius, Detection
  Validation, Assets & Exposure, Correlation Spine, Safety Layer).

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).
