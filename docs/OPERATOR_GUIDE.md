# Operator Guide

This guide walks a defender through using GreyNOC Bastion day to day. It assumes you
have installed it (`pip install -e .`) and can run `bastion`.

## First run

```bash
bastion doctor      # confirms safe defaults and a healthy environment
bastion status      # shows configuration and how many records are stored
```

`doctor` runs eight self-checks (loopback binding, live-fetch default, database and
report-dir health, playbook corpus, detection-pack validation, secret masking, and
AI command-execution disabled). Its result is recorded and shown on the **Safety
Status** page.

## Using the dashboard

```bash
bastion serve --host 127.0.0.1 --port 8788
```

Open **http://127.0.0.1:8788**. The dashboard is a defensive command post with:

- **Overview** — posture badge, module counts, highest-priority findings, and a
  one-click "Run demo across all modules."
- **Threat Forecast**, **Identity Blast Radius**, **Detection Validation**,
  **Operator Playbooks**, **Assets & Exposure**, **Reports** — one page per module,
  each with a safe action button.
- **Settings** — a read-only view of the resolved configuration.
- **Safety Status** — the live safety posture with warnings for anything moved off a
  safe default.

Every action on the dashboard is local and non-destructive.

## Module by module

### Threat Forecast

Rank threats by urgency using bundled offline CVE / CISA KEV / EPSS fixtures:

```bash
bastion forecast demo --pretty --sectors healthcare,public-sector
```

Each threat shows the drivers behind its score (KEV listing, EPSS probability, edge
exposure, ransomware use, CVSS). To score your own feed export:

```bash
bastion forecast ingest --fixture ./my-cve-export.json --sectors energy
```

Live fetching is off by default; ingestion reads files you already have.

### Identity Blast Radius

Scan a repository or project folder for non-human identities:

```bash
bastion identities scan ./path/to/repo --out ./out
```

You get a masked inventory — API keys, service accounts, CI/CD tokens, OAuth apps,
webhooks, model gateways, MCP servers, AI agents — each with severity, provider, a
masked preview (e.g. `AKIA***************2W`), location, and a derived blast radius
(what the credential could reach if it is live). **Bastion never tests whether a
credential is live.** Obvious placeholders (`changeme`, `your-...-here`) are
suppressed. Rotate and remove anything real; the recommended action explains how.

### Detection Validation Range

Prove whether a detection behaves before you rely on it:

```bash
bastion detections validate --all                       # whole bundled pack
bastion detections validate --scenario ./scenario.json  # one scenario
```

Each result shows expected vs actual alerts and a verdict: `validated`,
`needs_tuning`, or `failed`. A detection is only marked validated when its
true-positive telemetry fires *and* its true-negative telemetry stays silent.
Generated detection ideas stay **drafts** until they pass here.

### Operator Playbooks

Browse defensive doctrine and response checklists:

```bash
bastion playbooks list
bastion playbooks show 18-ransomware
```

Playbooks cover identity attacks, suspicious PowerShell, beaconing, phishing, BEC,
lateral movement, AD credential theft, persistence, web shells, exfiltration,
ransomware, AI-agent abuse, and post-quantum / E2EE / crypto-migration readiness.
Each describes how to **detect and respond to** a technique — never how to perform
it.

### Assets & Exposure

Review local listening services, passively:

```bash
bastion assets scan-local --passive
```

This reads your machine's own socket table (no packets are sent) and explains each
service in plain English, flags risky ones (Telnet, RDP, SMB, VNC, TR-069, …), and
classifies exposure (loopback / LAN / public). Remediation guidance is safe and
local-only — Bastion tells you what to change; it never changes it for you.

### Reports & Evidence

Aggregate everything into an evidence-backed report:

```bash
bastion report build --out ./out --formats html,markdown,json,csv,sarif,pdf
```

You get every format plus an integrity-checked evidence bundle (`.evidence.zip`)
containing a manifest with per-entry SHA-256 hashes, the full report, and one file
per finding. No full secrets appear in any output.

## Verifying an evidence bundle

Evidence bundles carry per-entry SHA-256 integrity. Re-check one at any time:

```bash
bastion evidence verify ./out/<report-id>.evidence.zip
# → Evidence bundle: OK / Report ID / Entries verified / Problems: 0
```

Returns a non-zero exit code (and lists the problems) if the bundle was
tampered with or is malformed. Add `--json` for machine-readable output.

## Active vs passive asset review

The default is passive — Bastion reads your machine's own socket table and sends
no packets:

```bash
bastion assets scan-local            # passive (default)
bastion assets scan-local --passive  # passive, explicit
bastion assets scan-local --active   # bounded, loopback-only liveness confirmation
```

`--active` only runs when `BASTION_ACTIVE_CHECKS=true` is set; otherwise it
refuses with a clear message and does nothing. Active mode is limited to a short
connect to your **own** loopback services — it never probes the LAN or the
internet.

## Exposing the dashboard beyond localhost (advanced)

By default the dashboard binds to `127.0.0.1` and refuses any non-loopback bind.
If you must reach it from another machine, do it deliberately:

```bash
export BASTION_ALLOW_REMOTE_DASHBOARD=1
export BASTION_DASHBOARD_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
bastion serve --host 0.0.0.0 --port 8788
```

Then every request needs the token:

```bash
curl -H "Authorization: Bearer $BASTION_DASHBOARD_TOKEN" http://<host>:8788/
```

Without both the override and the token, `serve` exits with an error rather than
exposing an unauthenticated dashboard. Prefer an SSH tunnel to a loopback bind
over remote exposure where possible.

## Ingesting a live threat feed (opt-in)

Live fetching is off by default. When you enable it, Bastion can pull a CVE feed
over a **guarded** HTTPS request:

```bash
export BASTION_LIVE_FETCH=true
export BASTION_FETCH_ALLOWLIST="services.nvd.nist.gov,www.cisa.gov"
bastion forecast ingest --url https://services.nvd.nist.gov/rest/json/cves/2.0
```

Every request — and every redirect — is evaluated by the network guard: HTTPS
only, host must be on your allowlist, must not resolve to a private/loopback/
CGNAT/test-net address (SSRF), and the response is size- and time-capped. Without
`BASTION_LIVE_FETCH=true` and an allowlisted host, the fetch is refused with a
clear message. Offline ingestion (`--fixture <file>`) needs none of this.

**Caching and offline resilience.** Fetched feed bodies are cached locally and
integrity-checked (SHA-256). Within the TTL (`BASTION_FETCH_CACHE_TTL_SECONDS`,
default 1h) a repeat ingest of the same URL is served from disk with **no**
network request. If a live fetch fails on transport (network down, timeout, TLS),
Bastion serves the last cached copy as a **stale fallback** rather than failing
hard. Two flags give explicit control:

```bash
bastion forecast ingest --url <url> --refresh   # ignore the cache; force a live fetch
bastion forecast ingest --url <url> --offline   # cache only; never touch the network
```

The cache is a performance/availability aid, **never a policy bypass**: the
HTTPS + allowlist guard is re-checked on every ingest, so a cache hit can never
resurrect a URL you have de-allowlisted, and a guard refusal (e.g. a redirect off
the allowlist) is never masked by a stale copy. Set `BASTION_FETCH_CACHE=false`
to disable caching entirely.

## Adding your own detection rules

Point Bastion at a directory of rule JSON files:

```bash
export BASTION_RULES_DIR=/path/to/my/rules
bastion detections load-custom          # or: --rules /path/to/my/rules
```

Each rule is linted and **ReDoS-screened** on load. Rules with structural errors
or unsafe regexes are rejected with reasons; accepted rules are stored as
**drafts** and must pass the Detection Validation Range before they count as
validated (`bastion detections validate`).

## Turning on optional capabilities

All optional capabilities are configured via environment variables or a `.env` file
(copy `.env.example`). After changing them, restart Bastion. The Safety Status page
will warn you about anything now off its safe default.

| To enable | Set | Note |
| --- | --- | --- |
| Live threat-feed fetching | `BASTION_LIVE_FETCH=true` + `BASTION_FETCH_ALLOWLIST=…` | HTTPS-only, allowlisted, capped, private hosts refused, redirects re-checked |
| Custom detection rules | `BASTION_RULES_DIR=/path/to/rules` | Linted + ReDoS-screened on load; accepted rules stay drafts |
| The AI assistant | `BASTION_AI_ASSISTANT=true` | Local, explain/summarize/ticket only |
| A local model endpoint | `BASTION_AI_ENDPOINT=http://127.0.0.1:11434` | Cloud refused unless `BASTION_AI_ALLOW_CLOUD=true` |

Command execution by the assistant remains disabled and refused in the MVP.

## Where your data lives

By default under `~/.greynoc-bastion/` (override with `BASTION_HOME`):

- `bastion.db` — SQLite store (findings, threats, masked identities, validations,
  assets, reports, audit log).
- `reports/` — generated reports and evidence bundles.

Nothing is uploaded anywhere.
