# Operator Guide

This guide walks a defender through using GreyNOC Bastion day to day. It assumes you
have installed it (`pip install -e .`) and can run `bastion`.

## First run

```bash
bastion doctor      # runs local safety and health checks
bastion status      # shows configuration and how many records are stored
```

`doctor` runs ten self-checks (loopback binding, live-fetch configuration, database and
report-dir health, playbook corpus presence, absence of offensive playbooks, detection-pack
validation, secret masking, confirmation that no helper command runner exists, and which
evidence-signing backends are available). Its result is recorded and shown on the **Safety
Status** page.

## Using the dashboard

```bash
bastion serve --host 127.0.0.1 --port 8788
```

Open **http://127.0.0.1:8788**. The dashboard is a defensive command post with:

- **Overview** — posture badge, module counts, highest-priority findings, and a
  one-click sample load for forecast, detections, identities, and assets.
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
bastion forecast ingest --fixture ./nvd.json --epss ./first-epss.json --kev ./cisa-kev.json
```

Live fetching is off by default; ingestion reads files you already have.

EPSS is the probability of exploitation in the next 30 days. Bastion keeps that
probability intact. Its p50/p90 timing estimate assumes a constant daily hazard:
`lambda = -ln(1-p30)/30`. FIRST does not independently calibrate those timing
quantiles, so every output carries the method and assumption. A CISA KEV match is
reported as exploitation already observed and supersedes future-probability timing.
With no EPSS observation, Bastion reports insufficient data instead of deriving a
date from CVSS or exposure.

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

Aggregate everything into a report with recorded source evidence:

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

## Signing evidence bundles (tamper-evident transfer)

On top of per-entry integrity you can add a **detached signature** over the whole
bundle file:

```bash
bastion evidence keygen                                # once; key stored 0600
bastion evidence sign ./out/<report-id>.evidence.zip   # writes <bundle>.sig.json
bastion evidence verify ./out/<report-id>.evidence.zip --key ~/.greynoc-bastion/keys/evidence.key
```

The default scheme is shared-key HMAC-SHA256: anyone holding the same key file
(exchanged out-of-band, e.g. on removable media for an air-gapped site) can verify
the bundle was not modified in transit. It is honest tamper evidence, **not**
third-party non-repudiation. Rotating the key (`keygen --force`) invalidates old
signatures.

### Public-key signing (asymmetric & post-quantum)

For real third-party non-repudiation — where a verifier needs only your **public**
key, never the secret — install the optional signing backend and generate a
keypair:

```bash
pip install 'greynoc-bastion[pqc]'         # adds the vetted `cryptography` library
bastion evidence backends                  # show which schemes are available
bastion evidence keygen --scheme hybrid    # writes evidence.key (private) + evidence.pub
bastion evidence sign ./out/<report-id>.evidence.zip
bastion evidence verify ./out/<report-id>.evidence.zip --pubkey ~/.greynoc-bastion/keys/evidence.pub
```

Three schemes are available:

| `--scheme`   | Algorithm                     | Property |
| ------------ | ----------------------------- | -------- |
| `ed25519`    | EdDSA, RFC 8032               | Classical public-key non-repudiation. |
| `ml-dsa-65`  | ML-DSA-65, FIPS 204           | Post-quantum non-repudiation. |
| `hybrid`     | Ed25519 **and** ML-DSA-65     | Both signatures; verification requires **both** to pass. Quantum-resistant with a classical safety net — safe unless *both* primitives are broken. `hybrid` is the recommended choice during the PQC transition. |

The private key is written owner-only (POSIX `0600` / Windows ACL); the public key
(`.pub`) is what you distribute so others can verify. Signing covers the bundle
digest **and** the attested sidecar metadata (bundle name, `signed_at`, scheme),
so neither the archive bytes nor the attestation can be altered without breaking
verification. Rotating (`keygen --scheme … --force`) mints a new keypair and
invalidates old signatures.

## Working findings as cases

Findings become trackable response work on the *Cases* page or the CLI:

```bash
bastion cases triage                 # open cases for untracked high+ findings (idempotent)
bastion cases list --queue           # the workqueue: open cases, unassigned first
bastion cases assign <case-id> alice
bastion cases note <case-id> "rotated the token, watching for reuse"
bastion cases close <case-id> --reason "rotated + revoked"
bastion audit                        # every mutation is in the audit trail
```

Notes and titles are scrubbed of secrets before they are stored.

## Replaying your own logs through the rule pack

Beyond synthetic validation, you can replay **local** log files through every
detection rule:

```bash
bastion detections replay --file ./auth-events.jsonl
```

The file is JSONL (one JSON event per line) or a single JSON array. Reads are
size-capped (default 25 MB) and event-capped; malformed lines are counted and
skipped. Rules that fire produce findings marked as live telemetry, plus
host-level incident correlation. Bastion never tails or collects logs itself —
you hand it a file.

## Schedules and workflows

Named workflows chain the engines end-to-end:

```bash
bastion orchestrate list
bastion orchestrate run full-sweep   # forecast → validate → assets → correlate → triage → report
```

Schedules persist the intent; a local runner executes what is due:

```bash
bastion schedule add nightly --every 24 --deliver-to /srv/bastion-drops
bastion schedule add sweep --kind workflow --workflow full-sweep --every 168
bastion schedule run-due             # put THIS in cron / a systemd timer
```

Bastion installs no daemon and nothing fires on its own — `run-due` is the only
executor, and every run lands in the audit trail.

## Multi-operator mode (login + roles)

Out of the box the loopback dashboard trusts the local user (single-operator
mode). To share one Bastion with a team, create accounts:

```bash
bastion users add alice --role admin     # password prompted, never on argv
bastion users add bob --role operator
bastion users add carol --role viewer
```

The moment one account exists, the dashboard requires login. Roles:

| Role | Can |
| --- | --- |
| `viewer` | read every page |
| `operator` | + run modules, work cases, manage schedules |
| `admin` | + manage operator accounts (dashboard *Operators* page) |

Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes; failed logins are
throttled and every attempt is audited. Role changes and disables take effect on
the target's next request — no re-login needed. The last enabled admin can never
be disabled, demoted, or deleted. The static `BASTION_DASHBOARD_TOKEN` (the
machine/API channel) maps to `operator` and can never manage accounts.

## Notifications (opt-in)

`BASTION_NOTIFY=true` turns on the fabric: events (workflow runs, scheduled
reports) append to a local JSONL file (`BASTION_NOTIFY_FILE`). To also POST them
to a webhook, set `BASTION_NOTIFY_WEBHOOK_URL` (HTTPS) **and** put its host on
`BASTION_NOTIFY_ALLOWLIST`; dispatches go through the same egress guard as live
fetching. Test with:

```bash
bastion notify test
```

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

## Accessing the dashboard from another machine

The built-in server always refuses non-loopback binds because it does not provide
production TLS. The simplest safe remote path is an SSH tunnel while Bastion stays
on loopback:

```bash
ssh -L 8788:127.0.0.1:8788 user@bastion-host
# on bastion-host:
bastion serve --host 127.0.0.1 --port 8788
```

For a shared deployment, serve `create_app()` with a production WSGI server behind
an HTTPS reverse proxy, configure operator accounts, set a persistent
`BASTION_WEB_SECRET`, and set `BASTION_SECURE_COOKIES=1`. The legacy
`BASTION_ALLOW_REMOTE_DASHBOARD` flag cannot weaken the built-in server boundary.

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
| Custom detection rules | `BASTION_RULES_DIR=/path/to/rules` | Linted + ReDoS-screened; add `tests/<RULE-ID>.json` to validate and promote, otherwise validation fails |
| Offline report helper | `BASTION_AI_ASSISTANT=true` | Deterministic explain/summarize/ticket formatting; no model or network client |
| Notifications | `BASTION_NOTIFY=true` (+ webhook: `BASTION_NOTIFY_WEBHOOK_URL` + `BASTION_NOTIFY_ALLOWLIST`) | Local file sink; webhook egress-guarded like live fetch |
| Multi-operator login | `bastion users add <name> --role admin` | Not an env var — the first account switches the dashboard to login-required |

No command runner is implemented. Legacy AI endpoint/cloud/command flags are ignored or refused.

## Where your data lives

By default under `~/.greynoc-bastion/` (override with `BASTION_HOME`):

- `bastion.db` — SQLite store (findings, threats, masked identities, validations,
  assets, reports, audit log).
- `reports/` — generated reports and evidence bundles.

Nothing is uploaded anywhere.
