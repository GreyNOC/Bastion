# Threat model

A short, practical threat model for GreyNOC Bastion itself — a defensive tool
that handles sensitive inputs (repos, credentials-in-source, local asset
inventory, threat intel) and must not become a liability.

## What Bastion is

A local-first defensive console run by an authorized operator on a machine they
control, to analyze **their own** systems. It is not a service exposed to
untrusted users by default.

## Assets to protect

1. **Discovered secrets.** Credentials found in scanned repos/configs.
2. **Operator data.** Findings, reports, asset inventory, evidence bundles.
3. **The host.** Bastion must not become a foothold or an SSRF pivot.
4. **Integrity of intel.** Detections, forecasts, and evidence shouldn't be
   silently tamperable.

## Trust boundaries

- **Scanned content is untrusted data.** Repo files, configs, and feed records
  are treated as data, never instructions. The AI assistant screens for
  prompt-injection and wraps untrusted content; rule regexes pass a ReDoS guard.
- **The network is off by default.** Live fetching is disabled; when enabled it
  is HTTPS-only, allowlisted, size/timeout-capped, and refuses private/loopback/
  CGNAT/test-net hosts (SSRF).
- **The dashboard is loopback-only by default.** Remote exposure fails closed
  unless explicitly overridden *and* protected by a token; POST actions are
  CSRF-protected.

## Threats considered and mitigations

| Threat | Mitigation | Where |
| --- | --- | --- |
| Secret leakage via output/logs | Mask at discovery; scrub every report format and log line; only fingerprints stored | `safety/masking.py`, `utils/logging.py` |
| Credential misuse by the tool | Never validate/replay/transmit a credential; liveness always "unknown" | `adapters/nhi_adapter.py` |
| SSRF via a fetch/redirect | Fail-closed netguard: HTTPS + allowlist + private-host block (with DNS resolution) + per-redirect re-check | `safety/netguard.py`, `safety/fetcher.py` |
| Unsafe user detection rule (ReDoS) | Custom rules are linted + ReDoS-screened on load; unsafe ones rejected | `adapters/dmz_adapter.py` |
| ReDoS via untrusted rule regex | Screen shapes + nested-quantifier detection before compile | `utils/redos.py` |
| Remote dashboard exposure | Refuse non-loopback bind without override + token; Bearer auth; CSRF on POST | `web/server.py` |
| CSV/formula injection in reports | Neutralize leading `= + - @` cells | `services/report_center.py` |
| Zip-slip via evidence bundle | Sanitize archive entry names | `services/evidence_center.py` |
| Unbounded active checks | Passive by default; active is opt-in, loopback-only, bounded, logged | `services/asset_exposure.py` |
| Tampered evidence bundle | Per-entry SHA-256 integrity + `evidence verify` (signing planned) | `services/evidence_center.py` |
| Hidden telemetry | No network connection the operator did not configure | (whole codebase) |

Each row above is exercised by a test in [`../tests`](../tests). See the
enforcement table in [SAFETY_MODEL.md](SAFETY_MODEL.md).

## Out of scope / known limitations

- **Multi-tenant / untrusted-user hosting.** Bastion is single-operator; there is
  no RBAC yet (planned, Phase 2). Do not expose it to untrusted users.
- **Cryptographic authenticity of evidence.** Bundles are tamper-*evident*
  (hash), not tamper-*proof* (no signature yet — Phase 3).
- **Active network reconnaissance.** Intentionally not built. Active checks are
  limited to loopback liveness of your own services.
- **DNS rebinding on live fetch.** Mitigated: the guarded fetcher resolves the
  host once, refuses if *any* returned address is non-public, and **pins the
  connection to the vetted IP** (with SNI/cert validation against the real
  hostname), so a DNS flip between check and connect cannot redirect the socket
  to a private/loopback/metadata address. The allowlist remains the primary
  control (only operator-approved hosts are fetchable at all).
- **Host compromise.** Bastion assumes the host it runs on is trusted; it does
  not defend against a fully compromised host.

## Reporting

Security issues: see [`../SECURITY.md`](../SECURITY.md). Do not open a public
issue for an unpatched vulnerability.
