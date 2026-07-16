# Safety Model

GreyNOC Bastion is a defensive product. Its safety posture is a feature, not a
disclaimer. This document states precisely what Bastion will and will not do, and
where each rule is enforced.

## Principles

1. **Authorized environments only.** Bastion is for defending systems you are
   authorized to defend.
2. **Local-first.** Nothing leaves your machine unless you explicitly configure it
   to.
3. **Safe by default.** Every default is the conservative choice. Loosening anything
   is a deliberate, visible operator action.
4. **Defensive only.** No capability that primarily enables attacking others is
   included.

## What Bastion will NOT do

- **No exploitation.** No exploit generation, no payload generation.
- **No credential replay.** Discovered credentials are never validated, replayed,
  or transmitted. Liveness is always reported as "unknown."
- **No brute forcing / password spraying / credential stuffing.** These appear only
  as *defensive playbooks* describing how to detect and respond to them.
- **No malware execution or malware behavior.**
- **No public-target scanning.** Active checks are private/loopback only.
- **No hidden telemetry.** Bastion makes no network connection you did not configure.
- **No helper cloud upload.** The optional report helper has no model or network client.
- **No full secrets in output.** Only masked previews and one-way fingerprints are
  stored, logged, or reported.
- **No helper command execution.** No command runner is implemented.
- **No destructive remediation.** Bastion never changes device settings, firewall
  rules, or files. It explains and recommends; you act.
- **No evasion or persistence tooling.**

## What Bastion enforces (and where)

| Guarantee | Enforced in | Covered by test |
| --- | --- | --- |
| API/dashboard bind to `127.0.0.1` by default | `config.py`, `web/server.py` | `test_cli_and_app.py` |
| Built-in dashboard server refuses every non-loopback bind | `web/server.py` `ensure_bind_allowed` | `test_dashboard_security.py` |
| Dashboard token auth (Bearer) when `BASTION_DASHBOARD_TOKEN` set | `web/server.py` | `test_dashboard_security.py` |
| CSRF token required on dashboard POST actions | `web/server.py` | `test_dashboard_security.py` |
| Active checks require `BASTION_ACTIVE_CHECKS=true` + `--active`; loopback-only | `cli.py`, `services/asset_exposure.py` | `test_dashboard_security.py` |
| Evidence bundles integrity-checked (per-entry SHA-256) | `services/evidence_center.py` | `test_reports.py` |
| Live fetching OFF by default | `config.py` | `test_safety.py` |
| Fetch is HTTPS-only, allowlisted, size/timeout-capped | `safety/netguard.py` | `test_safety.py` |
| Private/loopback/link-local/CGNAT/test-net hosts refused (SSRF) | `safety/netguard.py` | `test_safety.py` |
| Redirects re-validated against the guard | `safety/netguard.py` | `test_safety.py` |
| Secrets masked at discovery; only fingerprints stored | `safety/masking.py`, `adapters/nhi_adapter.py` | `test_identity_scan.py` |
| No full secret in any report format | `services/report_center.py` | `test_reports.py` |
| No full secret in logs | `utils/logging.py` | `test_cli_and_app.py` |
| Credentials never validated (liveness unknown) | `adapters/nhi_adapter.py` | `test_identity_scan.py` |
| Offline report helper disabled by default | `config.py`, `services/ai_assistant.py` | `test_adapters.py` |
| No helper command runner/model/network client implemented | `adapters/greyiq_adapter.py` | `test_adapters.py` |
| Active local checks gated + logged | `services/asset_exposure.py` | `test_cli_and_app.py` |
| Generated detections stay drafts until validated | `schemas/`, `adapters/detections_adapter.py` | `test_schemas.py`, `test_detection_validation.py` |
| Rule regexes screened for ReDoS | `utils/redos.py`, `adapters/dmz_adapter.py` | `test_live_fetch_and_rules.py` |
| Live fetch routes every request + redirect through the guard | `safety/fetcher.py` | `test_live_fetch_and_rules.py` |
| Custom rules are screened/linted and only promote after their own passing test | `adapters/dmz_adapter.py` | `test_live_fetch_and_rules.py` |
| Offensive playbooks excluded | `adapters/playbooks_adapter.py` | `test_adapters.py` |
| Passwords stored only as salted PBKDF2 hashes; verification constant-time and timing-equalized | `auth.py` | `test_auth_rbac.py` |
| First operator account switches the dashboard to login-required; RBAC on every POST | `web/server.py` | `test_auth_rbac.py` |
| Login attempts throttled and audited; role changes effective immediately | `web/server.py`, `auth.py` | `test_auth_rbac.py` |
| Last enabled admin cannot be disabled/demoted/deleted | `auth.py` | `test_auth_rbac.py` |
| Case titles/notes scrubbed of secrets before storage | `services/case_management.py` | `test_cases.py` |
| Telemetry replay reads local files only, size- and event-capped | `services/telemetry_ingest.py` | `test_telemetry_and_notify.py` |
| Notifications OFF by default; webhook sink egress-guarded (HTTPS, allowlist, SSRF, no redirects) | `services/notifications.py`, `safety/fetcher.py` | `test_telemetry_and_notify.py` |
| Schedules never self-execute; `run-due` is the only runner | `services/scheduler.py` | `test_scheduler_orchestrator.py` |
| Web-operator schedule delivery confined to the Bastion home tree | `services/scheduler.py`, `web/server.py` | `test_scheduler_orchestrator.py` |
| Evidence signing key owner-only (POSIX mode/Windows ACL), never logged; signature verification constant-time | `services/evidence_center.py` | `test_evidence_signing.py` |
| Evidence signature covers the attested metadata, not just the bundle digest | `services/evidence_center.py` | `test_evidence_signing.py` |
| Post-login redirect confined to in-app paths (no open redirect via `next`) | `web/server.py` `_safe_next` | `test_auth_rbac.py` |
| Token-bootstrapped sessions bound to the current token (rotation revokes) | `web/server.py` `_request_authed` | `test_auth_rbac.py` |

## Live fetching (when you turn it on)

Live threat-feed fetching is **off by default**. If you set `BASTION_LIVE_FETCH=true`,
every fetch must pass `safety.netguard.evaluate_fetch_target`, which enforces, in
order:

1. Live fetching is enabled.
2. Scheme is `https`.
3. Host is not private/loopback/link-local/CGNAT/test-net (fail closed on
   resolution errors).
4. Host is on your allowlist.

Response-size and timeout caps travel on the decision and are applied by the
fetcher. Redirects are re-evaluated against the same guard.

## Offline report helper

The optional deterministic report helper:

- is **disabled by default** (`BASTION_AI_ASSISTANT=false`);
- has no model or network client;
- **explains, summarizes, and drafts** using deterministic offline helpers that need
  no model at all;
- treats file contents and feed data as **untrusted data**, screening for
  prompt-injection and wrapping content in an explicit data boundary;
- has no command runner; legacy command requests are logged and refused.

## Active local checks

Passive review (reading this machine's own socket table — no packets are sent) is
the default. Any future active check is private/loopback only, opt-in
(`BASTION_ACTIVE_CHECKS=true`), bounded, and written to the append-only audit log.
Bastion never probes public targets.

## Reporting a security issue

See [`SECURITY.md`](../SECURITY.md).
