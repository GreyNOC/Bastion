# Security Policy

GreyNOC Bastion is a defensive product. Its security posture is part of the product.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the GreyNOC maintainers. Do not open a
public issue for an unpatched vulnerability. Include reproduction steps, affected
version, and impact assessment. You will receive an acknowledgement, and a fix or
mitigation plan will be communicated before any public disclosure.

## Product security guarantees

These are enforced in code and covered by the test suite (see `tests/`):

- **Loopback binding.** The local API and dashboard bind to `127.0.0.1` by default.
  Binding to any other address requires an explicit configuration change.
- **No live network fetching by default.** Threat-feed fetching is off until the
  operator enables it. When enabled, fetching is HTTPS-only, restricted to an
  allowlist, size-capped, timeout-capped, redirect-validated, and always refuses
  private/loopback/link-local destinations.
- **No full secrets at rest or in output.** Discovered credentials are masked at the
  point of discovery. Only masked previews and fingerprint hashes are stored, logged,
  or reported. Bastion never validates, replays, or transmits a discovered credential.
- **No hidden telemetry.** Bastion makes no network connections you did not configure.
- **No command execution by the AI assistant by default.** Assistant command execution
  is a separate opt-in gate, is logged, and is confined to an explicit workspace.
- **Active checks are private-only.** Optional active asset checks refuse public
  targets, are bounded, and are logged.

## Scope boundaries

Bastion will not implement, and pull requests will be rejected for: exploitation,
payload generation, credential replay, brute forcing, unauthorized scanning, malware
execution, evasion, persistence tooling, or attack automation. See
`docs/SAFETY_MODEL.md` for the full safety model.

## Supported versions

Pre-1.0: only the latest release receives fixes.
