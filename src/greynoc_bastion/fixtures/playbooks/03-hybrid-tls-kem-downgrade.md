# 03 — Hybrid TLS / KEM Downgrade & Misconfiguration Detection

## Overview

The transition strategy is hybrid: run a classical KEM (X25519/P-256) **and** a PQ KEM
(ML-KEM) together so an attacker must break both. That protection only holds if the hybrid
group is actually negotiated. An adversary positioned in path — or a careless middlebox,
load balancer, or TLS-terminating proxy — can **strip the PQ key share** or force
negotiation down to a classical-only group, quietly re-exposing the session to HNDL. This
playbook detects downgrade of hybrid key exchange, PQ-stripping, and the misconfigurations
that silently disable PQ protection.

## MITRE mapping

- **T1600** — Weaken Encryption (forcing classical-only key exchange).
- **T1557** — Adversary-in-the-Middle (in-path manipulation of `ClientHello`/`ServerHello`).
- **T1562** — Impair Defenses (misconfiguration that disables PQ negotiation as a "defense").
- Downstream link to **T1040** Network Sniffing / HNDL (PB-02) — the payoff of a successful downgrade.

## Detection strategy

Compare **offered** vs. **negotiated** key exchange, per connection and in aggregate, against
a per-endpoint baseline:

1. **Capability vs. outcome.** A client that offered `X25519MLKEM768` but negotiated plain
   `X25519` against a server known to support hybrid is a downgrade signal.
2. **Regression over time.** An endpoint that previously negotiated hybrid and now negotiates
   classical-only — a config regression or active stripping.
3. **In-path mutation.** Evidence that the `key_share`/`supported_groups` extension was altered
   between client and server (size anomalies, removed PQ share, inconsistent views from two
   vantage points).
4. **Misconfiguration scan (posture).** Endpoints that *should* offer hybrid (per policy/CBOM)
   but do not; PQ disabled at a proxy/CDN/load balancer; non-validated PQ provider in path.

## Indicators

- Server supports hybrid in a baseline probe, but live sessions negotiate classical-only at scale.
- `ClientHello` advertised `0x11EC` (X25519MLKEM768) yet the negotiated group is classical.
- TLS-terminating middlebox / WAF / LB that re-originates connections **without** the PQ group
  (PQ ends at the edge; backhaul is classical and may traverse untrusted segments).
- Sudden drop in the proportion of hybrid handshakes for an endpoint after a deploy/change.
- Key-share byte-size anomalies indicating a stripped PQ component (X25519-only share is 32 B;
  X25519MLKEM768 client share is ~1216 B — a "downgraded" session that should be hybrid but
  shows a 32 B share is suspicious).
- Production path using `oqs-provider`/liboqs where a FIPS-validated module is required.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "hybrid_kem_downgrade",
  "join": "tls_handshake.client_offered_groups WITH tls_handshake.negotiated_group",
  "trigger": {
    "client_offered": "contains X25519MLKEM768 (0x11EC) OR any *MLKEM*",
    "negotiated": "classical_only (X25519 | secp256r1 | secp384r1)",
    "server_capability": "known_supports_hybrid == true"
  },
  "severity": "high",
  "enrich": ["client_ip", "server", "path_middleboxes", "asset.cbom_priority"]
}
```

```json
{
  "rule": "hybrid_negotiation_regression",
  "metric": "ratio(hybrid_handshakes / total_handshakes) per endpoint",
  "trigger": "ratio drops > 40% vs. 7-day baseline within 1h",
  "context_join": "recent change_event(endpoint) within 24h",
  "severity": "medium; high if no approved change explains the drop"
}
```

## Example data

```json
{ "ts": "2026-06-27T13:02Z", "client": "203.0.113.22", "server": "edge.example",
  "offered_groups": ["X25519MLKEM768","X25519"], "negotiated": "X25519",
  "server_supports_hybrid": true, "client_key_share_bytes": 32,
  "path": ["waf-edge-01"], "verdict": "downgrade: PQ share stripped at/after WAF" }
```

## Investigation steps

1. Reproduce with a controlled probe from a clean vantage point:
   `openssl s_client -connect SERVER:443 -groups X25519MLKEM768 -tls1_3` — does the server
   negotiate hybrid when asked directly? (Authorized hosts only.)
2. If the server *does* negotiate hybrid directly but live clients don't, suspect an in-path
   element: enumerate middleboxes/LB/WAF/CDN and test each segment.
3. Distinguish **misconfiguration** (a proxy that simply wasn't configured for PQ) from
   **active stripping** (mutation that varies by client/time, or differs between two vantage points).
4. For regressions, correlate with the most recent deploy/config change to the endpoint or its
   path. Most regressions are a rollback or template drift, not an adversary.
5. Assess HNDL impact via PB-02: what data does this session carry, and what is its shelf-life?

## False positives

- A genuinely non-hybrid client connecting (old browser, legacy library) — the *client* didn't
  offer PQ, so a classical negotiation is correct, not a downgrade. The rule requires the client
  to have offered hybrid.
- Planned, approved disabling of PQ for a compatibility window — track approved changes so they
  suppress the regression alert by reference, not blanket.
- Interop fallback where the server legitimately lacks hybrid support (then the finding is a
  *posture* gap for PB-01, not a downgrade attack).

## Tuning

- Maintain a server-capability baseline (which endpoints support which groups) so the rule only
  fires when hybrid *was* achievable. Refresh it from PB-01.
- Tune on the offered-vs-negotiated join, not by muting handshake logging. If you stop logging
  negotiated groups to reduce volume, you go blind to the entire downgrade class.
- Treat middlebox/CDN PQ-termination as a first-class architecture question: PQ that ends at
  the edge while backhaul stays classical is a partial control — document it as accepted or fix it.

## Response actions

- Confirmed active stripping → treat as in-path AiTM: identify and isolate the manipulating
  element, preserve packet evidence from both vantage points, and assume sessions in the window
  are HNDL-exposed (rotate/re-encrypt per PB-02).
- Misconfiguration → reconfigure the proxy/LB/CDN to offer and prefer hybrid groups end-to-end;
  re-test; update CBOM.
- Replace any non-validated PQ provider in a FIPS-obligated path with a validated module.

## Escalation criteria

- Evidence of active, selective PQ-stripping (not mere misconfig) → incident escalation as AiTM.
- Systemic hybrid regression across many internet-facing endpoints after a change → change-
  management + crypto-program escalation (likely a template/rollback defect affecting the fleet).

## Analyst notes (template)

```
DGRD-ID:            DGRD-____
Client offered:     ____ (hybrid? Y/N)
Negotiated:         ____    Server supports hybrid? Y/N
Key-share bytes:    ____ (expected ____)
Path elements:      ____
Classification:     active-stripping | misconfig | benign(client-side)
Change correlated:  ____ (approved? Y/N)
HNDL impact (PB-02): data class ____ / shelf ____ yrs
Disposition:        incident | reconfigure | accepted | benign
```

## Summary

Hybrid PQ only protects you if it is actually negotiated end to end. Continuously compare what
clients offer against what gets negotiated, watch for regressions after changes, and treat
PQ-share stripping as the AiTM/HNDL pivot it is. The most common true finding is mundane —
a proxy or CDN that terminates PQ at the edge and backhauls classical — and fixing that quietly
closes a large HNDL window.
