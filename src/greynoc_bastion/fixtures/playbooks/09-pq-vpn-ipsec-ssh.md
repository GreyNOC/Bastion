# 09 — Post-Quantum VPN, IPsec & SSH Migration

## Overview

Remote-access and site-to-site tunnels are the estate's longest-lived encrypted channels and
the highest-value **harvest-now-decrypt-later** targets: a captured IKE/IPsec or SSH session
recorded today is decryptable when a cryptographically relevant quantum computer arrives, and
the traffic it carried (management planes, replication, admin sessions) often has a multi-decade
shelf-life. This playbook covers inventorying tunnels and the key exchanges they actually
negotiate, and detecting the downgrade / PQ-share stripping / classical-only fallback that
silently strips the PQ hedge from tunnels that should be hybrid.

Scope: IKEv2/IPsec (RFC 9370 multiple key exchanges, RFC 8784 post-quantum preshared keys),
OpenSSH hybrid KEX (`sntrup761x25519-sha512`, `mlkem768x25519-sha256`), and WireGuard's
preshared-key / Rosenpass-style PQ overlay. TLS-based VPNs (SSL-VPN, some SASE tunnels) inherit
the hybrid-group story from PB-03 — this playbook does not re-derive it.

## MITRE mapping

- **T1600** — Weaken Encryption: forcing a tunnel to a classical-only key exchange, or stripping
  the PPK/PQ additional-KE so the SA rests on ECDH alone. **T1600.001** (Reduce Key Space) is the
  precise sub-technique when the fallback lands on a weaker DH group (e.g., MODP-1024) rather than
  merely dropping PQ.
- **T1557** — Adversary-in-the-Middle: in-path manipulation of IKE_SA_INIT proposals or the SSH
  KEXINIT to remove PQ methods before the peers converge on a suite.
- **T1040** — Network Sniffing: the HNDL payoff. Long-lived tunnel captures are the collection
  target; a successful downgrade is what makes tomorrow's decryption worthwhile (feed PB-02).
- **T1021.004** — Remote Services: SSH. Relevant when the concern is an SSH session's KEX/host-key
  posture; not every finding here is adversary SSH use, so tag only interactive/lateral SSH cases.
- **T1133** — External Remote Services: internet-facing VPN concentrators and bastions are the
  in-scope assets; the technique frames the exposure, not the crypto defect itself.
- Much of this work is PQ-migration-defect detection with **no clean ATT&CK adversary technique**
  (a proxy that wasn't configured for PPK is misconfiguration, not an intrusion). Per CONVENTIONS
  §4, we say so rather than force a tag.

## Detection strategy

Compare **negotiated** tunnel crypto against a per-endpoint policy baseline (from PB-01's CBOM),
across three tunnel families:

1. **Inventory plane.** Enumerate every tunnel endpoint and the KEX/algorithms it actually
   negotiates — not what config claims. IKE: proposal transforms and additional-KE payloads.
   SSH: offered vs. negotiated `kex_algorithms` and host-key types. WireGuard: presence/absence
   of a PSK and any Rosenpass sidecar.
2. **Downgrade / stripping.** A tunnel that previously negotiated hybrid (or PPK) and now
   negotiates classical-only, or a peer that offered PQ methods but converged on a classical
   suite against a peer known to support PQ — the tunnel analogue of PB-03's KEM downgrade.
3. **Regression after change.** A drop in the hybrid/PPK-negotiation ratio for an endpoint
   correlated with a recent deploy, firmware update, or template rollback.
4. **Posture gap.** Endpoints that *should* be hybrid per policy/CBOM but never offer PQ:
   IKE daemons too old for RFC 9370, SSH servers pre-9.x, WireGuard peers with no PSK overlay.

Enumeration stays read-only and authorized: `ssh -Q kex` / `ssh -Q key` for local support,
`ssh -vv` KEXINIT observation, reading strongSwan `swanctl --list-sas` / `ipsec statusall`
proposals, and `wg show` for PSK presence — no state changes to peers.

## Indicators

- IKE_SA_INIT that offered an additional-KE transform (RFC 9370, e.g. ML-KEM-768) but the
  established CHILD_SA shows KE from a classical DH group only.
- IKE peers that support RFC 8784 PPK per policy, but SAs establish with `ppk_id` absent —
  the quantum-safe preshared hedge silently not in force.
- IKE fallback to a legacy MODP group (MODP-1024 / DH group 2) — key-space reduction, T1600.001.
- SSH KEXINIT where a client offered `sntrup761x25519-sha512` / `mlkem768x25519-sha256` yet the
  session negotiated `curve25519-sha256` / `ecdh-sha2-nistp256` against a server known to support
  hybrid — a config regression at scale or in-path KEXINIT mutation.
- SSH host keys still `ssh-rsa` / `ecdsa-*` on long-lived bastions (host-key auth remains
  classical; not HNDL-breaking for confidentiality, but tracked for the migration).
- WireGuard peers with no `preshared-key` and no Rosenpass sidecar — pure X25519, no PQ hedge.
- Sudden drop in the proportion of hybrid/PPK tunnels for an endpoint after a firmware/config push.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "ike_pq_ke_or_ppk_downgrade",
  "join": "ike.sa_init.offered_transforms WITH ike.child_sa.established",
  "trigger": {
    "offered": "contains additional_KE (RFC 9370 ML-KEM-*) OR ppk_supported == true",
    "established": {
      "additional_ke": "absent OR classical_only",
      "ppk_id": "absent"
    },
    "peer_capability": "known_supports_pq_or_ppk == true"
  },
  "severity": "high",
  "enrich": ["local_gw", "peer_ip", "child_sa_id", "path_middleboxes", "asset.cbom_priority"]
}
```

```json
{
  "rule": "ssh_hybrid_kex_downgrade",
  "join": "ssh.kexinit.client_offered_kex WITH ssh.negotiated_kex",
  "trigger": {
    "client_offered": "contains sntrup761x25519-sha512 OR mlkem768x25519-sha256",
    "negotiated": "classical_only (curve25519-sha256 | ecdh-sha2-nistp256 | ecdh-sha2-nistp384)",
    "server_capability": "known_supports_hybrid == true"
  },
  "severity": "high",
  "//": "if client did NOT offer PQ, classical is correct — not a downgrade"
}
```

```json
{
  "rule": "tunnel_pq_negotiation_regression",
  "metric": "ratio(pq_or_ppk_tunnels / total_tunnels) per endpoint",
  "trigger": "ratio drops > 40% vs. 7-day baseline within 1h",
  "context_join": "recent change_event(endpoint) within 24h",
  "severity": "medium; high if no approved change explains the drop"
}
```

## Example data

```json
{ "ts": "2026-06-30T09:14Z", "type": "ike", "local_gw": "vpn-hub-01",
  "peer": "198.51.100.40", "offered_transforms": ["ML-KEM-768(addl-KE)","ECP-256"],
  "established_ke": "ECP-256", "additional_ke": "absent", "ppk_id": "absent",
  "peer_supports_pq": true, "verdict": "downgrade: RFC 9370 additional-KE stripped; PPK not applied" }

{ "ts": "2026-06-30T09:20Z", "type": "ssh", "server": "bastion-eu",
  "client": "203.0.113.55", "offered_kex": ["mlkem768x25519-sha256","curve25519-sha256"],
  "negotiated_kex": "curve25519-sha256", "server_supports_hybrid": true,
  "host_key_type": "ssh-ed25519", "verdict": "downgrade: PQ KEX method not selected; investigate path" }

{ "ts": "2026-06-30T09:33Z", "type": "wireguard", "peer": "[2001:db8:2::9]",
  "psk_present": false, "rosenpass_sidecar": false,
  "verdict": "posture gap: pure X25519, no PQ hedge on long-lived site tunnel" }
```

## Investigation steps

1. Reproduce from a clean, authorized vantage point. SSH: `ssh -vv -o KexAlgorithms=mlkem768x25519-sha256 SERVER`
   — does it negotiate PQ when asked directly? IKE: read the peer's advertised proposals from the
   local daemon (`swanctl --list-conns` / `ipsec statusall`), not by re-initiating against production.
2. If the endpoint negotiates PQ/PPK directly but live sessions don't, suspect an in-path element
   (VPN-terminating LB, SSH jump-proxy/bastion, SASE broker) and test each segment.
3. Distinguish **misconfiguration** (daemon/firmware lacks or wasn't enabled for RFC 9370 / PPK /
   OpenSSH 9.x) from **active stripping** (mutation varying by peer/time, or differing between two
   vantage points). Most tunnel findings are the former.
4. For regressions, correlate with the most recent firmware update, template change, or rollback on
   the endpoint or its path — a downgrade after a firmware bump is usually a default reverting.
5. Assess HNDL impact via PB-02: tunnels are high-value by construction. Weight by what the tunnel
   carries (mgmt plane, DB replication) and its shelf-life.
6. For SSH, separate the **confidentiality** question (KEX — HNDL-relevant) from the
   **authentication** question (host-key type — a migration item, not a decryption exposure).

## False positives

- A genuinely classical-only peer (legacy IKE daemon, OpenSSH < 9.0, embedded appliance) — it
  never offered PQ, so a classical negotiation is correct. The rules require the initiator to have
  offered PQ/PPK before flagging a downgrade.
- Planned compatibility windows where PQ/PPK is intentionally disabled for interop — track the
  approved change so it suppresses the regression alert by reference, not blanket.
- SSH host-key type being classical (`ssh-ed25519`/`ecdsa`) is a **posture** item for PB-01, not a
  KEX downgrade — do not conflate host-key auth with session confidentiality.
- A single legacy-client connection negotiating classical vs. a systemic default — require repeated
  observation before declaring an endpoint "downgraded in use."

## Tuning

- Maintain a peer-capability baseline (which endpoints/daemons support RFC 9370, PPK, or OpenSSH
  9.x hybrid KEX) refreshed from PB-01 so a rule only fires when PQ *was* achievable.
- Tune on the offered-vs-negotiated join, not by muting IKE/SSH negotiation logging. Dropping
  KEXINIT or IKE-proposal logging to cut volume blinds you to the entire downgrade class.
- Treat PQ-termination boundaries as a first-class architecture question, mirroring PB-03: a
  bastion or VPN-LB that terminates PQ at the edge and backhauls classical over an untrusted
  segment is a partial control — document as accepted or fix it.
- WireGuard has no native PQ KEM; do not alert on "no PQ KEM negotiated." Alert only on the
  **absence of the PSK/Rosenpass overlay** where policy requires the hedge.

## Response actions

- Confirmed active stripping (varies by peer/time, or differs across vantage points) → treat as
  in-path AiTM: identify and isolate the manipulating element, preserve IKE/SSH negotiation
  evidence from both vantage points, and assume sessions in the window are HNDL-exposed
  (rotate credentials, re-key, re-establish tunnels per PB-02).
- Misconfiguration → enable RFC 9370 additional-KE and/or RFC 8784 PPK on IKE peers; upgrade SSH
  to 9.x+ and set `KexAlgorithms` to prefer `mlkem768x25519-sha256` / `sntrup761x25519-sha512`;
  add the WireGuard PSK/Rosenpass overlay. Re-test and update the CBOM.
- Dual-stack the rollout: enable hybrid/PPK **alongside** classical, verify negotiation, then
  tighten. Keep a tested rollback (revert the transform/KexAlgorithms/PSK change) staged — sequence
  and gate all of this through PB-13 migration ops so a fleet-wide change is reversible.
- Replace any non-validated PQ provider in a FIPS-obligated tunnel path with a validated module.

## Escalation criteria

- Evidence of active, selective PQ/PPK stripping on a tunnel (not mere misconfig) → incident
  escalation as AiTM against a remote-access control (**T1557** + **T1133**).
- Systemic hybrid/PPK regression across many internet-facing VPN concentrators or bastions after a
  firmware/template push → change-management + crypto-program escalation (likely a fleet default
  reverting), coordinated via PB-13.
- Any internet-facing tunnel carrying >5-year-shelf-life data on classical-only KEX with no hybrid
  or PPK, and no approved exception → escalate to the crypto-program owner as a tracked migration item.

## Analyst notes (template)

```
TUN-ID:             TUN-____
Tunnel type:        [ ] IKEv2/IPsec  [ ] OpenSSH  [ ] WireGuard  [ ] TLS-VPN (→ PB-03)
Endpoint / owner:   ____ / ____
Offered:            ____ (PQ/PPK offered? Y/N)
Negotiated KEX/KE:  ____   PPK applied? Y/N   Peer supports PQ/PPK? Y/N
SSH host-key type:  ____ (posture only)     WireGuard PSK/Rosenpass? Y/N
Classification:     active-stripping | misconfig | posture-gap | benign(peer-side)
Change correlated:  ____ (approved? Y/N)
HNDL impact (PB-02): traffic class ____ / shelf ____ yrs
Rollback staged (PB-13)? Y/N
Disposition:        incident | reconfigure | accepted | benign
```

## Summary

Tunnels are the estate's longest-lived secrets, so a PQ hedge that isn't actually negotiated is
the worst kind of blind spot. Inventory what IKE, SSH, and WireGuard endpoints truly negotiate,
compare offered-vs-negotiated to catch additional-KE/PPK stripping and classical SSH fallback, and
treat any downgrade as the HNDL pivot it is. As with PB-03, the most common true finding is
mundane — a bastion or VPN-LB terminating PQ at the edge, or a firmware bump reverting a default —
and fixing it, dual-stacked and reversibly via PB-13, quietly closes a very long HNDL window.
