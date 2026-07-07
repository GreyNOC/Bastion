# 02 — Harvest-Now-Decrypt-Later (HNDL) Exposure & Bulk-Capture Detection

## Overview

Harvest-now-decrypt-later is the defining pre-quantum threat: an adversary records encrypted
traffic or exfiltrates ciphertext **today**, stores it, and decrypts it **later** once a
cryptographically relevant quantum computer (or a classical break) exists. The data does not
need to be readable now to be valuable — only to outlive the protection on it. This playbook
covers detecting bulk/long-horizon capture behavior and, just as importantly, **prioritizing
which assets matter** by the shelf-life of the data they protect.

HNDL is not detectable as a single event the way a brute-force burst is. The detection posture
is a blend of (a) catching capture/exfil behavior and (b) treating *unmitigated quantum-
vulnerable exposure of long-shelf-life data* as a standing finding from the CBOM (PB-01).

## MITRE mapping

- **T1040** — Network Sniffing (passive capture of handshakes/ciphertext).
- **T1557** — Adversary-in-the-Middle (active interception positioning to harvest).
- **T1074 / T1041 / T1567** — Data Staged / Exfiltration Over C2 / Exfiltration to Web Service
  (bulk ciphertext leaving the estate to be stored for later decryption).
- **T1600** — Weaken Encryption (forcing classical-only so harvested traffic is future-decryptable).

## Detection strategy

Two complementary detectors plus one posture signal:

1. **Bulk-capture / span-port abuse (behavioral).** Detect unauthorized traffic mirroring,
   promiscuous interfaces, rogue tap/SPAN configuration, or a host receiving traffic it has no
   business receiving. Harvesting frequently begins with positioning to *see* the ciphertext.
2. **Large ciphertext egress to storage (behavioral).** Detect unusually large or sustained
   transfers of opaque/encrypted blobs to external storage or unfamiliar destinations,
   especially of data classes with long retention. The adversary stores now to crack later.
3. **Standing exposure (posture, from PB-01 CBOM).** Any long-shelf-life data still protected
   only by quantum-broken key exchange with no hybrid PQ is an HNDL finding by definition,
   independent of whether capture has been observed.

## Indicators

- New or unexpected SPAN/mirror/tap configuration; interface entering promiscuous mode on a
  host that is not a sanctioned sensor.
- A host or service suddenly receiving copies of east-west or north-south traffic flows.
- Sustained, high-volume egress of high-entropy (encrypted/compressed) data to cloud storage,
  paste/transfer services, or first-seen ASNs — particularly outside business hours.
- Internet-facing services negotiating **classical-only** key exchange (no `X25519MLKEM768` or
  equivalent) while carrying long-shelf-life data (cross-reference PB-01, PB-03).
- Capture tooling artifacts on endpoints (packet-capture libraries invoked by non-sanctioned
  processes).

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "hndl_bulk_ciphertext_egress",
  "where": {
    "direction": "outbound",
    "dst": "external AND (cloud_storage OR first_seen_asn OR transfer_service)",
    "payload_entropy": ">= 7.5 bits/byte",
    "bytes_sum_over_window": ">= threshold(per_asset_baseline * 5)",
    "window": "1h"
  },
  "amplify_if": {
    "data_class.shelf_life_years": ">= 5",
    "source_asset.pq_status": "classical_only"
  },
  "severity": "base=medium; high if amplify_if all true",
  "enrich": ["dst_asn", "data_class", "cbom_priority", "auth_context"]
}
```

```json
{
  "rule": "unauthorized_traffic_capture_position",
  "any_of": [
    "iface.promiscuous == true AND host NOT IN sanctioned_sensors",
    "switch.span_config.changed == true AND change.approved == false",
    "host.received_flows NOT consistent with host.role"
  ],
  "severity": "high",
  "note": "positioning to harvest precedes the harvest"
}
```

## Example data

```json
{ "ts": "2026-06-27T02:14Z", "src": "203.0.113.40", "dst": "198.51.100.7",
  "dst_class": "external/first_seen_asn", "bytes": 41203998811,
  "payload_entropy": 7.93, "data_class": "legal_archive",
  "shelf_life_years": 25, "src_pq_status": "classical_only",
  "verdict": "HNDL-high: long-shelf-life ciphertext bulk egress from non-PQ asset" }
```

## Investigation steps

1. Establish whether the egress/capture is sanctioned (backup job, approved sensor, DR replica).
   Most true alerts here are mundane; rule that out first.
2. Identify the data class and real shelf-life with the owner. A 25-year legal archive leaving
   the estate is categorically different from a 30-day log ship.
3. Determine the protection on the data *in transit and at rest*: classical-only? hybrid PQ?
   already PQ? This sets whether future decryption is even plausible.
4. Pivot on the destination (ASN, reputation, prior contact) and the source process/identity.
5. If capture positioning is involved, treat as active AiTM/sniffing and pivot to PB-03.

## False positives

- Sanctioned backups, log shipping, DR replication, and CDN origin pulls — high-volume opaque
  egress is normal for these. Baseline per asset and allowlist sanctioned jobs.
- Approved network sensors and IDS taps (promiscuous mode is expected).
- Encrypted client uploads to known services (the entropy signal alone is weak; require the
  destination + volume + shelf-life amplifiers).

## Tuning

- Baseline egress volume and destinations **per asset**, not globally. The signal is deviation
  from an asset's own normal, amplified by data shelf-life.
- Do not suppress the base entropy/volume detector to silence backup noise; allowlist the
  specific sanctioned source→destination pairs instead, so a new harvester is still caught.
- Weight by CBOM priority: the same egress from a PQ-protected asset is far lower risk than
  from a classical-only, long-shelf-life one.

## Response actions

- Containment for confirmed unauthorized capture/exfil: isolate the capture position, revoke
  the involved identity, block the destination, preserve evidence.
- For the *posture* class (long-shelf-life data on classical-only crypto): this is a migration
  action, not an incident — fast-track hybrid PQ enablement (PB-03) and re-encryption at rest
  with AES-256 for the affected data class.
- Rotate any long-lived secrets that may have been captured; assume captured ciphertext is
  permanently at risk if it was protected by quantum-broken key exchange.

## Escalation criteria

- Confirmed unauthorized bulk capture/exfil of any long-shelf-life sensitive data class →
  incident escalation, regardless of current decryptability (the harvest is the harm).
- Discovery that a regulated, long-retention data class is internet-exposed on classical-only
  crypto → escalate to crypto-program owner and compliance as a priority migration item.

## Analyst notes (template)

```
HNDL-ID:            HNDL-____
Trigger:            bulk-egress | capture-position | posture(CBOM)
Source / identity:  ____ / ____
Destination:        ____ (asn ____, reputation ____)
Data class / shelf: ____ / ____ yrs
Protection:         classical-only | hybrid-PQ | PQ   (in transit / at rest)
Sanctioned?         Y/N (job/approval ref ____)
Future-decrypt risk: high | moderate | low   why: ____
Disposition:        incident | migration-action | benign
```

## Summary

HNDL turns "not readable yet" into "stolen already." Detect the *positioning to capture* and
the *bulk ciphertext egress*, but the higher-leverage move is posture: use the CBOM to find
long-shelf-life data still on quantum-broken crypto and migrate it to hybrid PQ before it is
ever harvested. The clock on harvested data is the data's retention period, not the attacker's.
