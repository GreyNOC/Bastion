# 12 — Post-Quantum E2EE for Real-Time Media & Collaboration

## Overview

Real-time voice, video, and group collaboration ride a different crypto path than text
messaging (PB-04). A **WebRTC** call agrees media keys over a **DTLS-SRTP** handshake and
protects media with **SRTP**; when the media traverses an SFU/relay, true end-to-end
protection requires **SFrame** encryption *inside* the transport so the server never sees
plaintext. Group calls and rooms use **MLS (RFC 9420)** TreeKEM for shared-key agreement.
The PQ status here lags messaging: the DTLS/key-exchange step is still **classical or only
just gaining hybrid**, MLS PQ ciphersuites are **emerging**, and — per CONVENTIONS §3 — PQ
*authentication* ("Level 4") is unsolved, so media/session key exchange is authenticated with
**classical** primitives. That makes **key-transparency / participant-verification** the real
mitigation, not a PQ signature. This playbook detects classical-only media key exchange where
PQ/hybrid is expected, E2EE-to-transport downgrade, participant key-substitution MITM, silent
"ghost participant" additions, and HNDL exposure of recorded encrypted media (feed PB-02).

## MITRE mapping

- **T1557** — Adversary-in-the-Middle (participant key-substitution on identity keys; ghost
  device/member injected into a call or room). Note: media PQ key exchange still authenticates
  with **classical** primitives (Level-4 PQ auth unsolved), so the durable defense is
  key-transparency / out-of-band participant verification, **not** a PQ signature.
- **T1040** — Network Sniffing (harvesting encrypted media / call recordings for later
  decryption — the HNDL payoff; hand off to PB-02).
- **T1600** — Weaken Encryption (forcing DTLS/MLS ciphersuite negotiation to classical-only or
  a weaker suite where hybrid/PQ was achievable).
- **T1556** — Modify Authentication Process (subverting the participant-verification / roster
  trust step that gates who holds the media key).

## Detection strategy

The media crypto is improving; **who holds the key** and **whether PQ was actually negotiated**
are the soft targets. Four detectors:

1. **Media key-exchange PQ posture.** For each WebRTC/DTLS-SRTP session or MLS group, compare the
   negotiated key exchange against endpoint capability. Classical-only DTLS where the platform
   supports hybrid, or an MLS group that negotiated a classical ciphersuite where a PQ suite was
   offered, is a downgrade signal (mirror PB-03's offered-vs-negotiated logic).
2. **E2EE → transport-only downgrade.** Detect a call/meeting that *should* be true E2EE (SFrame
   / MLS media keys held only by participants) dropping to **server-mediated / transport-only**
   encryption (keys terminate at the SFU/MCU). This re-exposes plaintext at the server.
3. **Participant key-substitution / ghost participant.** Watch identity-key changes for call
   participants and **roster/membership-change** events: an extra member or device silently added
   to a call or room (MLS Add/Commit without a corresponding user action) is the AiTM tell.
   Detect via key-transparency and membership-change monitoring.
4. **Recorded-media HNDL exposure.** Flag encrypted call recordings / media streams captured on
   untrusted segments or retained long-term — harvest-now-decrypt-later against media (PB-02).

## Indicators

- WebRTC session negotiated classical-only DTLS key exchange where the platform advertises a
  hybrid group (`X25519MLKEM768` / equivalent) and the peer supports it.
- A meeting flagged "end-to-end encrypted" in UI but the media path shows keys terminating at the
  SFU/MCU (transport encryption to the server, not true E2EE) — SFrame absent where expected.
- MLS group join/Commit that downgrades the negotiated ciphersuite to classical where a PQ suite
  was on offer.
- MLS Add/Commit that inserts an unexpected member or device into a call/room with no paired
  user-initiated invite — a silent ghost participant.
- Participant identity/media-signing key changes mid-call or just before a call, with no
  device-add / reinstall to explain it.
- Transparency-log split view for a call participant's identity key (targeted MITM hallmark).
- Absence of expected PQ rekey on a long-lived room where the MLS PQ suite should periodically
  refresh key material.
- Encrypted media/recording streams observed traversing an untrusted segment or a
  recording sink retaining ciphertext well beyond policy shelf-life.

## Sample logic (JSON-shaped pseudocode)

```json
{
  "rule": "media_key_exchange_pq_downgrade",
  "join": "webrtc.dtls_offered_groups WITH webrtc.dtls_negotiated_group",
  "trigger": {
    "peer_supports": "hybrid (X25519MLKEM768) OR mls_pq_ciphersuite",
    "negotiated": "classical_only (X25519 | secp256r1) OR classical_mls_suite"
  },
  "//": "same offered-vs-negotiated logic as PB-03, applied to the media path",
  "severity": "high",
  "enrich": ["call_id", "participant_ids", "sfu_node", "asset.cbom_priority"]
}
```

```json
{
  "rule": "e2ee_call_downgraded_to_transport",
  "trigger": {
    "call.declared_mode": "true_e2ee (SFrame | MLS media keys participant-held)",
    "observed_mode": "server_mediated OR transport_only (keys terminate at SFU/MCU)"
  },
  "//": "plaintext re-exposed at the relay; SFrame missing where expected",
  "severity": "high"
}
```

```json
{
  "rule": "ghost_participant_or_key_substitution",
  "trigger": {
    "event": "mls_add_or_commit OR participant_identity_key_changed",
    "without": ["user_initiated_invite", "device_add", "reinstall"],
    "scope": "single_call OR room_roster"
  },
  "amplify_if": {
    "participant.is_high_value": true,
    "transparency_log.split_view_detected": true,
    "membership_delta.silent": true
  },
  "//": "Level-4 PQ auth unsolved; classical-auth key swap is the durable attack",
  "severity": "base=medium; high if amplify_if any true",
  "enrich": ["call_id", "member_id", "old_key_fp", "new_key_fp", "log_inclusion_proof_ref"]
}
```

## Example data

```json
{ "ts": "2026-06-27T14:08Z", "call_id": "rtc-8842", "sfu_node": "sfu-eu-3",
  "participant": "vip-exec-2", "peer": "198.51.100.44",
  "dtls_offered_groups": ["X25519MLKEM768","X25519"], "dtls_negotiated": "X25519",
  "peer_supports_hybrid": true, "sframe": true,
  "verdict": "high: media key exchange downgraded to classical where hybrid was achievable" }
```

```json
{ "ts": "2026-06-27T14:19Z", "call_id": "room-collab-17", "member_added": "device-unknown-9c",
  "src": "[2001:db8:5:5::9c]", "mls_commit": true, "user_initiated_invite": false,
  "transparency_split_view": true, "declared_mode": "true_e2ee", "observed_mode": "true_e2ee",
  "verdict": "high: silent MLS member insertion (ghost participant) with directory split view" }
```

## Investigation steps

1. Rule out benign churn first: a mid-call key change or new device is usually a reconnect,
   app restart, or a participant genuinely joining from another device. Require the *absence* of
   a legitimate trigger before treating a roster/key change as substitution.
2. For a downgrade, reproduce with a controlled, authorized probe from a clean vantage point —
   does the peer/SFU negotiate hybrid DTLS or the PQ MLS suite when asked directly? If it does
   for a direct probe but not for live sessions, suspect an in-path element (mirror PB-03).
3. Distinguish **true E2EE vs. transport-to-server**: confirm whether SFrame/MLS media keys are
   participant-held or terminate at the SFU/MCU. A meeting labeled E2EE that terminates at the
   server is either misconfiguration or a deliberate mode downgrade.
4. For a ghost participant, pull the MLS Commit history and map each Add/Update to a
   user-initiated action; an unexplained membership delta with no invite is the finding.
5. For identity-key changes, pull the transparency-log inclusion/consistency proof; a key that
   can't be proven consistently included (or shows a split view) is the strong MITM signal.
6. Verify out-of-band for high-value participants — the entire point of participant verification
   is an out-of-band channel; use it actively for VIP calls.
7. Assess recorded-media HNDL impact via PB-02: what does this media carry, where was it
   captured/retained, and what is its shelf-life?

## False positives

- Reconnects, network handoffs (Wi-Fi ↔ cellular), and app restarts legitimately renegotiate
  DTLS-SRTP and can rotate media keys mid-call — dominant cause of "key changed" in real-time media.
- A participant genuinely joining from a second device produces a legitimate roster/membership add.
- A non-PQ peer (old client / legacy SDK) that never offered hybrid negotiating classical is
  correct, not a downgrade — the rule requires the peer to have offered PQ/hybrid.
- Some products intentionally offer a **server-mediated** mode (cloud recording, transcription,
  PSTN bridging, compliance capture) where transport-only is by design and disclosed — not a downgrade.
- Planned MLS ciphersuite changes during a platform rollout.

## Tuning

- Baseline per-endpoint media key-exchange capability (which SFUs/clients support hybrid DTLS
  or the PQ MLS suite) so the downgrade rule only fires when PQ *was* achievable. Refresh from PB-01.
- Baseline per-room roster churn; alert on membership adds that lack a paired user-initiated
  invite, not on adds per se.
- Weight high-value participants (executives, journalists, IR responders, negotiators) far higher
  — targeted ghost-participant insertion goes after specific meetings, not the population.
- Tune at the correlation layer (change + no-trigger + log-inconsistency + silent membership
  delta); never silence roster/key telemetry — that telemetry *is* the ghost-participant detector.
- Treat SFU/MCU media-key termination as a first-class architecture question: a true-E2EE label
  over a server-terminating path is a partial control — document it as accepted or fix it.

## Response actions

- Confirmed downgrade / active stripping on the media path → treat as in-path AiTM: identify and
  isolate the manipulating element, preserve evidence from two vantage points, and assume media in
  the window is HNDL-exposed (feed PB-02 for re-encryption / retention decisions).
- Ghost participant / silent membership insertion → remove the injected member/device, force a
  fresh MLS key rotation for the group, invalidate the suspect key, and re-verify the roster
  out-of-band; for high-value rooms, restart the call on a clean session.
- Suspected participant key substitution → force out-of-band re-verification, invalidate the
  suspect identity key, and for service operators freeze and audit the affected directory entries
  and their inclusion proofs.
- E2EE→transport downgrade → restore/enforce the true-E2EE mode (SFrame / participant-held MLS
  keys); investigate the in-path or config cause; confirm no recording sink captured plaintext.

## Escalation criteria

- Any transparency-log split-view or unprovable key insertion for a call participant → incident
  escalation (directory integrity is the trust root for the whole media session).
- Silent ghost-participant insertion into a high-value call/room → incident + protective
  out-of-band roster verification and call restart.
- Evidence of active, selective PQ-stripping on the media path (not mere misconfig) → incident
  escalation as AiTM, with HNDL assessment handed to PB-02.

## Analyst notes (template)

```
RTM-ID:             RTM-____
Call / room ID:     ____
Participant / VIP?: ____ / Y/N
Event:              media-kex-downgrade | e2ee->transport | ghost-participant | key-substitution | recorded-HNDL
Media path:         WebRTC/DTLS-SRTP | SFrame | MLS(RFC 9420)
Offered / negotiated: ____ / ____  (hybrid/PQ achievable? Y/N)
E2EE mode:          true-e2ee | server-mediated/transport-only
Legit trigger?:     reconnect | device-add | invite | rollout | NONE
Membership delta:   silent-add | user-invited | none
Transparency proof: included-consistent | split-view | unprovable
Old/new key fp:     ____ / ____
Out-of-band verif:  done? result ____
HNDL impact (PB-02): media class ____ / shelf ____ yrs
Classification:     benign-churn | downgrade | mode-downgrade | ghost-participant | substitution-MITM
Disposition:        ____
```

## Summary

Real-time media has its own crypto path — DTLS-SRTP and SFrame for calls, MLS TreeKEM for rooms —
and it trails messaging on PQ: media key exchange is classical or newly-hybrid, MLS PQ suites are
emerging, and PQ authentication is still unsolved. So the attacks live in **negotiation** and
**trust**: classical-only media key exchange where hybrid was achievable, a true-E2EE call quietly
downgraded to server-mediated, participant key substitution, and silent ghost-participant additions
caught only by roster and key-transparency monitoring. Instrument offered-vs-negotiated on the media
path, watch membership deltas for unexplained inserts, verify high-value participants out-of-band,
and route harvested-recording exposure to PB-02 — participant verification remains the decisive control.
