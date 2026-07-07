# Safety Layer

The one place every hard safety rule lives, so nothing is reimplemented ad hoc.
Everything that stores, logs, reports, or fetches routes through here.

```mermaid
flowchart TD
    subgraph MASK["masking — no full secret ever leaves"]
        M1["mask_secret()<br/>keep a few chars, star the rest"]
        M2["fingerprint_secret()<br/>one-way sha256[:16]"]
        M3["scrub_text()<br/>provider patterns + high-entropy backstop"]
        M4["ScrubbingFilter<br/>every log record scrubbed"]
    end

    subgraph NET["netguard — outbound fetch (off by default)"]
        N0{"live fetch enabled?"}
        N0 -->|no| BLK["refused"]
        N0 -->|yes| N1{"scheme https?"}
        N1 -->|no| BLK
        N1 -->|yes| N2{"private/loopback/CGNAT?"}
        N2 -->|yes| BLK
        N2 -->|no| N3{"host on allowlist?"}
        N3 -->|no| BLK
        N3 -->|yes| OKF["allowed<br/>size + timeout capped"]
        OKF --> RD["validate_redirect()<br/>re-checks every redirect"]
    end

    subgraph REDOS["redos — untrusted rule regexes"]
        R1["is_safe_regex()<br/>shape heuristics"]
        R2["_has_dangerous_nesting()<br/>quantifier-in-quantified-group"]
        R1 & R2 --> SC["safe_compile()<br/>refuse if risky"]
    end

    STATUS["build_safety_status()<br/>live posture for doctor + dashboard"]

    classDef danger fill:#2a1518,stroke:#ff4d4f,color:#e6edf3;
    class BLK danger;
```

**How to read it.** Masking reduces any discovered secret to a preview plus a
non-reversible fingerprint; `scrub_text` is the final backstop applied to every
report format and log line (it also catches long high-entropy tokens with a
length-bounded pattern so the scrub itself can't ReDoS). The network guard is a
fail-closed decision chain — live fetch must be explicitly enabled, HTTPS-only,
allowlisted, size/timeout-capped, and it refuses private / loopback / CGNAT /
test-net destinations (SSRF), re-validating every redirect. The ReDoS guard
screens any externally-sourced rule regex — including the general
"unbounded-quantifier-nested-in-a-quantified-group" family — before it is ever
compiled or run. `build_safety_status` renders the live posture for `doctor` and
the Safety Status page.

**Where it's enforced (and tested).** See the guarantees table in
[`../SAFETY_MODEL.md`](../SAFETY_MODEL.md) — each row maps to code here and a test
in [`tests/`](../../tests).

**Key code.**
[`safety/masking.py`](../../src/greynoc_bastion/safety/masking.py),
[`safety/netguard.py`](../../src/greynoc_bastion/safety/netguard.py),
[`safety/status.py`](../../src/greynoc_bastion/safety/status.py),
[`utils/redos.py`](../../src/greynoc_bastion/utils/redos.py),
[`utils/logging.py`](../../src/greynoc_bastion/utils/logging.py).
