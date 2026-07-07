# Detection Validation

Replays synthetic telemetry against detection rules to prove whether a detection
is ready, needs tuning, or should be deprecated — plus a rule linter, an ATT&CK
coverage map, and multi-stage incident correlation. **Synthetic telemetry only;
no live network.**

```mermaid
flowchart TD
    RULES["load_rules()<br/>GNOC-*.json rule pack"] --> LINT["lint_rule() / lint_all()"]
    LINT --> LINTd["structure · MITRE id format<br/>operator validity · ReDoS gate"]

    RULES --> EV["evaluate_rule(rule, events)"]
    TEL["synthetic telemetry"] --> EV

    subgraph MATCH["match engine"]
        M1["event_matches_rule()<br/>event_type + all conditions"]
        M2["_get_field()<br/>top-level then nested fields"]
        M3["_match_condition()<br/>eq · regex · gte · contains · in"]
        M4["threshold + sliding window<br/>grouped by (host, user)"]
    end
    EV --> MATCH --> AL["alerts"]

    AL --> RT["run_rule_test()<br/>TP fires · TN stays silent"]
    RT --> CM["compute_metrics()<br/>precision · recall · verdict"]
    CM --> VR["BastionValidationResult<br/>validated / needs_tuning / failed"]

    RULES --> CV["build_coverage()<br/>ATT&CK tactics + technique gaps"]
    AL --> IC["correlate_incidents()<br/>same host, dwell window → incident"]

    classDef star fill:#1b2430,stroke:#4dc9ff,color:#e6edf3;
    class CV,IC star;
```

**How to read it.** A rule is first linted statically (is it well-formed, are its
MITRE ids valid, are its operators known, is any regex ReDoS-safe). The match
engine resolves each field from the event's top level *or* its nested `fields`
map, applies the matcher (exact equality by default; `contains`/`regex`/numeric
ops explicit), and aggregates matches per `(host, user)` within the rule's
threshold and sliding time window. Validation runs the rule against its
true-positive set (must fire) and true-negative set (must stay silent), then
`compute_metrics` assigns a verdict. Two analysis views sit alongside: a coverage
map (which ATT&CK tactics/techniques the pack covers, and the gaps) and incident
correlation (chaining multi-stage activity on one host into a single incident
with dwell time).

**A fixed bug worth noting.** `GNOC-DISC-001` shipped with `\b` in a JSON string —
which JSON parses as a backspace, silently breaking the `net user` branch. It's
corrected in the bundled fixture and covered by a regression test.

**Key code.**
[`adapters/dmz_adapter.py`](../../src/greynoc_bastion/adapters/dmz_adapter.py)
— `load_rules`, `lint_rule`/`lint_all`, `event_matches_rule`, `_get_field`,
`_match_condition`, `evaluate_rule`, `run_rule_test`, `validate_scenario`,
`build_coverage`, `correlate_incidents`.
[`schemas/detection.py`](../../src/greynoc_bastion/schemas/detection.py)
`BastionValidationResult.compute_metrics`.
[`utils/redos.py`](../../src/greynoc_bastion/utils/redos.py) `is_safe_regex`.
