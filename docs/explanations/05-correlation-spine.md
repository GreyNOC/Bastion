# Correlation Spine

The cross-engine layer that makes Bastion one console instead of seven silos. It
re-reads the stored records and joins them by shared entities, then surfaces the
highest-value operator insight: **forecasted techniques with no validated
detection coverage.**

```mermaid
flowchart TD
    subgraph STORE["stored records (SQLite)"]
        TH["threats<br/>+ ATT&CK techniques"]
        DE["detections"]
        VA["validations"]
        PB["playbooks"]
        AS["assets"]
    end

    VA --> VID["validated detection ids"]

    TH --> TI["technique index"]
    DE --> TI
    PB --> TI
    VID --> TI

    TI --> CL{"per technique:<br/>spans ≥ 2 engines?<br/>OR forecasted + no detection?"}
    CL -->|yes| CLU["CorrelationCluster<br/>threats ↔ detections ↔ playbooks"]
    CL -->|no| SKIP["skip"]

    AS --> HC["host clusters<br/>risky/exposed assets by host"]

    CLU --> GAP{"forecasted technique<br/>with no validated detection?"}
    GAP -->|yes| CG["COVERAGE GAP<br/>build/validate this detection"]
    GAP -->|no| COV["covered"]

    CLU & HC & CG --> EX["executive summary<br/>+ ranked clusters"]

    classDef gap fill:#2a1518,stroke:#ff4d4f,color:#e6edf3;
    class CG gap;
```

**How to read it.** Every engine's typed record already carries join material:
threats and detections and playbooks all carry ATT&CK technique ids; assets carry
a host. The spine builds a technique index across threats, detections, and
playbooks, and a host index across assets. A cluster is emitted when a technique
links two or more engines *or* when it's the special coverage-gap case: a
technique that a threat forecast points at but that **no validated detection**
covers. That gap — plus the playbook that already exists for it — is the single
most actionable output of the whole product.

**Example (from the bundled fixtures).** `CVE-2026-12345` (command injection) maps
to `T1059`. No rule in the pack covers `T1059`, so the spine reports it as a
coverage gap and names the applicable playbook — telling the operator exactly what
detection to build next.

**Key code.**
[`services/correlation.py`](../../src/greynoc_bastion/services/correlation.py)
— `CorrelationService.build`, `CorrelationCluster`, `_technique_narrative`,
`_summary`. Join vocabulary:
[`knowledge/attack.py`](../../src/greynoc_bastion/knowledge/attack.py).
