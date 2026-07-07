# Bastion explanations

Per-engine technical walkthroughs. Each page has a GitHub-rendered Mermaid
flowchart, a short "how to read it", and a "key code" map to the real functions.

- [System data flow](#system-data-flow) — the whole pipeline (this page)
- [Threat Forecast](01-threat-forecast.md)
- [Identity Blast Radius](02-identity-blast-radius.md)
- [Detection Validation](03-detection-validation.md)
- [Assets & Exposure](04-assets-exposure.md)
- [Correlation Spine](05-correlation-spine.md)
- [Safety Layer](06-safety-layer.md)

---

## System data flow

Inputs enter their own column, are processed by a clean-room adapter, enriched
by shared knowledge, masked at the safety gate, and stored as one universal
finding shape. The correlation spine then joins the stored records back together.

```mermaid
flowchart TD
    %% inputs
    subgraph IN["inputs (offline by default)"]
        F["Threat feeds<br/>CVE · KEV · EPSS"]
        R["Repos & configs<br/>.env · .mcp.json · k8s"]
        T["Synthetic telemetry<br/>rule pack + scenarios"]
        S["Local sockets<br/>netstat / ss (passive)"]
        P["Playbook corpus<br/>30 markdown files"]
    end

    subgraph AD["clean-room adapters"]
        A1["detector_engine"]
        A2["nhi"]
        A3["dmz + detections"]
        A4["homeguard + port_manager"]
        A5["playbooks"]
    end

    K{{"shared knowledge<br/>ATT&CK · AI-abuse · PQC · OWASP"}}

    subgraph SV["engines (services)"]
        E1["Threat forecast"]
        E2["Identity blast radius"]
        E3["Detection validation"]
        E4["Assets & exposure"]
        E5["Operator playbooks"]
    end

    G{{"safety gate<br/>mask secrets · live-fetch off · SSRF/ReDoS · loopback"}}
    DB[("SQLite store<br/>universal BastionFinding")]
    COR["correlation spine<br/>join by technique + host → coverage gaps"]

    subgraph OUT["outputs"]
        O1["Report & evidence<br/>HTML MD JSON CSV SARIF PDF"]
        O2["Threat-intel export<br/>STIX 2.1 · ATT&CK Navigator"]
        O3["CLI + dashboard<br/>127.0.0.1 loopback"]
    end

    F --> A1 --> K
    R --> A2 --> K
    T --> A3 --> K
    S --> A4 --> K
    P --> A5 --> K
    K --> E1 & E2 & E3 & E4 & E5
    E1 & E2 & E3 & E4 & E5 --> G --> DB --> COR
    COR --> O1 & O2 & O3

    classDef accent fill:#1b2430,stroke:#4dc9ff,color:#e6edf3;
    class K,G,COR accent;
```

**How to read it.** The five columns are independent until they converge in the
store — that convergence onto one `BastionFinding` shape is what later lets the
correlation spine join across engines. The two diamond nodes and the correlation
box are *cross-cutting layers*, not pipeline stages: knowledge enriches every
adapter, and the safety gate is mandatory — nothing reaches the store or a report
unmasked.

**Key code.** Composition root: [`app.py`](../../src/greynoc_bastion/app.py)
(`BastionApp` wires adapters → services → db). Universal shape:
[`schemas/finding.py`](../../src/greynoc_bastion/schemas/finding.py). Safety:
[`safety/`](../../src/greynoc_bastion/safety/). Knowledge:
[`knowledge/`](../../src/greynoc_bastion/knowledge/).
