# Threat Forecast

Turns offline CVE / CISA KEV / FIRST EPSS feeds into ranked threats with an
explainable exploit-**timing** forecast, ATT&CK/AI-abuse/PQC enrichment, and
STIX / ATT&CK Navigator export.

```mermaid
flowchart TD
    subgraph FEEDS["offline fixtures (live fetch off by default)"]
        CVE["cve_sample.json<br/>NVD 2.0"]
        KEV["kev_sample.json<br/>CISA KEV"]
        EPSS["epss_sample.json<br/>FIRST EPSS"]
    end

    CVE --> PC["parse_cve_feed()<br/>desc · cvss · cwe · products"]
    KEV --> PK["parse_kev_feed()<br/>ransomware flag · due date"]
    EPSS --> PE["parse_epss_feed()<br/>clamp to 0..1"]

    PC & PK & PE --> COR["correlate by CVE id"]

    COR --> SC["score_threat()<br/>ThreatScore"]
    SC --> SCd["exploit_likelihood · public_exposure<br/>ransomware · remediation · urgency"]

    SC --> FT["forecast_exploit_timing()"]
    FT --> FTd["ThreatForecast<br/>probability · p50/p90 days<br/>confidence · window"]

    COR --> EN["enrichment (knowledge bases)"]
    EN --> EN1["infer_techniques() → ATT&CK"]
    EN --> EN2["classify_ai_abuse()"]
    EN --> EN3["hndl_exposure() → post-quantum"]

    FT --> BT["build_threats() → BastionThreat<br/>ranked by urgency, then probability"]
    SCd --> BT
    EN1 & EN2 & EN3 --> BT

    BT --> TF["to_findings() → BastionFinding"]
    BT --> X1["to_stix_bundle()<br/>STIX 2.1"]
    BT --> X2["to_attack_navigator_layer()"]

    classDef star fill:#1b2430,stroke:#4dc9ff,color:#e6edf3;
    class FT,FTd star;
```

**How to read it.** Three feeds are parsed independently, then joined on the CVE
id so a single threat carries CVSS (from NVD), known-exploited + ransomware
signals (from KEV), and an exploitation probability (from EPSS). `score_threat`
blends those into an explainable 0–1 urgency; `forecast_exploit_timing` then
converts the same signals into a *time* estimate — KEV means "already exploited,
horizon 0", otherwise a pressure blend compresses the p50/p90 day estimate and
raises the probability. Enrichment runs off the description text: technique
inference, AI-abuse classification, and harvest-now-decrypt-later exposure.

**Why it matters.** The forecast answers "how soon" not just "how bad", and the
inferred ATT&CK techniques are the join key the correlation spine uses to find
threats you can't yet detect.

**Key code.**
[`adapters/detector_engine_adapter.py`](../../src/greynoc_bastion/adapters/detector_engine_adapter.py)
— `parse_cve_feed` / `parse_kev_feed` / `parse_epss_feed`, `score_threat`,
`forecast_exploit_timing`, `build_threats`.
[`knowledge/attack.py`](../../src/greynoc_bastion/knowledge/attack.py) `infer_techniques`,
[`knowledge/ai_abuse.py`](../../src/greynoc_bastion/knowledge/ai_abuse.py) `classify_ai_abuse`,
[`knowledge/postquantum.py`](../../src/greynoc_bastion/knowledge/postquantum.py) `hndl_exposure`.
Exports: [`services/threat_intel_export.py`](../../src/greynoc_bastion/services/threat_intel_export.py).
Schema: [`schemas/threat.py`](../../src/greynoc_bastion/schemas/threat.py) `BastionThreat`, `ThreatForecast`.
