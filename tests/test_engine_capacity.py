"""Full-capacity engine tests: knowledge bases, forecast, correlation, exports."""

from __future__ import annotations

import json

from greynoc_bastion.adapters.detector_engine_adapter import DetectorEngineAdapter
from greynoc_bastion.adapters.dmz_adapter import DmzAdapter
from greynoc_bastion.adapters.nhi_adapter import NhiAdapter
from greynoc_bastion.knowledge import ai_abuse, attack, postquantum
from greynoc_bastion.knowledge.owasp import owasp_nhi_for
from greynoc_bastion.schemas import BastionThreat
from greynoc_bastion.services.correlation import CorrelationService
from greynoc_bastion.services.threat_intel_export import (
    to_attack_navigator_layer,
    to_stix_bundle,
)


# --- knowledge bases ---------------------------------------------------------
def test_attack_inference_and_lookups():
    assert "T1190" in attack.infer_techniques("command injection allows remote code execution")
    assert attack.technique_name("T1486") == "Data Encrypted for Impact"
    assert attack.tactic_for_technique("T1110.003") == "TA0006"
    assert attack.normalize_technique("see T1059.001 here") == "T1059.001"
    assert attack.infer_techniques("") == []
    assert len(attack.ATTACK_TACTICS) == 14


def test_ai_abuse_and_pqc_and_owasp():
    cats = ai_abuse.classify_ai_abuse("prompt injection lets you jailbreak the agent")
    assert any(c["id"] == "prompt_injection" for c in cats)
    assert not ai_abuse.is_ai_related("a plain nginx buffer overflow")
    hndl = postquantum.hndl_exposure("RSA and ECDH protect long-term backups")
    assert hndl and hndl["at_risk"]
    assert postquantum.mosca_margin(10, 5, 12)["at_risk"] is True
    refs = owasp_nhi_for("cloud_workload", privileged=True)
    assert any(r["id"] == "NHI2" for r in refs)


# --- threat forecast ---------------------------------------------------------
def test_forecast_timing_and_enrichment():
    threats = DetectorEngineAdapter().forecast_from_fixtures(sectors=["healthcare"])
    top = threats[0]
    assert top.forecast is not None
    assert top.forecast.window == "already_exploited"  # KEV
    assert top.forecast.horizon_days_p50 == 0
    assert "T1190" in top.attack_techniques
    # roundtrip keeps the new nested fields
    clone = BastionThreat.from_dict(top.to_dict())
    assert clone.forecast.window == top.forecast.window
    assert clone.attack_techniques == top.attack_techniques


def test_forecast_horizon_monotonicity():
    a = DetectorEngineAdapter()
    lo = a.score_threat({"description": "x", "cvss": 2.0}, epss=0.02)
    hi = a.score_threat({"description": "internet-facing rce", "cvss": 9.8}, epss=0.9)
    f_lo = a.forecast_exploit_timing(lo, kev=False, epss_30d=0.02)
    f_hi = a.forecast_exploit_timing(hi, kev=False, epss_30d=0.9)
    assert f_hi.horizon_days_p50 <= f_lo.horizon_days_p50   # higher EPSS -> shorter horizon
    assert f_hi.exploit_probability >= f_lo.exploit_probability
    assert f_hi.horizon_days_p90 >= f_hi.horizon_days_p50


def test_stix_and_navigator_export():
    threats = DetectorEngineAdapter().forecast_from_fixtures()
    stix = json.loads(to_stix_bundle(threats))
    assert stix["type"] == "bundle"
    assert {"vulnerability", "attack-pattern", "relationship"} <= {o["type"] for o in stix["objects"]}
    # deterministic ids
    assert to_stix_bundle(threats) == to_stix_bundle(threats)
    nav = json.loads(to_attack_navigator_layer(threats))
    assert nav["domain"] == "enterprise-attack"


# --- NHI full capacity -------------------------------------------------------
def test_nhi_structured_parsing_and_risk_paths(sample_project):
    a = NhiAdapter()
    ids = a.scan_repo(sample_project)
    types = {i.identity_type.value for i in ids}
    assert "mcp_server" in types
    assert any(i.detector == "k8s-secret" for i in ids)
    # owasp refs attached
    assert any(i.owasp_refs for i in ids)
    # risk paths surface privileged escalation
    paths = a.derive_risk_paths(ids)
    assert paths and paths[0]["severity"] in ("critical", "high")
    # no k8s secret value leaks
    blob = json.dumps([i.to_dict() for i in ids])
    assert "R04wQ2Zha2VfazhzX3NlY3JldF92YWx1ZTAx" not in blob


# --- detection validation full capacity --------------------------------------
def test_detection_lint_coverage_incidents():
    a = DmzAdapter()
    assert a.lint_all()["clean"] is True
    bad = a.lint_rule({"id": "B", "match": {"x": {"op": "nope", "value": "1"}}, "mitre": ["ZZ"]})
    codes = {i["code"] for i in bad}
    assert "bad-operator" in codes and "bad-mitre" in codes
    cov = a.build_coverage()
    assert cov["techniques_covered"] >= 10 and cov["tactics_covered"] >= 10
    incidents = a.correlate_incidents([
        {"host": "h", "rule_id": "R1", "first_ts": "2026-01-01T00:00:00Z", "last_ts": "2026-01-01T00:00:00Z"},
        {"host": "h", "rule_id": "R2", "first_ts": "2026-01-01T00:05:00Z", "last_ts": "2026-01-01T00:05:00Z"},
    ], dwell_minutes=60)
    assert incidents and incidents[0]["multi_stage"] and incidents[0]["alert_count"] == 2


# --- correlation spine -------------------------------------------------------
def test_correlation_spine_finds_coverage_gap(app, sample_project):
    app.threat_forecast.demo(persist=True)
    app.detection.validate_all(persist=True)
    app.assets.scan_local(passive=True, observations=[
        {"host": "0.0.0.0", "port": 3389, "exposure": "lan"}], persist=True)
    result = CorrelationService(app.db).build()
    assert result["cluster_count"] > 0
    assert result["cross_engine_clusters"] >= 1
    # T1059 is forecasted (from the command-injection CVE) but not in the rule pack
    gaps = [c for c in result["clusters"] if c["coverage_gap"]]
    assert any(c["entity_value"] == "T1059" for c in gaps)


# --- assets baseline / drift -------------------------------------------------
def test_asset_baseline_and_drift(app):
    obs = [{"host": "127.0.0.1", "port": 8080, "exposure": "loopback"}]
    first = app.assets.scan_local(passive=True, observations=obs, persist=True)
    n = app.assets.set_baseline(first)
    assert n >= 1
    # a new service not in the baseline is flagged as drift
    obs2 = obs + [{"host": "0.0.0.0", "port": 3389, "exposure": "lan"}]
    second = app.assets.scan_local(passive=True, observations=obs2, persist=True)
    drift = [a for a in second if a.metadata.get("drift")]
    assert any(a.port == 3389 for a in drift)


# --- app + CLI surfaces ------------------------------------------------------
def test_app_intel_export_and_coverage(app):
    app.threat_forecast.demo(persist=True)
    assert json.loads(app.export_threat_intel("stix"))["type"] == "bundle"
    assert app.detection_coverage()["tactics_total"] == 14
    assert app.lint_detections()["clean"] is True
