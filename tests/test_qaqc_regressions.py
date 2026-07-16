"""Regression coverage for the veteran QA/QC wiring pass."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from greynoc_bastion.adapters import AdapterExecutionError
from greynoc_bastion.adapters.detector_engine_adapter import DetectorEngineAdapter
from greynoc_bastion.auth import AuthError
from greynoc_bastion.schemas import (
    BastionFinding,
    ReportFormat,
    Severity,
)
from greynoc_bastion.services.threat_forecast import ThreatForecastService


def test_epss_forecast_uses_native_probability_and_disclosed_survival_math():
    adapter = DetectorEngineAdapter()
    score = adapter.score_threat({"description": "x", "cvss": 9.8}, epss=0.5)
    forecast = adapter.forecast_exploit_timing(score, kev=False, epss_30d=0.5)

    assert forecast.exploit_probability == 0.5
    assert forecast.probability_horizon_days == 30
    assert forecast.horizon_days_p50 == 30
    assert forecast.horizon_days_p90 == 100
    assert forecast.status == "estimated"
    assert forecast.method == "epss-30d-constant-hazard-v1"
    assert any("not independently calibrated" in item for item in forecast.assumptions)


def test_forecast_refuses_to_invent_timing_without_epss_and_kev_is_observed():
    adapter = DetectorEngineAdapter()
    score = adapter.score_threat({"description": "internet-facing rce", "cvss": 9.8})

    missing = adapter.forecast_exploit_timing(score, kev=False, epss_30d=None)
    assert missing.status == "insufficient_data"
    assert missing.exploit_probability is None
    assert missing.horizon_days_p50 is None

    observed = adapter.forecast_exploit_timing(score, kev=True, epss_30d=0.2)
    assert observed.status == "observed"
    assert observed.exploit_probability is None
    assert observed.horizon_days_p50 == 0


def test_forecast_joins_explicit_nvd_epss_and_kev_exports(tmp_path):
    cve_path = tmp_path / "nvd.json"
    epss_path = tmp_path / "first-epss.json"
    kev_path = tmp_path / "cisa-kev.json"
    cve_path.write_text(json.dumps({"vulnerabilities": [
        {"cve": {"id": "CVE-2026-10001", "descriptions": [
            {"lang": "en", "value": "remote gateway flaw"},
        ]}},
        {"cve": {"id": "CVE-2026-10002", "descriptions": [
            {"lang": "en", "value": "remote gateway flaw"},
        ]}},
    ]}), encoding="utf-8")
    epss_path.write_text(json.dumps({"data": [
        {"cve": "CVE-2026-10001", "epss": "0.5"},
        {"cve": "CVE-2026-10002", "epss": "0.2"},
    ]}), encoding="utf-8")
    kev_path.write_text(json.dumps({"vulnerabilities": [{
        "cveID": "CVE-2026-10002",
        "vulnerabilityName": "Observed gateway exploitation",
    }]}), encoding="utf-8")

    threats = DetectorEngineAdapter().forecast_from_path(
        cve_path, epss_path=epss_path, kev_path=kev_path,
    )
    by_id = {threat.threat_id: threat for threat in threats}
    estimated = by_id["CVE-2026-10001"].forecast
    observed = by_id["CVE-2026-10002"].forecast
    assert estimated is not None and estimated.exploit_probability == 0.5
    assert estimated.horizon_days_p50 == 30
    assert observed is not None and observed.status == "observed"
    assert observed.exploit_probability is None


def test_module_reruns_converge_instead_of_duplicating(app):
    sample = Path(__file__).parents[1] / "src" / "greynoc_bastion" / "fixtures" / "sample_project"
    observations = [{"host": "0.0.0.0", "port": 3389, "exposure": "lan"}]

    def run() -> None:
        app.threat_forecast.demo(persist=True)
        app.detection.validate_all(persist=True)
        app.identity.scan(sample, persist=True)
        app.assets.scan_local(passive=True, observations=observations, persist=True)
        app.cases.open_from_findings()

    run()
    first = app.db.counts()
    run()
    second = app.db.counts()
    for table in ("threats", "identities", "detections", "validation_results",
                  "assets", "findings", "cases"):
        assert second[table] == first[table], table


def test_custom_rule_is_validated_persisted_and_used_for_replay(app, tmp_path):
    rule = {
        "id": "CUSTOM-AUTH-001",
        "name": "Custom denied authentication",
        "event_type": "auth",
        "severity": "medium",
        "mitre": ["T1110"],
        "match": {"outcome": "denied"},
    }
    (tmp_path / "CUSTOM-AUTH-001.json").write_text(json.dumps(rule), encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    tests_dir.joinpath("CUSTOM-AUTH-001.json").write_text(json.dumps({
        "true_positive": [{"event_type": "auth", "outcome": "denied", "host": "h"}],
        "true_negative": [{"event_type": "auth", "outcome": "success", "host": "h"}],
    }), encoding="utf-8")

    loaded = app.load_custom_rules(tmp_path)
    assert loaded["accepted_count"] == 1
    results = app.detection.validate_all(persist=True)
    result = next(r for r in results if r.detection_id == rule["id"])
    detection = app.db.get_detection(rule["id"])
    assert result.passed
    assert detection is not None and detection.status.value == "validated"
    assert detection.metadata["last_validation"] == result.result_id
    assert any(v.result_id == result.result_id for v in app.db.list_validations())

    telemetry = tmp_path / "events.jsonl"
    telemetry.write_text(json.dumps({
        "event_type": "auth", "outcome": "denied", "host": "h",
    }) + "\n", encoding="utf-8")
    replay = app.telemetry.replay_file(telemetry, persist=False)
    assert any(item["rule_id"] == rule["id"] for item in replay["rules_fired"])


def test_custom_rule_without_test_cannot_promote(app, tmp_path):
    rule = {
        "id": "CUSTOM-NO-TEST",
        "name": "Custom untested rule",
        "event_type": "auth",
        "match": {"outcome": "denied"},
    }
    (tmp_path / "CUSTOM-NO-TEST.json").write_text(json.dumps(rule), encoding="utf-8")
    app.load_custom_rules(tmp_path)
    results = app.detection.validate_all(persist=True)
    result = next(r for r in results if r.detection_id == rule["id"])
    detection = app.db.get_detection(rule["id"])
    assert not result.passed
    assert "missing" in result.notes
    assert detection is not None and detection.status.value == "failed"


def test_reports_include_more_than_legacy_thousand_row_cap(app, tmp_path):
    for i in range(1001):
        app.db.save_finding(BastionFinding(
            correlation_id=f"fnd-cap-{i}", title=f"finding {i}", severity=Severity.LOW,
        ))
    report = app.build_report(
        out_dir=tmp_path, formats=[ReportFormat.JSON], include_bundle=False,
    )
    assert report.summary.total_findings == 1001


def test_top_findings_considers_old_critical_records(app):
    app.db.save_finding(BastionFinding(
        correlation_id="fnd-old-critical", title="old critical", severity=Severity.CRITICAL,
        timestamp="2020-01-01T00:00:00Z",
    ))
    for i in range(15):
        app.db.save_finding(BastionFinding(
            correlation_id=f"fnd-new-low-{i}", title=f"new low {i}", severity=Severity.LOW,
            timestamp=f"2026-01-01T00:00:{i:02d}Z",
        ))
    assert app.db.list_top_findings(10)[0].title == "old critical"


def test_scheduler_claim_prevents_concurrent_double_run(app, monkeypatch):
    app.scheduler.add("once", kind="report")
    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def fake_run(record, *, actor):
        calls.append(record["schedule_id"])
        entered.set()
        release.wait(5)
        return {"schedule_id": record["schedule_id"], "kind": "report", "ok": True}

    monkeypatch.setattr(app.scheduler, "_run_one", fake_run)
    results: list[list[dict]] = []
    first = threading.Thread(target=lambda: results.append(app.scheduler.run_due()))
    first.start()
    assert entered.wait(5)
    second = threading.Thread(target=lambda: results.append(app.scheduler.run_due()))
    second.start()
    second.join(5)
    release.set()
    first.join(5)

    assert calls == [app.scheduler.list_schedules()[0]["schedule_id"]]
    assert sorted(len(item) for item in results) == [0, 1]


def test_first_account_must_be_admin_and_auth_mode_is_sticky(app):
    with pytest.raises(AuthError):
        app.operators.add("operator1", "correct-horse-battery", "operator")
    app.operators.add("admin1", "correct-horse-battery", "admin")
    assert app.operators.multi_operator_mode()


def test_service_uses_adapter_failure_boundary(app):
    class BrokenAdapter(DetectorEngineAdapter):
        def forecast_from_fixtures(self, sectors=None):
            raise RuntimeError("boom")

    service = ThreatForecastService(app.db, adapter=BrokenAdapter())
    with pytest.raises(AdapterExecutionError, match="detector_engine adapter failed"):
        service.demo()
