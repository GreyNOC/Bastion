"""Detection validation fixture-flow tests."""

from __future__ import annotations

from greynoc_bastion.adapters.dmz_adapter import DmzAdapter
from greynoc_bastion.schemas import ValidationStatus


def test_all_bundled_rules_validate():
    results = DmzAdapter().validate_all_rules()
    assert len(results) == 13
    assert all(r.passed for r in results), [
        (r.detection_id, r.verdict.value) for r in results if not r.passed
    ]


def test_disc_rule_regex_bug_is_fixed(fixtures_dir):
    # The JSON-backspace bug in GNOC-DISC-001 must be corrected in the fixture:
    # 'net user' should match, and no backspace char should be present.
    import json
    rule = json.loads((fixtures_dir / "detections" / "rules" / "GNOC-DISC-001.json").read_text())
    pattern = rule["match"]["message"]["value"]
    assert chr(8) not in pattern, "backspace char still present (JSON \\b bug)"
    adapter = DmzAdapter()
    event = {"event_type": "process_event", "host": "h", "user": "u",
             "message": "net user administrator", "timestamp": "2026-01-01T00:00:00Z"}
    assert adapter.event_matches_rule(event, rule)


def test_scenario_replay_matches_expected(fixtures_dir):
    adapter = DmzAdapter()
    scenario = fixtures_dir / "scenarios" / "auth-bruteforce-sim.json"
    result = adapter.validate_scenario(scenario)
    assert result.passed
    assert result.verdict is ValidationStatus.VALIDATED
    assert result.expected_alerts == result.actual_alerts


def test_adversary_chain_fires_all_expected_rules(fixtures_dir):
    result = DmzAdapter().validate_scenario(fixtures_dir / "scenarios" / "adversary-chain-sim.json")
    assert result.passed
    assert result.false_negatives == 0


def test_true_negative_set_stays_silent():
    # A rule must not fire on its true-negative telemetry.
    adapter = DmzAdapter()
    rule = adapter.load_rule("GNOC-AUTH-001")
    tn_events = [
        {"event_type": "auth_success", "host": "h", "user": "u",
         "message": "successful login", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    alerts = adapter.evaluate_rule(rule, tn_events)
    assert alerts == []


def test_service_persists_validation(app):
    results = app.detection.validate_all(persist=True)
    assert results
    stored = app.db.list_validations()
    assert len(stored) >= len(results)
    # Validated detections are persisted as VALIDATED, drafts never auto-promote.
    dets = app.db.list_detections()
    assert dets
    assert all(d.status in (ValidationStatus.VALIDATED, ValidationStatus.NEEDS_TUNING) for d in dets)
