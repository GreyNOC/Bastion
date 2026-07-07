"""DMZ adapter — Detection Validation Range.

Clean-room port of GreyNOC/DMZ's detection-validation core: it loads the GNOC
rule pack, replays synthetic telemetry, matches events against rules with
threshold/window aggregation, and reports expected-vs-actual alerts as
``BastionValidationResult`` records.

Ported fixes flagged during the source audit:
  * GNOC-DISC-001's ``\\b`` (JSON backspace) regex bug is corrected in the
    bundled fixture.
  * Rule regexes run through the ReDoS guard before use.
  * Only synthetic telemetry is replayed; nothing here touches a network.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..schemas import (
    BastionDetection,
    BastionValidationResult,
    Severity,
    ValidationStatus,
)
from ..utils.redos import safe_compile
from .base import BaseAdapter


def _parse_ts(value: str) -> datetime:
    if not value:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    v = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _get_field(event: Dict[str, Any], name: str) -> Any:
    """Resolve a field from top-level then the nested ``fields`` map."""
    if name in event:
        return event[name]
    fields = event.get("fields")
    if isinstance(fields, dict) and name in fields:
        return fields[name]
    return None


def _match_condition(event: Dict[str, Any], field: str, matcher: Any) -> bool:
    value = _get_field(event, field)
    if value is None:
        return False

    if isinstance(matcher, dict) and "op" in matcher:
        op = matcher["op"]
        target = matcher.get("value")
        if op == "regex":
            pattern = safe_compile(str(target))
            if pattern is None:  # refused by ReDoS guard or invalid
                return False
            return bool(pattern.search(str(value)))
        try:
            if op in ("gte", "gt", "lte", "lt"):
                fv, tv = float(value), float(target)
                return {"gte": fv >= tv, "gt": fv > tv, "lte": fv <= tv, "lt": fv < tv}[op]
        except (TypeError, ValueError):
            return False
        if op == "eq":
            return str(value).lower() == str(target).lower()
        if op == "ne":
            return str(value).lower() != str(target).lower()
        if op == "contains":
            return str(target).lower() in str(value).lower()
        if op == "in":
            return str(value).lower() in [str(t).lower() for t in (target or [])]
        return False

    # Scalar matcher: numeric equality, or case-insensitive substring for text.
    if isinstance(matcher, (int, float)) and not isinstance(matcher, bool):
        try:
            return float(value) == float(matcher)
        except (TypeError, ValueError):
            return False
    return str(matcher).lower() in str(value).lower()


class DmzAdapter(BaseAdapter):
    source_repo = "GreyNOC/DMZ"
    name = "dmz"

    def __init__(self, fixtures_dir: Optional[Path] = None) -> None:
        super().__init__()
        self.fixtures_root = Path(fixtures_dir) if fixtures_dir else (
            Path(__file__).resolve().parents[1] / "fixtures"
        )

    # --- loading -------------------------------------------------------------
    def load_rules(self, rules_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        rules_dir = Path(rules_dir) if rules_dir else self.fixtures_root / "detections" / "rules"
        rules: List[Dict[str, Any]] = []
        for f in sorted(rules_dir.glob("*.json")):
            try:
                rules.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                self.log.warning("skipping unreadable rule %s: %s", f.name, exc)
        return rules

    def load_rule(self, rule_id: str, rules_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        for r in self.load_rules(rules_dir):
            if r.get("id") == rule_id:
                return r
        return None

    def rule_to_detection(self, rule: Dict[str, Any]) -> BastionDetection:
        """Represent a rule as a BastionDetection (validated pack -> VALIDATED)."""
        return BastionDetection(
            detection_id=rule.get("id", ""),
            name=rule.get("name", ""),
            description=rule.get("description", ""),
            severity=Severity.coerce(rule.get("severity"), Severity.MEDIUM),
            attack_techniques=list(rule.get("mitre", [])),
            data_sources=[rule.get("data_source", "")] if rule.get("data_source") else [],
            logic={
                "event_type": rule.get("event_type"),
                "match": rule.get("match", {}),
                "threshold": rule.get("threshold", 1),
                "window_minutes": rule.get("window_minutes", 5),
            },
            logic_language="gnoc-match",
            status=ValidationStatus.DRAFT,
            references=[rule.get("runbook")] if rule.get("runbook") else [],
        )

    # --- matching ------------------------------------------------------------
    def event_matches_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        et = rule.get("event_type")
        if et and str(_get_field(event, "event_type")).lower() != str(et).lower():
            return False
        match = rule.get("match", {}) or {}
        for field, matcher in match.items():
            if not _match_condition(event, field, matcher):
                return False
        return True

    def evaluate_rule(self, rule: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return alerts produced by ``rule`` over ``events`` (threshold+window)."""
        threshold = int(rule.get("threshold", 1) or 1)
        window_minutes = int(rule.get("window_minutes", 5) or 5)
        window = window_minutes * 60

        # Group matched events by (host, user).
        groups: Dict[Tuple[Any, Any], List[Tuple[datetime, Dict[str, Any]]]] = {}
        for ev in events:
            if not self.event_matches_rule(ev, rule):
                continue
            key = (ev.get("host"), ev.get("user"))
            groups.setdefault(key, []).append((_parse_ts(ev.get("timestamp", "")), ev))

        alerts: List[Dict[str, Any]] = []
        for (host, user), items in groups.items():
            items.sort(key=lambda x: x[0])
            # Sliding window over sorted timestamps.
            fired = False
            n = len(items)
            for i in range(n):
                j = i
                while j < n and (items[j][0] - items[i][0]).total_seconds() <= window:
                    j += 1
                count = j - i
                if count >= threshold:
                    fired = True
                    alerts.append({
                        "rule_id": rule.get("id"),
                        "host": host,
                        "user": user,
                        "count": count,
                        "first_ts": items[i][1].get("timestamp"),
                        "last_ts": items[j - 1][1].get("timestamp"),
                        "sample": items[i][1],
                    })
                    break
            if fired:
                continue
        return alerts

    # --- validation flows ----------------------------------------------------
    def run_rule_test(self, rule: Dict[str, Any], test: Dict[str, Any]) -> BastionValidationResult:
        """Validate a rule against its TP/TN test corpus."""
        tp_events = test.get("true_positive", []) or []
        tn_events = test.get("true_negative", []) or []

        tp_alerts = self.evaluate_rule(rule, tp_events) if tp_events else []
        fp_alerts = self.evaluate_rule(rule, tn_events) if tn_events else []

        detected_tp = 1 if tp_alerts else 0
        false_neg = 0 if tp_alerts or not tp_events else 1
        false_pos = len(fp_alerts)

        result = BastionValidationResult(
            detection_id=rule.get("id", ""),
            scenario=f"rule-test:{rule.get('id', '')}",
            expected_alerts=1 if tp_events else 0,
            actual_alerts=len(tp_alerts),
            true_positives=detected_tp,
            false_positives=false_pos,
            false_negatives=false_neg,
            matched_events=[a for a in tp_alerts],
            missed_events=[] if detected_tp else [{"note": "true-positive set did not fire"}],
            notes=(
                f"TP set produced {len(tp_alerts)} alert(s); "
                f"TN set produced {len(fp_alerts)} alert(s) (expected 0)."
            ),
        )
        return result.compute_metrics()

    def validate_all_rules(self) -> List[BastionValidationResult]:
        """Validate every bundled rule against its bundled test."""
        results: List[BastionValidationResult] = []
        tests_dir = self.fixtures_root / "detections" / "tests"
        for rule in self.load_rules():
            rid = rule.get("id")
            test_path = tests_dir / f"{rid}.json"
            if not test_path.is_file():
                continue
            try:
                test = json.loads(test_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            results.append(self.run_rule_test(rule, test))
        return results

    def validate_scenario(self, scenario_path: Path) -> BastionValidationResult:
        """Replay a scenario's telemetry against the rule pack and compare.

        A scenario declares ``expected_rules``; validation passes when exactly
        those rules fire (no more, no fewer).
        """
        scenario_path = Path(scenario_path)
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        expected = set(scenario.get("expected_rules", []) or [])

        telemetry = self._resolve_telemetry(scenario, scenario_path)
        rules = self.load_rules()
        fired: set[str] = set()
        all_alerts: List[Dict[str, Any]] = []
        for rule in rules:
            alerts = self.evaluate_rule(rule, telemetry)
            if alerts:
                fired.add(rule.get("id"))
                all_alerts.extend(alerts)

        tp = len(expected & fired)
        fn = len(expected - fired)
        fp = len(fired - expected)

        result = BastionValidationResult(
            detection_id=",".join(sorted(expected)) or "(none)",
            scenario=scenario.get("id", scenario_path.stem),
            expected_alerts=len(expected),
            actual_alerts=len(fired),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            matched_events=all_alerts[:50],
            missed_events=[{"rule_id": r, "note": "expected but did not fire"} for r in (expected - fired)],
            notes=(
                f"Expected rules: {sorted(expected) or '[]'}; "
                f"fired: {sorted(fired) or '[]'}."
            ),
        )
        return result.compute_metrics()

    def _resolve_telemetry(self, scenario: Dict[str, Any], scenario_path: Path) -> List[Dict[str, Any]]:
        """Load the telemetry a scenario points at, tolerant of path layouts."""
        tf = scenario.get("telemetry_file") or scenario.get("telemetry")
        if not tf:
            return scenario.get("events", []) or []
        candidates = [
            Path(tf),
            scenario_path.parent / tf,
            scenario_path.parent.parent / tf,
            self.fixtures_root / tf,
            # Source-repo layout "telemetry/fixtures/x.json" -> bundled "telemetry/x.json"
            self.fixtures_root / "telemetry" / Path(tf).name,
        ]
        for c in candidates:
            if c.is_file():
                return json.loads(c.read_text(encoding="utf-8"))
        raise FileNotFoundError(f"telemetry file not found for scenario: {tf}")
