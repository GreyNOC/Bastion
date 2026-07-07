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
from typing import Any

from ..knowledge.attack import ATTACK_TACTICS, normalize_technique, tactic_for_technique
from ..schemas import (
    BastionDetection,
    BastionValidationResult,
    Severity,
    ValidationStatus,
)
from ..utils.logging import get_logger
from ..utils.redos import is_safe_regex, safe_compile
from .base import BaseAdapter

_log = get_logger("adapter.dmz.match")

# Valid ATT&CK tactic (TAxxxx) or technique (Txxxx[.yyy]) id.
_MITRE_TOKEN_RE = re.compile(r"^(?:TA\d{4}|T\d{4}(?:\.\d{3})?)$")


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


def _incident_from_cluster(host: Any, cluster: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize a dwell-window cluster of alerts on one host into an incident."""
    ts0 = _parse_ts(cluster[0].get("first_ts") or cluster[0].get("last_ts") or "")
    ts1 = _parse_ts(cluster[-1].get("last_ts") or cluster[-1].get("first_ts") or "")
    rule_ids = sorted({str(c["rule_id"]) for c in cluster if c.get("rule_id")})
    return {
        "host": host,
        "rule_ids": rule_ids,
        "alert_count": len(cluster),
        "dwell_minutes": round((ts1 - ts0).total_seconds() / 60, 1),
        "first_ts": cluster[0].get("first_ts"),
        "last_ts": cluster[-1].get("last_ts"),
        "multi_stage": len(rule_ids) > 1,
    }


def _get_field(event: dict[str, Any], name: str) -> Any:
    """Resolve a field from top-level then the nested ``fields`` map."""
    if name in event:
        return event[name]
    fields = event.get("fields")
    if isinstance(fields, dict) and name in fields:
        return fields[name]
    return None


def _match_condition(event: dict[str, Any], field: str, matcher: Any) -> bool:
    value = _get_field(event, field)
    if value is None:
        return False

    if isinstance(matcher, dict) and "op" in matcher:
        op = matcher["op"]
        target = matcher.get("value")
        if op == "regex":
            pattern = safe_compile(str(target))
            if pattern is None:  # refused by ReDoS guard or invalid regex
                # Surface this: a refused pattern means the rule cannot detect
                # anything, which would otherwise be a silent false negative.
                _log.warning(
                    "detection regex refused (invalid or ReDoS-risky); rule field %r "
                    "will not match: %r", field, str(target)[:80],
                )
                return False
            return bool(pattern.search(str(value)))
        try:
            if op in ("gte", "gt", "lte", "lt"):
                fv, tv = float(value), float(target)  # type: ignore[arg-type]  # guarded by except
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

    # Scalar matcher: exact equality (case-insensitive for text). Substring
    # matching would over-match (e.g. "200" inside "2000"); rules that want
    # substring semantics must use the explicit {"op": "contains"} form.
    if isinstance(matcher, (int, float)) and not isinstance(matcher, bool):
        try:
            return float(value) == float(matcher)
        except (TypeError, ValueError):
            return False
    return str(value).lower() == str(matcher).lower()


class DmzAdapter(BaseAdapter):
    source_repo = "GreyNOC/DMZ"
    name = "dmz"

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        super().__init__()
        self.fixtures_root = Path(fixtures_dir) if fixtures_dir else (
            Path(__file__).resolve().parents[1] / "fixtures"
        )

    # --- loading -------------------------------------------------------------
    def load_rules(self, rules_dir: Path | None = None) -> list[dict[str, Any]]:
        rules_dir = Path(rules_dir) if rules_dir else self.fixtures_root / "detections" / "rules"
        rules: list[dict[str, Any]] = []
        for f in sorted(rules_dir.glob("*.json")):
            try:
                rules.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                self.log.warning("skipping unreadable rule %s: %s", f.name, exc)
        return rules

    def load_rule(self, rule_id: str, rules_dir: Path | None = None) -> dict[str, Any] | None:
        for r in self.load_rules(rules_dir):
            if r.get("id") == rule_id:
                return r
        return None

    def rule_to_detection(self, rule: dict[str, Any]) -> BastionDetection:
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
            references=[str(rule["runbook"])] if rule.get("runbook") else [],
        )

    # --- matching ------------------------------------------------------------
    def event_matches_rule(self, event: dict[str, Any], rule: dict[str, Any]) -> bool:
        et = rule.get("event_type")
        if et and str(_get_field(event, "event_type")).lower() != str(et).lower():
            return False
        match = rule.get("match", {}) or {}
        for field, matcher in match.items():
            if not _match_condition(event, field, matcher):
                return False
        return True

    def evaluate_rule(self, rule: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return alerts produced by ``rule`` over ``events`` (threshold+window)."""
        threshold = int(rule.get("threshold", 1) or 1)
        window_minutes = int(rule.get("window_minutes", 5) or 5)
        window = window_minutes * 60

        # Group matched events by (host, user).
        groups: dict[tuple[Any, Any], list[tuple[datetime, dict[str, Any]]]] = {}
        for ev in events:
            if not self.event_matches_rule(ev, rule):
                continue
            # Resolve host/user with the same top-level-then-nested resolver used
            # for matching, so events that carry these under "fields" group with
            # their top-level siblings instead of forming a separate group.
            key = (_get_field(ev, "host"), _get_field(ev, "user"))
            groups.setdefault(key, []).append((_parse_ts(ev.get("timestamp", "")), ev))

        alerts: list[dict[str, Any]] = []
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
    def run_rule_test(self, rule: dict[str, Any], test: dict[str, Any]) -> BastionValidationResult:
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
            matched_events=list(tp_alerts),
            missed_events=[] if detected_tp else [{"note": "true-positive set did not fire"}],
            notes=(
                f"TP set produced {len(tp_alerts)} alert(s); "
                f"TN set produced {len(fp_alerts)} alert(s) (expected 0)."
            ),
        )
        return result.compute_metrics()

    def validate_all_rules(self) -> list[BastionValidationResult]:
        """Validate every bundled rule against its bundled test."""
        results: list[BastionValidationResult] = []
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
        all_alerts: list[dict[str, Any]] = []
        for rule in rules:
            alerts = self.evaluate_rule(rule, telemetry)
            if alerts:
                fired.add(str(rule.get("id")))
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

    def _resolve_telemetry(self, scenario: dict[str, Any], scenario_path: Path) -> list[dict[str, Any]]:
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

    # --- rule linting -------------------------------------------------------
    def lint_rule(self, rule: dict[str, Any]) -> list[dict[str, str]]:
        """Static-check one rule for structural and safety issues.

        Returns a list of ``{severity, code, message}`` issues (empty = clean).
        """
        issues: list[dict[str, str]] = []

        def add(sev: str, code: str, msg: str) -> None:
            issues.append({"severity": sev, "code": code, "message": msg})

        for field in ("id", "name", "event_type"):
            if not rule.get(field):
                add("error", "missing-field", f"required field '{field}' is missing or empty")
        if not rule.get("match"):
            add("error", "no-match", "rule has no match conditions (matches nothing or everything)")

        # MITRE ids must be valid TA/T tokens.
        for tok in rule.get("mitre", []) or []:
            if not _MITRE_TOKEN_RE.match(str(tok)):
                add("warning", "bad-mitre", f"'{tok}' is not a valid ATT&CK tactic/technique id")

        # Threshold / window sanity.
        thr = rule.get("threshold", 1)
        if not isinstance(thr, int) or thr < 1:
            add("warning", "bad-threshold", f"threshold {thr!r} should be an integer >= 1")
        win = rule.get("window_minutes", 5)
        if not isinstance(win, (int, float)) or win <= 0:
            add("warning", "bad-window", f"window_minutes {win!r} should be > 0")

        # Match operators + regex safety.
        match = rule.get("match", {}) or {}
        valid_ops = {"regex", "eq", "ne", "gt", "gte", "lt", "lte", "contains", "in"}
        for field, matcher in match.items():
            if isinstance(matcher, dict) and "op" in matcher:
                op = matcher["op"]
                if op not in valid_ops:
                    add("error", "bad-operator", f"field '{field}' uses unknown operator '{op}'")
                if op == "regex":
                    ok, reason = is_safe_regex(str(matcher.get("value", "")))
                    if not ok:
                        add("error", "unsafe-regex",
                            f"field '{field}' regex refused: {reason}")
        return issues

    def lint_all(self) -> dict[str, Any]:
        """Lint every bundled rule; returns per-rule issues + a rollup."""
        results: dict[str, list[dict[str, str]]] = {}
        errors = warnings = 0
        for rule in self.load_rules():
            issues = self.lint_rule(rule)
            if issues:
                results[rule.get("id", "?")] = issues
                errors += sum(1 for i in issues if i["severity"] == "error")
                warnings += sum(1 for i in issues if i["severity"] == "warning")
        return {"clean": not results, "errors": errors, "warnings": warnings, "by_rule": results}

    # --- ATT&CK coverage ----------------------------------------------------
    def build_coverage(self) -> dict[str, Any]:
        """Map the rule pack's ATT&CK coverage and surface tactic-level gaps."""
        covered_techniques: dict[str, list[str]] = {}   # technique -> rule ids
        covered_tactics: set = set()
        for rule in self.load_rules():
            rid = rule.get("id", "?")
            for tok in rule.get("mitre", []) or []:
                tid = normalize_technique(tok)
                if tid:
                    covered_techniques.setdefault(tid, []).append(rid)
                    tac = tactic_for_technique(tid)
                    if tac:
                        covered_tactics.add(tac)
                elif str(tok).startswith("TA"):
                    covered_tactics.add(str(tok))

        tactic_rows = []
        for ta_id, ta_name in ATTACK_TACTICS.items():
            techs = [t for t in covered_techniques if tactic_for_technique(t) == ta_id]
            tactic_rows.append({
                "tactic_id": ta_id, "tactic": ta_name,
                "covered": ta_id in covered_tactics or bool(techs),
                "technique_count": len(techs),
                "techniques": sorted(techs),
            })
        gaps = [r["tactic"] for r in tactic_rows if not r["covered"]]
        return {
            "techniques_covered": len(covered_techniques),
            "tactics_covered": sum(1 for r in tactic_rows if r["covered"]),
            "tactics_total": len(ATTACK_TACTICS),
            "gaps": gaps,
            "by_tactic": tactic_rows,
            "technique_to_rules": {t: sorted(set(r)) for t, r in covered_techniques.items()},
        }

    # --- incident correlation -----------------------------------------------
    def correlate_incidents(self, alerts: list[dict[str, Any]],
                            dwell_minutes: int = 60) -> list[dict[str, Any]]:
        """Group alerts on the same host within a dwell window into incidents.

        Chains multi-stage activity (e.g. discovery -> lateral -> exfil on one
        host) into a single incident with a dwell time, so a defender sees the
        story instead of scattered alerts.
        """
        by_host: dict[Any, list[dict[str, Any]]] = {}
        for a in alerts:
            by_host.setdefault(a.get("host"), []).append(a)

        incidents: list[dict[str, Any]] = []
        window = dwell_minutes * 60
        for host, host_alerts in by_host.items():
            host_alerts.sort(key=lambda a: _parse_ts(a.get("first_ts") or a.get("last_ts") or ""))
            cluster: list[dict[str, Any]] = []
            for a in host_alerts:
                if not cluster:
                    cluster = [a]
                    continue
                prev = _parse_ts(cluster[-1].get("last_ts") or cluster[-1].get("first_ts") or "")
                cur = _parse_ts(a.get("first_ts") or a.get("last_ts") or "")
                if (cur - prev).total_seconds() <= window:
                    cluster.append(a)
                else:
                    incidents.append(_incident_from_cluster(host, cluster))
                    cluster = [a]
            if cluster:
                incidents.append(_incident_from_cluster(host, cluster))
        # Multi-stage incidents first, then by alert count.
        incidents.sort(key=lambda i: (i["multi_stage"], i["alert_count"]), reverse=True)
        return incidents
