"""Shared-schema tests: construction, enums, serialization round-trips."""

from __future__ import annotations

from greynoc_bastion.schemas import (
    BastionAsset,
    BastionDetection,
    BastionEvidence,
    BastionFinding,
    BastionIdentity,
    BastionPlaybook,
    BastionReport,
    BastionThreat,
    BastionValidationResult,
    Confidence,
    EvidenceKind,
    FindingCategory,
    IdentityType,
    Severity,
    ValidationStatus,
)


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_enum_coercion_is_tolerant():
    assert Severity.coerce("HIGH") is Severity.HIGH
    assert Severity.coerce("critical") is Severity.CRITICAL
    assert Severity.coerce("nonsense", Severity.INFO) is Severity.INFO
    assert Severity.coerce(None, Severity.LOW) is Severity.LOW


def test_finding_roundtrip_preserves_types_and_nested_evidence():
    f = BastionFinding(
        title="t", severity=Severity.HIGH, confidence=Confidence.HIGH,
        category=FindingCategory.THREAT,
    )
    f.add_evidence(BastionEvidence(kind=EvidenceKind.LOG_LINE, summary="s", location="a.log:1"))
    data = f.to_dict()
    back = BastionFinding.from_dict(data)
    assert back.severity is Severity.HIGH
    assert back.confidence is Confidence.HIGH
    assert back.category is FindingCategory.THREAT
    assert isinstance(back.evidence[0], BastionEvidence)
    assert back.evidence[0].kind is EvidenceKind.LOG_LINE
    assert back.correlation_id == f.correlation_id


def test_all_models_roundtrip():
    models = [
        BastionThreat(title="x"),
        BastionIdentity(name="k", identity_type=IdentityType.API_KEY, masked_preview="ab****yz"),
        BastionDetection(detection_id="D-1", name="d"),
        BastionValidationResult(detection_id="D-1"),
        BastionPlaybook(slug="p", name="P"),
        BastionAsset(host="127.0.0.1", port=8080),
        BastionEvidence(summary="e"),
    ]
    for m in models:
        clone = type(m).from_dict(m.to_dict())
        assert clone.to_dict() == m.to_dict()


def test_finding_required_narrative_fields_present():
    f = BastionFinding()
    for field in (
        "title", "severity", "confidence", "evidence", "source", "affected",
        "why_it_matters", "recommended_action", "validation_status",
        "false_positive_notes", "operator_notes", "timestamp", "correlation_id",
    ):
        assert hasattr(f, field), field


def test_validation_metrics_compute():
    r = BastionValidationResult(
        detection_id="D", true_positives=3, false_positives=0,
        false_negatives=0, expected_alerts=3,
    ).compute_metrics()
    assert r.verdict is ValidationStatus.VALIDATED
    assert r.passed is True
    assert r.precision == 1.0 and r.recall == 1.0

    r2 = BastionValidationResult(
        detection_id="D", true_positives=0, false_negatives=1, expected_alerts=1,
    ).compute_metrics()
    assert r2.verdict is ValidationStatus.FAILED
    assert r2.passed is False


def test_report_summary_recompute():
    findings = [
        BastionFinding(title="a", severity=Severity.CRITICAL),
        BastionFinding(title="b", severity=Severity.HIGH),
        BastionFinding(title="c", severity=Severity.HIGH),
    ]
    rep = BastionReport(findings=findings).recompute_summary()
    assert rep.summary.total_findings == 3
    assert rep.summary.by_severity["high"] == 2
    assert rep.summary.highest_severity is Severity.CRITICAL


def test_generated_detection_defaults_to_draft():
    # Product rule: generated detections must remain drafts until validated.
    assert BastionThreat().detection_status is ValidationStatus.DRAFT
    assert BastionDetection().status is ValidationStatus.DRAFT
