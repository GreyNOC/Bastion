"""Report generation and evidence-bundle tests."""

from __future__ import annotations

import json

from greynoc_bastion.schemas import (
    BastionEvidence,
    BastionFinding,
    BastionReport,
    Confidence,
    EvidenceKind,
    FindingCategory,
    ReportFormat,
    Severity,
)
from greynoc_bastion.services.evidence_center import EvidenceCenter
from greynoc_bastion.services.report_center import ReportCenter

SECRET = "wJalrXUtnFGNOCK7MDbPxRfiCYzKq0011223344ab"


def _report_with_leaky_finding() -> BastionReport:
    # A finding whose text (wrongly) contains a full secret — the renderers must
    # scrub it out in every format.
    f = BastionFinding(
        title="leaky", severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        category=FindingCategory.IDENTITY, source="test", affected="a.env:1",
        why_it_matters=f"found token {SECRET} in file",
        recommended_action="rotate it",
    )
    f.add_evidence(BastionEvidence(kind=EvidenceKind.FILE_MATCH, summary=f"value {SECRET}"))
    return BastionReport(title="Test Report", modules=["identity"], findings=[f])


def test_all_formats_render(tmp_path):
    rep = _report_with_leaky_finding()
    written = ReportCenter().write(rep, tmp_path, [
        ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.HTML,
        ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.PDF,
    ])
    for fmt in ("json", "markdown", "html", "csv", "sarif", "pdf"):
        assert fmt in written


def test_no_secret_in_any_rendered_format(tmp_path):
    rep = _report_with_leaky_finding()
    written = ReportCenter().write(rep, tmp_path, [
        ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.HTML,
        ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.PDF,
    ])
    for fmt, path in written.items():
        data = open(path, "rb").read()
        assert SECRET.encode() not in data, f"secret leaked in {fmt}"


def test_pdf_is_structurally_valid(tmp_path):
    rep = _report_with_leaky_finding()
    pdf = ReportCenter().to_pdf(rep)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    assert b"/Catalog" in pdf


def test_sarif_is_valid_json_210(tmp_path):
    rep = _report_with_leaky_finding()
    doc = json.loads(ReportCenter().to_sarif(rep))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "GreyNOC Bastion"
    assert len(doc["runs"][0]["results"]) == 1


def test_evidence_bundle_builds_and_verifies(tmp_path):
    rep = _report_with_leaky_finding()
    ec = EvidenceCenter()
    bundle_path = ec.build_bundle(rep, tmp_path)
    assert bundle_path.endswith(".evidence.zip")
    # bundle content must not contain the secret
    data = open(bundle_path, "rb").read()
    assert SECRET.encode() not in data
    # integrity check passes
    result = ec.verify_bundle(bundle_path)
    assert result["ok"], result["problems"]
    assert result["entry_count"] >= 3


def test_report_json_roundtrips(tmp_path):
    rep = _report_with_leaky_finding()
    written = ReportCenter().write(rep, tmp_path, [ReportFormat.JSON])
    data = json.loads(open(written["json"]).read())
    back = BastionReport.from_dict(data)
    assert back.summary.total_findings == 1
