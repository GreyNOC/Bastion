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


def test_evidence_bundle_resists_zip_slip(tmp_path):
    # A finding whose correlation_id contains path traversal must not produce a
    # zip entry that escapes the extraction directory (zip-slip).
    from greynoc_bastion.schemas import BastionFinding, Severity
    f = BastionFinding(title="x", severity=Severity.LOW, correlation_id="../../etc/evil")
    rep = BastionReport(title="t", findings=[f]).recompute_summary()
    import zipfile
    bundle = EvidenceCenter().build_bundle(rep, tmp_path)
    names = zipfile.ZipFile(bundle).namelist()
    assert all(".." not in n and not n.startswith("/") and ":" not in n[2:] for n in names), names


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


def test_csv_neutralizes_formula_injection():
    # Cells beginning with = + - @ must be neutralized so spreadsheets treat
    # them as text, not formulas (OWASP CSV Injection).
    f = BastionFinding(
        title="=HYPERLINK(0)", severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        category=FindingCategory.ASSET, source="+cmd", affected="-2+3",
        why_it_matters="@SUM(1)", recommended_action="normal text",
    )
    csv_text = ReportCenter().to_csv(BastionReport(findings=[f]).recompute_summary())
    import csv as _csv
    rows = list(_csv.reader(csv_text.splitlines()))
    for cell in rows[1]:
        assert cell[:1] not in ("=", "+", "-", "@"), f"un-neutralized formula cell: {cell!r}"
    # normal cells are untouched
    assert "normal text" in csv_text


def test_sarif_and_html_scrub_the_affected_field(tmp_path):
    # `affected` is the one field that previously bypassed the scrub backstop
    # in SARIF and HTML.
    f = BastionFinding(
        title="x", severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        category=FindingCategory.IDENTITY,
        affected="postgres://u:AKIAIOSFODNN7EXAMPLE@db/x", source="ghp_" + "a" * 36,
    )
    rep = BastionReport(findings=[f]).recompute_summary()
    rc = ReportCenter()
    assert "AKIAIOSFODNN7EXAMPLE" not in rc.to_sarif(rep)
    html = rc.to_html(rep)
    assert "AKIAIOSFODNN7EXAMPLE" not in html and "ghp_" + "a" * 36 not in html


def test_verify_bundle_handles_malformed_archive(tmp_path):
    # A non-bundle file must be reported as a failure, not raise.
    bad = tmp_path / "not-a-bundle.zip"
    bad.write_text("garbage", encoding="utf-8")
    result = EvidenceCenter().verify_bundle(bad)
    assert result["ok"] is False and result["problems"]


def test_report_json_roundtrips(tmp_path):
    rep = _report_with_leaky_finding()
    written = ReportCenter().write(rep, tmp_path, [ReportFormat.JSON])
    data = json.loads(open(written["json"]).read())
    back = BastionReport.from_dict(data)
    assert back.summary.total_findings == 1
