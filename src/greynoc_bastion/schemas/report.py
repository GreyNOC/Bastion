"""BastionReport — a generated report envelope over a set of findings."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List

from .base import BastionModel, new_correlation_id, utcnow_iso
from .enums import ReportFormat, Severity
from .finding import BastionFinding


@dataclasses.dataclass
class ReportSummary(BastionModel):
    """Executive rollup computed from the findings in a report."""

    total_findings: int = 0
    by_severity: Dict[str, int] = dataclasses.field(default_factory=dict)
    by_category: Dict[str, int] = dataclasses.field(default_factory=dict)
    highest_severity: Severity = Severity.INFO
    headline: str = ""


@dataclasses.dataclass
class BastionReport(BastionModel):
    """A report: metadata, an executive summary, and the findings it covers.

    The same report object is rendered to HTML/Markdown/JSON/CSV/SARIF/PDF and
    can be packaged as an evidence bundle by the Report/Evidence centers.
    """

    report_id: str = dataclasses.field(default_factory=lambda: new_correlation_id("rpt"))
    title: str = "GreyNOC Bastion Report"
    generated_at: str = dataclasses.field(default_factory=utcnow_iso)
    generated_by: str = "greynoc-bastion"
    modules: List[str] = dataclasses.field(default_factory=list)  # which modules contributed

    summary: ReportSummary = dataclasses.field(default_factory=ReportSummary)
    findings: List[BastionFinding] = dataclasses.field(default_factory=list)

    # Formats actually written to disk in this run.
    formats: List[ReportFormat] = dataclasses.field(default_factory=list)
    output_paths: Dict[str, str] = dataclasses.field(default_factory=dict)  # format -> path
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def recompute_summary(self) -> "BastionReport":
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        highest = Severity.INFO
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
            if f.severity.rank > highest.rank:
                highest = f.severity
        crit = by_sev.get("critical", 0)
        high = by_sev.get("high", 0)
        headline = (
            f"{len(self.findings)} findings; "
            f"{crit} critical, {high} high. Highest severity: {highest.value}."
        )
        self.summary = ReportSummary(
            total_findings=len(self.findings),
            by_severity=by_sev,
            by_category=by_cat,
            highest_severity=highest,
            headline=headline,
        )
        return self
