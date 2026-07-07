"""Evidence Center — package findings + evidence into a portable bundle.

An evidence bundle is a single ``.zip`` containing:
  * ``manifest.json`` — bundle metadata, integrity hashes, correlation ids;
  * ``report.json``   — the full report;
  * ``report.md`` / ``report.html`` — human-readable copies;
  * ``findings/<correlation_id>.json`` — one file per finding with its evidence.

Everything written is scrubbed of secrets first. The manifest records a
SHA-256 of each entry so a bundle can be integrity-checked later.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Dict, List

from ..safety.masking import scrub_text
from ..schemas import BastionReport, ReportFormat, utcnow_iso
from ..utils.logging import get_logger
from .report_center import ReportCenter


class EvidenceCenter:
    def __init__(self) -> None:
        self.log = get_logger("evidence_center")
        self._rc = ReportCenter()

    def build_bundle(self, report: BastionReport, out_dir: Path) -> str:
        """Write an evidence bundle zip and return its path."""
        report.recompute_summary()
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = out_dir / f"{report.report_id}.evidence.zip"

        entries: Dict[str, bytes] = {}

        report_json = self._rc.to_json(report).encode("utf-8")
        entries["report.json"] = report_json
        entries["report.md"] = self._rc.to_markdown(report).encode("utf-8")
        entries["report.html"] = self._rc.to_html(report).encode("utf-8")

        finding_index: List[dict] = []
        for f in report.findings:
            payload = json.dumps(f.to_dict(), indent=2, ensure_ascii=False)
            payload = scrub_text(payload).encode("utf-8")
            name = f"findings/{f.correlation_id}.json"
            entries[name] = payload
            finding_index.append({
                "correlation_id": f.correlation_id,
                "title": scrub_text(f.title),
                "severity": f.severity.value,
                "validation_status": f.validation_status.value,
                "file": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "evidence_count": len(f.evidence),
            })

        manifest = {
            "bundle_type": "greynoc-bastion-evidence",
            "schema_version": "1.0",
            "report_id": report.report_id,
            "title": scrub_text(report.title),
            "generated_at": report.generated_at,
            "bundled_at": utcnow_iso(),
            "modules": report.modules,
            "summary": report.summary.to_dict(),
            "secret_policy": "masked-only; no full secrets are included in this bundle",
            "findings": finding_index,
            "entries": {
                name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                for name, data in entries.items()
            },
        }
        manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", manifest_bytes)
            for name, data in entries.items():
                zf.writestr(name, data)

        report.output_paths[ReportFormat.EVIDENCE_BUNDLE.value] = str(bundle_path)
        if ReportFormat.EVIDENCE_BUNDLE not in report.formats:
            report.formats.append(ReportFormat.EVIDENCE_BUNDLE)
        self.log.info("evidence bundle written: %s (%d findings)", bundle_path, len(report.findings))
        return str(bundle_path)

    def verify_bundle(self, bundle_path: Path) -> Dict[str, object]:
        """Re-open a bundle and verify every entry hash against the manifest."""
        bundle_path = Path(bundle_path)
        with zipfile.ZipFile(bundle_path, "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))
            problems: List[str] = []
            for name, meta in manifest.get("entries", {}).items():
                try:
                    data = zf.read(name)
                except KeyError:
                    problems.append(f"missing entry: {name}")
                    continue
                actual = hashlib.sha256(data).hexdigest()
                if actual != meta.get("sha256"):
                    problems.append(f"hash mismatch: {name}")
        return {
            "bundle": str(bundle_path),
            "report_id": manifest.get("report_id"),
            "ok": not problems,
            "problems": problems,
            "entry_count": len(manifest.get("entries", {})),
        }
