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
import re
import zipfile
from pathlib import Path
from typing import Any

from ..safety.masking import scrub_text
from ..schemas import BastionReport, ReportFormat, utcnow_iso
from ..utils.logging import get_logger
from .report_center import ReportCenter

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _safe_entry_name(value: str) -> str:
    """Reduce an id to a safe archive filename (no separators, no traversal)."""
    cleaned = _UNSAFE_NAME.sub("_", str(value or ""))
    cleaned = cleaned.strip("._")            # no leading dots -> no ".." traversal
    return cleaned[:80]


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

        entries: dict[str, bytes] = {}

        report_json = self._rc.to_json(report).encode("utf-8")
        entries["report.json"] = report_json
        entries["report.md"] = self._rc.to_markdown(report).encode("utf-8")
        entries["report.html"] = self._rc.to_html(report).encode("utf-8")

        finding_index: list[dict] = []
        used_names: set[str] = set()
        for idx, f in enumerate(report.findings):
            payload = scrub_text(json.dumps(f.to_dict(), indent=2, ensure_ascii=False)).encode("utf-8")
            # Sanitize the id before using it as an archive path: a
            # correlation_id imported from untrusted data could contain "../"
            # or separators and produce a zip-slip entry. Fall back to the index.
            safe_id = _safe_entry_name(f.correlation_id) or f"finding-{idx}"
            name = f"findings/{safe_id}.json"
            while name in used_names:  # guarantee uniqueness after sanitizing
                name = f"findings/{safe_id}-{idx}.json"
                idx += 1
            used_names.add(name)
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
            # Integrity today is per-entry SHA-256 in this manifest. Cryptographic
            # SIGNING (detached signature over the manifest) is planned but NOT yet
            # implemented — these fields advertise that honestly. See
            # docs/RELEASE_PROCESS.md and EvidenceCenter.sign_bundle().
            "signing": {"signed": False, "scheme": None, "status": "not-implemented"},
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

    def verify_bundle(self, bundle_path: Path) -> dict[str, Any]:
        """Re-open a bundle and verify every entry hash against the manifest.

        A malformed archive (not a zip, no ``manifest.json``, bad JSON) is
        reported as a verification failure, never raised.
        """
        bundle_path = Path(bundle_path)
        problems: list[str] = []
        manifest: dict[str, Any] = {}
        try:
            with zipfile.ZipFile(bundle_path, "r") as zf:
                try:
                    manifest = json.loads(zf.read("manifest.json"))
                except KeyError:
                    return {"bundle": str(bundle_path), "report_id": None,
                            "ok": False, "problems": ["missing manifest.json"], "entry_count": 0}
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    return {"bundle": str(bundle_path), "report_id": None,
                            "ok": False, "problems": [f"unreadable manifest: {exc}"], "entry_count": 0}
                # Validate the manifest shape before iterating: a valid-JSON but
                # malformed manifest (not an object, or `entries` not an object)
                # must be reported as a failure, not raise AttributeError.
                if not isinstance(manifest, dict):
                    return {"bundle": str(bundle_path), "report_id": None,
                            "ok": False, "problems": ["manifest is not a JSON object"], "entry_count": 0}
                entries = manifest.get("entries", {})
                if not isinstance(entries, dict):
                    return {"bundle": str(bundle_path), "report_id": manifest.get("report_id"),
                            "ok": False, "problems": ["manifest 'entries' is not an object"], "entry_count": 0}
                for name, meta in entries.items():
                    if not isinstance(meta, dict):
                        problems.append(f"malformed entry metadata: {name}")
                        continue
                    try:
                        data = zf.read(name)
                    except KeyError:
                        problems.append(f"missing entry: {name}")
                        continue
                    actual = hashlib.sha256(data).hexdigest()
                    if actual != meta.get("sha256"):
                        problems.append(f"hash mismatch: {name}")
        except (zipfile.BadZipFile, OSError) as exc:
            return {"bundle": str(bundle_path), "report_id": None,
                    "ok": False, "problems": [f"not a readable bundle: {exc}"], "entry_count": 0}
        return {
            "bundle": str(bundle_path),
            "report_id": manifest.get("report_id"),
            "ok": not problems,
            "problems": problems,
            "entry_count": len(entries),
        }

    # --- signing scaffold (NOT yet implemented) -----------------------------
    def sign_bundle(self, bundle_path: Path, *, key_ref: str | None = None) -> None:
        """Placeholder for future cryptographic signing of evidence bundles.

        NOT IMPLEMENTED. Bundles today carry per-entry SHA-256 integrity in the
        manifest, but no cryptographic signature. When implemented, this will
        write a detached signature over the canonicalized manifest (candidate
        scheme: Ed25519, with an optional post-quantum SLH-DSA hybrid), stored
        alongside the bundle. Until then this raises rather than silently
        producing an unsigned-but-"signed" artifact. See docs/RELEASE_PROCESS.md.
        """
        raise NotImplementedError(
            "evidence-bundle signing is not implemented yet; bundles are integrity-checked "
            "with per-entry SHA-256 (verify_bundle), not cryptographically signed. "
            "See docs/RELEASE_PROCESS.md for the plan."
        )
