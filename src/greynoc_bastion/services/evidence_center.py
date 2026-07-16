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
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess  # nosec B404
import zipfile
from pathlib import Path
from typing import Any

from ..safety.masking import scrub_text
from ..schemas import BastionReport, ReportFormat, utcnow_iso
from ..utils.logging import get_logger
from .report_center import ReportCenter

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

# Detached-signature scheme for bundles. HMAC-SHA256 with a locally generated
# shared key: standard-library only, and honest about its trust model — it is
# TAMPER EVIDENCE for transfer between parties who share the key out-of-band
# (e.g. an air-gapped export), not third-party non-repudiation. An asymmetric
# scheme (Ed25519 / PQ hybrid) stays on the roadmap; it needs a crypto
# dependency this project deliberately doesn't take yet.
SIGNING_SCHEME = "hmac-sha256-detached"
_KEY_BYTES = 32


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
            "secret_policy": "masked-only; no full secrets are included in this bundle",  # nosec B105
            # Integrity is per-entry SHA-256 in this manifest. On top of that a
            # DETACHED signature over the whole bundle file is available via
            # `bastion evidence sign` (EvidenceCenter.sign_bundle) — the manifest
            # can only advertise the capability, since the signature covers the
            # finished archive and therefore lives next to it, not inside it.
            "signing": {"signed": False, "scheme": SIGNING_SCHEME,
                        "status": "detached-signature-available (bastion evidence sign)"},
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

    # --- detached signing (shared-key HMAC) ----------------------------------
    @staticmethod
    def generate_key(key_path: Path, *, force: bool = False) -> str:
        """Create an owner-only signing key. Refuses to overwrite by default."""
        key_path = Path(key_path)
        if key_path.exists() and not force:
            raise FileExistsError(
                f"key file already exists: {key_path} (pass force=True / --force to rotate; "
                "bundles signed with the old key will no longer verify)")
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_hex = secrets.token_bytes(_KEY_BYTES).hex()
        # Secure a new file before atomically replacing the target. This avoids
        # a permissive window during forced rotation and preserves the old key
        # if platform ACL hardening fails.
        temp_path = key_path.with_name(f".{key_path.name}.{secrets.token_hex(6)}.tmp")
        fd = os.open(str(temp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (key_hex + "\n").encode("ascii"))
        finally:
            os.close(fd)
        try:
            EvidenceCenter._secure_key_file(temp_path)
            os.replace(temp_path, key_path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        return str(key_path)

    @staticmethod
    def _secure_key_file(path: Path) -> None:
        """Apply owner-only permissions using the platform's real ACL model."""
        path = Path(path)
        if os.name != "nt":
            os.chmod(path, 0o600)
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise PermissionError(f"could not restrict signing key permissions: {path}")
            return

        username = os.environ.get("USERNAME", "")
        domain = os.environ.get("USERDOMAIN", "")
        identity = f"{domain}\\{username}" if domain and username else username
        if not identity:
            raise PermissionError("cannot determine the Windows identity for key ACL hardening")
        icacls = shutil.which("icacls.exe") or shutil.which("icacls")
        if not icacls:
            raise PermissionError("cannot locate icacls for signing-key ACL hardening")
        # Absolute system executable, fixed switches, and a path created by Bastion.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [icacls, str(path), "/inheritance:r", "/grant:r", f"{identity}:(R,W)"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        if result.returncode != 0:
            raise PermissionError(
                f"could not restrict Windows ACL on signing key: {result.stderr.strip()}"
            )

    @staticmethod
    def key_permissions_private(path: Path) -> bool:
        """Return whether the key is owner-only under POSIX mode bits/Windows ACLs."""
        path = Path(path)
        if os.name != "nt":
            return stat.S_IMODE(path.stat().st_mode) == 0o600
        icacls = shutil.which("icacls.exe") or shutil.which("icacls")
        if not icacls:
            return False
        result = subprocess.run(  # noqa: S603  # nosec B603
            [icacls, str(path)], capture_output=True, text=True, check=False, timeout=15,
        )
        acl = result.stdout.lower()
        username = os.environ.get("USERNAME", "").lower()
        return (
            result.returncode == 0
            and bool(username)
            and username in acl
            and "everyone:" not in acl
            and "builtin\\users:" not in acl
        )

    @staticmethod
    def _load_key(key_path: Path) -> bytes:
        key_path = Path(key_path)
        try:
            text = key_path.read_text(encoding="ascii").strip()
            key = bytes.fromhex(text)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"signing key not found: {key_path} (create one with `bastion evidence keygen`)"
            ) from None
        except (ValueError, UnicodeDecodeError):
            raise ValueError(f"signing key file is not valid hex: {key_path}") from None
        if len(key) < 16:
            raise ValueError(f"signing key is too short ({len(key)} bytes; want >= 16)")
        if not EvidenceCenter.key_permissions_private(key_path):
            raise PermissionError(
                f"signing key permissions are not owner-only: {key_path}"
            )
        return key

    @staticmethod
    def _key_id(key: bytes) -> str:
        """A short, non-reversible identifier for a key (never the key itself)."""
        return hashlib.sha256(b"bastion-evidence-key:" + key).hexdigest()[:16]

    @staticmethod
    def _digest_file(path: Path) -> str:
        h = hashlib.sha256()
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _signing_input(*, bundle_sha256: str, bundle: str, signed_at: str,
                       scheme: str, schema_version: str) -> bytes:
        """Canonical bytes the HMAC covers: the bundle digest AND the attested
        metadata, so ``signed_at`` / bundle name / scheme cannot be altered on a
        signed sidecar while it still verifies."""
        return json.dumps({
            "bundle_sha256": bundle_sha256,
            "bundle": bundle,
            "signed_at": signed_at,
            "scheme": scheme,
            "schema_version": schema_version,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_bundle(self, bundle_path: Path, *, key_path: Path) -> dict[str, Any]:
        """Write a detached signature file next to the bundle and return its info.

        The signature is HMAC-SHA256 over the bundle's SHA-256 **and** the
        attested sidecar metadata (bundle name, ``signed_at``, scheme,
        schema_version), so it covers the manifest, every entry, and the archive
        structure (via the digest) plus the attestation fields themselves. The
        sidecar (``<bundle>.sig.json``) records the scheme, a non-reversible key
        id, the bundle's SHA-256, and the signature.
        """
        bundle_path = Path(bundle_path)
        if not bundle_path.is_file():
            raise FileNotFoundError(f"bundle not found: {bundle_path}")
        key = self._load_key(key_path)
        digest = self._digest_file(bundle_path)
        signed_at = utcnow_iso()
        schema_version = "1.0"
        signing_input = self._signing_input(
            bundle_sha256=digest, bundle=bundle_path.name, signed_at=signed_at,
            scheme=SIGNING_SCHEME, schema_version=schema_version)
        signature = hmac.new(key, signing_input, hashlib.sha256).hexdigest()
        sidecar = {
            "signature_type": "greynoc-bastion-evidence-signature",
            "schema_version": schema_version,
            "scheme": SIGNING_SCHEME,
            "key_id": self._key_id(key),
            "bundle": bundle_path.name,
            "bundle_sha256": digest,
            "signature": signature,
            "signed_at": signed_at,
            "trust_model": (
                "shared-key HMAC: verifiable by any holder of the same key file; "
                "tamper evidence for transfer, not third-party non-repudiation"),
        }
        sig_path = bundle_path.with_name(bundle_path.name + ".sig.json")
        sig_path.write_text(json.dumps(sidecar, indent=2, ensure_ascii=False), encoding="utf-8")
        self.log.info("bundle signed: %s (key id %s)", sig_path.name, sidecar["key_id"])
        return {"signature_path": str(sig_path), **sidecar}

    def verify_signature(self, bundle_path: Path, *, key_path: Path,
                         signature_path: Path | None = None) -> dict[str, Any]:
        """Verify a bundle against its detached signature. Never raises for a
        bad signature — reports ``ok: False`` with reasons (missing key files
        still raise, since that is operator error, not evidence tampering)."""
        bundle_path = Path(bundle_path)
        sig_path = Path(signature_path) if signature_path else \
            bundle_path.with_name(bundle_path.name + ".sig.json")
        key = self._load_key(key_path)

        problems: list[str] = []
        sidecar: dict[str, Any] = {}
        if not bundle_path.is_file():
            problems.append(f"bundle not found: {bundle_path}")
        if not sig_path.is_file():
            problems.append(f"signature file not found: {sig_path}")
        if not problems:
            try:
                sidecar = json.loads(sig_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
                problems.append(f"unreadable signature file: {exc}")
        if not problems and not isinstance(sidecar, dict):
            problems.append("signature file is not a JSON object")
        if not problems:
            if sidecar.get("scheme") != SIGNING_SCHEME:
                problems.append(f"unsupported scheme: {sidecar.get('scheme')!r}")
            if sidecar.get("key_id") and sidecar["key_id"] != self._key_id(key):
                problems.append("key id mismatch: signature was made with a different key")
        if not problems:
            digest = self._digest_file(bundle_path)
            if digest != str(sidecar.get("bundle_sha256", "")):
                problems.append("bundle hash mismatch: bundle bytes changed since signing")
            # Recompute the MAC over the sidecar's OWN attested fields, then
            # compare (constant-time). Because the digest is one of those fields
            # and is independently checked against the actual bundle above,
            # tampering with either the bundle bytes or any attested field
            # (bundle name, signed_at, scheme) breaks verification.
            expected = hmac.new(
                key,
                self._signing_input(
                    bundle_sha256=str(sidecar.get("bundle_sha256", "")),
                    bundle=str(sidecar.get("bundle", "")),
                    signed_at=str(sidecar.get("signed_at", "")),
                    scheme=str(sidecar.get("scheme", "")),
                    schema_version=str(sidecar.get("schema_version", "")),
                ),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, str(sidecar.get("signature", ""))):
                problems.append("signature mismatch: bundle or signature has been tampered with")
        return {
            "bundle": str(bundle_path),
            "signature": str(sig_path),
            "scheme": SIGNING_SCHEME,
            "ok": not problems,
            "problems": problems,
            "signed_at": sidecar.get("signed_at") if isinstance(sidecar, dict) else None,
        }
