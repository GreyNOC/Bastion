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
from . import signing
from .report_center import ReportCenter

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

# Default detached-signature scheme for bundles. HMAC-SHA256 with a locally
# generated shared key: standard-library only, zero runtime dependencies, and
# honest about its trust model — it is TAMPER EVIDENCE for transfer between
# parties who share the key out-of-band (e.g. an air-gapped export), not
# third-party non-repudiation.
#
# Asymmetric schemes (Ed25519 and post-quantum ML-DSA-65, plus a hybrid of the
# two) are available on top of this via the optional ``cryptography`` backend
# (:mod:`greynoc_bastion.services.signing`, installed with
# ``greynoc-bastion[pqc]``). They give real public-key non-repudiation and,
# in hybrid mode, quantum resistance. The HMAC path below is unchanged and
# remains the zero-dependency default.
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
                        "available_schemes": [SIGNING_SCHEME, *signing.available_asymmetric_schemes()],
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
    def _write_owner_only(path: Path, data: bytes) -> None:
        """Atomically write ``data`` to ``path`` with owner-only permissions.

        Mirrors :meth:`generate_key`'s hardening: a fresh temp file is created
        O_EXCL at mode 0600, ACL-hardened, then atomically renamed into place,
        so there is never a world-readable window and a failed hardening never
        leaves a permissive key behind.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        fd = os.open(str(temp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        try:
            EvidenceCenter._secure_key_file(temp_path)
            os.replace(temp_path, path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    @staticmethod
    def crypto_backend_status() -> dict[str, Any]:
        """Signing-backend capability snapshot (safe to display; no secrets)."""
        return signing.backend_status()

    def generate_keypair(self, private_path: Path, public_path: Path, *,
                         scheme: str, force: bool = False) -> dict[str, Any]:
        """Generate an asymmetric (or hybrid PQC) signing keypair.

        Writes an owner-only **private** key envelope and a shareable **public**
        key envelope, each a small JSON file. The public key is all a third
        party needs to verify a bundle. Refuses to overwrite either file without
        ``force`` (rotation is explicit; bundles signed with the old key stop
        verifying).
        """
        if not signing.crypto_available():
            raise signing.SigningBackendUnavailable(
                "asymmetric signing needs the 'cryptography' library — "
                "install it with:  pip install 'greynoc-bastion[pqc]'")
        canonical = signing.resolve_scheme(scheme)
        private_path = Path(private_path)
        public_path = Path(public_path)
        for p, label in ((private_path, "private"), (public_path, "public")):
            if p.exists() and not force:
                raise FileExistsError(
                    f"{label} key file already exists: {p} (pass --force to rotate; "
                    "bundles signed with the old key will no longer verify)")
        private_env, public_env = signing.generate_keypair(canonical)
        priv_bytes = (json.dumps(private_env, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        self._write_owner_only(private_path, priv_bytes)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.write_text(json.dumps(public_env, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        # Log the algorithm list (short, and more precise than the scheme id).
        # The 33-char hybrid scheme constant would otherwise be redacted by the
        # log scrubber's high-entropy-token backstop — the safety layer working
        # as intended, but unhelpful in an audit trail.
        self.log.info("asymmetric keypair generated: algorithms=%s key_id=%s",
                      "+".join(private_env["algorithms"]), private_env["key_id"])
        return {
            "scheme": canonical,
            "algorithms": list(private_env["algorithms"]),
            "key_id": private_env["key_id"],
            "private_key": str(private_path),
            "public_key": str(public_path),
        }

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

    @staticmethod
    def _read_key_envelope(key_path: Path) -> dict[str, Any] | None:
        """Return a signing-key JSON envelope if the file is one, else ``None``.

        ``None`` means "treat this as an HMAC hex key" — the default scheme.
        A missing file is left for the downstream loader to report.
        """
        try:
            text = Path(key_path).read_text(encoding="utf-8").strip()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return None
        if not text.startswith("{"):
            return None
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        if signing.is_private_key_envelope(obj) or signing.is_public_key_envelope(obj):
            return obj
        return None

    def sign_bundle(self, bundle_path: Path, *, key_path: Path) -> dict[str, Any]:
        """Write a detached signature file next to the bundle and return its info.

        The key file's format selects the scheme. A raw hex key (the default,
        from ``bastion evidence keygen``) uses **HMAC-SHA256** shared-key
        signing; an asymmetric key envelope (from ``keygen --scheme
        ed25519|ml-dsa-65|hybrid``) uses public-key signing via the optional
        ``cryptography`` backend.

        In every scheme the signature covers the bundle's SHA-256 **and** the
        attested sidecar metadata (bundle name, ``signed_at``, scheme,
        schema_version), so it protects the manifest, every entry, and the
        archive structure (via the digest) plus the attestation fields
        themselves. The sidecar (``<bundle>.sig.json``) records the scheme, a
        non-reversible key id, the bundle's SHA-256, and the signature(s).
        """
        bundle_path = Path(bundle_path)
        if not bundle_path.is_file():
            raise FileNotFoundError(f"bundle not found: {bundle_path}")
        envelope = self._read_key_envelope(key_path)
        if envelope is not None:
            return self._sign_bundle_asymmetric(bundle_path, envelope, key_path)
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

    def _sign_bundle_asymmetric(self, bundle_path: Path, private_env: dict[str, Any],
                                key_path: Path) -> dict[str, Any]:
        """Sign a bundle with an asymmetric / hybrid-PQC private key envelope."""
        if not signing.is_private_key_envelope(private_env):
            raise ValueError(
                f"{key_path} is a public key; signing needs the private key")
        if not signing.crypto_available():
            raise signing.SigningBackendUnavailable(
                "asymmetric signing needs the 'cryptography' library — "
                "install it with:  pip install 'greynoc-bastion[pqc]'")
        # A private key must be owner-only, exactly like the HMAC key.
        if not self.key_permissions_private(key_path):
            raise PermissionError(
                f"signing key permissions are not owner-only: {key_path}")
        scheme = str(private_env.get("scheme"))
        algorithms = list(signing.SCHEME_ALGORITHMS[scheme])
        digest = self._digest_file(bundle_path)
        signed_at = utcnow_iso()
        schema_version = "2.0"
        signing_input = self._signing_input(
            bundle_sha256=digest, bundle=bundle_path.name, signed_at=signed_at,
            scheme=scheme, schema_version=schema_version)
        signatures = signing.sign(signing_input, private_env)
        sidecar: dict[str, Any] = {
            "signature_type": "greynoc-bastion-evidence-signature",
            "schema_version": schema_version,
            "scheme": scheme,
            "algorithms": algorithms,
            "key_id": private_env.get("key_id"),
            "bundle": bundle_path.name,
            "bundle_sha256": digest,
            "signatures": signatures,
            "signed_at": signed_at,
            "trust_model": signing.trust_model(scheme),
        }
        sig_path = bundle_path.with_name(bundle_path.name + ".sig.json")
        sig_path.write_text(json.dumps(sidecar, indent=2, ensure_ascii=False), encoding="utf-8")
        self.log.info("bundle signed (%s): %s (key id %s)",
                      "+".join(algorithms), sig_path.name, sidecar["key_id"])
        # Keep a stable, single-scheme-agnostic shape for callers that print a
        # summary: expose the first signature under "signature" too.
        first_sig = next(iter(signatures.values()), "")
        return {"signature_path": str(sig_path), "signature": first_sig, **sidecar}

    @staticmethod
    def _load_public_env_or_raise(public_key_path: Path | None,
                                  key_path: Path | None) -> dict[str, Any]:
        """Load a public-key envelope for verification from ``--pubkey`` (or a
        ``--key`` that is itself a key envelope). Missing/malformed key files are
        operator errors and raise; a well-formed but *wrong* key is not — it is
        left for the signature check to reject."""
        path = public_key_path or key_path
        if path is None:
            raise FileNotFoundError(
                "a public key is required to verify an asymmetric signature "
                "(pass --pubkey <evidence.pub>)")
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"public key not found: {path}")
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            raise ValueError(f"unreadable public key file: {path} ({exc})") from None
        if not (signing.is_public_key_envelope(obj) or signing.is_private_key_envelope(obj)):
            raise ValueError(f"not a Bastion signing key envelope: {path}")
        try:
            return signing.to_public_envelope(obj)
        except signing.SigningBackendUnavailable as exc:
            raise ValueError(str(exc)) from None
        except Exception as exc:  # malformed key material
            raise ValueError(f"unusable key envelope: {path} ({exc})") from None

    def _verify_asymmetric(self, bundle_path: Path, sig_path: Path,
                           sidecar: dict[str, Any], *, key_path: Path | None,
                           public_key_path: Path | None) -> dict[str, Any]:
        """Verify an asymmetric / hybrid signature sidecar with a public key."""
        pub_env = self._load_public_env_or_raise(public_key_path, key_path)
        scheme = str(sidecar.get("scheme"))
        problems: list[str] = []
        sidecar_key_id = sidecar.get("key_id")
        if sidecar_key_id and pub_env.get("key_id") and sidecar_key_id != pub_env["key_id"]:
            problems.append("key id mismatch: signature was made with a different key")
        if not problems:
            if pub_env.get("scheme") != scheme:
                problems.append(
                    f"scheme mismatch: signature is {scheme!r} but key is "
                    f"{pub_env.get('scheme')!r}")
        if not problems:
            digest = self._digest_file(bundle_path)
            if digest != str(sidecar.get("bundle_sha256", "")):
                problems.append("bundle hash mismatch: bundle bytes changed since signing")
            signing_input = self._signing_input(
                bundle_sha256=str(sidecar.get("bundle_sha256", "")),
                bundle=str(sidecar.get("bundle", "")),
                signed_at=str(sidecar.get("signed_at", "")),
                scheme=str(sidecar.get("scheme", "")),
                schema_version=str(sidecar.get("schema_version", "")),
            )
            problems.extend(signing.verify(signing_input, sidecar.get("signatures", {}), pub_env))
        return {
            "bundle": str(bundle_path),
            "signature": str(sig_path),
            "scheme": scheme,
            "ok": not problems,
            "problems": problems,
            "signed_at": sidecar.get("signed_at"),
        }

    def verify_signature(self, bundle_path: Path, *, key_path: Path | None = None,
                         public_key_path: Path | None = None,
                         signature_path: Path | None = None) -> dict[str, Any]:
        """Verify a bundle against its detached signature. Never raises for a
        bad signature — reports ``ok: False`` with reasons (missing key files
        still raise, since that is operator error, not evidence tampering).

        The sidecar's ``scheme`` selects the verifier: HMAC shared-key bundles
        are checked with ``key_path``; asymmetric / hybrid-PQC bundles are
        checked with ``public_key_path`` (the public key alone suffices)."""
        bundle_path = Path(bundle_path)
        sig_path = Path(signature_path) if signature_path else \
            bundle_path.with_name(bundle_path.name + ".sig.json")

        # Peek the sidecar first so we route to the right verifier and demand the
        # right kind of key. Malformed bundles/sidecars are reported, not raised.
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

        scheme = sidecar.get("scheme") if isinstance(sidecar, dict) else None
        if not problems and scheme in signing.ASYMMETRIC_SCHEMES:
            return self._verify_asymmetric(bundle_path, sig_path, sidecar,
                                           key_path=key_path, public_key_path=public_key_path)

        # ---- HMAC shared-key path (default scheme) ----
        if key_path is None:
            raise FileNotFoundError(
                "a signing key is required to verify this signature "
                "(pass --key for HMAC bundles, or --pubkey for asymmetric bundles)")
        key = self._load_key(key_path)
        if not problems:
            if scheme != SIGNING_SCHEME:
                problems.append(f"unsupported scheme: {scheme!r}")
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
