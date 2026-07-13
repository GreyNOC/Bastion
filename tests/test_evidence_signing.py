"""Detached evidence-bundle signing: keygen, sign, verify, tamper detection."""

from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from greynoc_bastion.cli import main
from greynoc_bastion.schemas import BastionFinding, BastionReport, FindingCategory, Severity


@pytest.fixture
def bundle(app, tmp_path) -> Path:
    report = BastionReport(
        title="Signing test",
        modules=["threat"],
        findings=[BastionFinding(title="f1", severity=Severity.LOW,
                                 category=FindingCategory.THREAT)])
    report.recompute_summary()
    return Path(app.evidence_center.build_bundle(report, tmp_path))


@pytest.fixture
def key(app, tmp_path) -> Path:
    key_path = tmp_path / "keys" / "evidence.key"
    app.evidence_center.generate_key(key_path)
    return key_path


def test_keygen_creates_0600_and_refuses_overwrite(app, tmp_path):
    key_path = tmp_path / "k.key"
    app.evidence_center.generate_key(key_path)
    mode = stat.S_IMODE(key_path.stat().st_mode)
    assert mode == 0o600
    assert len(bytes.fromhex(key_path.read_text().strip())) == 32
    with pytest.raises(FileExistsError):
        app.evidence_center.generate_key(key_path)
    app.evidence_center.generate_key(key_path, force=True)   # rotation is explicit


def test_sign_and_verify_roundtrip(app, bundle, key):
    info = app.evidence_center.sign_bundle(bundle, key_path=key)
    sig_path = Path(info["signature_path"])
    assert sig_path.is_file()
    sidecar = json.loads(sig_path.read_text(encoding="utf-8"))
    assert sidecar["scheme"] == "hmac-sha256-detached"
    # The signature file must not contain the key itself.
    assert key.read_text().strip() not in sig_path.read_text()

    result = app.evidence_center.verify_signature(bundle, key_path=key)
    assert result["ok"], result


def test_tampered_bundle_fails_signature(app, bundle, key):
    app.evidence_center.sign_bundle(bundle, key_path=key)
    # Append a byte: per-entry hashes still verify, the signature must not.
    with bundle.open("ab") as fh:
        fh.write(b"X")
    result = app.evidence_center.verify_signature(bundle, key_path=key)
    assert not result["ok"]
    assert any("mismatch" in p for p in result["problems"])


def test_tampered_entry_inside_zip_fails(app, bundle, key, tmp_path):
    app.evidence_center.sign_bundle(bundle, key_path=key)
    # Rebuild the zip with one modified entry (a classic re-pack attack).
    rebuilt = tmp_path / "rebuilt.evidence.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(rebuilt, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "report.md":
                data = data + b"\ninjected line"
            zout.writestr(item, data)
    rebuilt.replace(bundle)
    result = app.evidence_center.verify_signature(bundle, key_path=key)
    assert not result["ok"]


def test_wrong_key_fails(app, bundle, key, tmp_path):
    app.evidence_center.sign_bundle(bundle, key_path=key)
    other = tmp_path / "other.key"
    app.evidence_center.generate_key(other)
    result = app.evidence_center.verify_signature(bundle, key_path=other)
    assert not result["ok"]
    assert any("key id mismatch" in p for p in result["problems"])


def test_missing_signature_reports_not_raises(app, bundle, key):
    result = app.evidence_center.verify_signature(bundle, key_path=key)
    assert not result["ok"]
    assert any("signature file not found" in p for p in result["problems"])


def test_bad_key_file_raises_operator_error(app, bundle, tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text("not hex!", encoding="utf-8")
    with pytest.raises(ValueError):
        app.evidence_center.sign_bundle(bundle, key_path=bad)
    with pytest.raises(FileNotFoundError):
        app.evidence_center.sign_bundle(bundle, key_path=tmp_path / "absent.key")


def test_cli_keygen_sign_verify(monkeypatch, home, bundle, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    assert main(["evidence", "keygen"]) == 0
    assert main(["evidence", "sign", str(bundle)]) == 0
    assert main(["evidence", "verify", str(bundle), "--key",
                 str(home / "keys" / "evidence.key")]) == 0
    out = capsys.readouterr().out
    assert "Detached signature: OK" in out
    # Tamper -> CLI exit 1.
    with bundle.open("ab") as fh:
        fh.write(b"X")
    assert main(["evidence", "verify", str(bundle), "--key",
                 str(home / "keys" / "evidence.key")]) == 1


def test_manifest_advertises_detached_signing(app, bundle):
    with zipfile.ZipFile(bundle) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["signing"]["scheme"] == "hmac-sha256-detached"
    assert manifest["signing"]["signed"] is False   # honest: sidecar, not embedded
