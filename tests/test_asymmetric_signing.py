"""Asymmetric & post-quantum-hybrid evidence-bundle signing.

Covers keygen (per scheme), sign/verify round trips, the public-key-only
non-repudiation property, tamper detection (bundle, sidecar metadata, and each
component signature of a hybrid), wrong-key rejection, cross-scheme rejection,
the CLI surface, and graceful degradation when the optional ``cryptography``
backend is absent.
"""

from __future__ import annotations

import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from greynoc_bastion.cli import main
from greynoc_bastion.schemas import BastionFinding, BastionReport, FindingCategory, Severity
from greynoc_bastion.services import signing

# The asymmetric backend is optional; skip the crypto-dependent tests when it is
# not installed (the graceful-degradation tests below run regardless).
requires_crypto = pytest.mark.skipif(
    not signing.crypto_available(), reason="cryptography backend not installed")
requires_pqc = pytest.mark.skipif(
    not signing.mldsa_available(), reason="ML-DSA (FIPS 204) not available in cryptography")

ASYMMETRIC = ["ed25519", "ml-dsa-65", "hybrid"]


@pytest.fixture
def bundle(app, tmp_path) -> Path:
    report = BastionReport(
        title="Asym signing test",
        modules=["threat"],
        findings=[BastionFinding(title="f1", severity=Severity.HIGH,
                                 category=FindingCategory.THREAT)])
    report.recompute_summary()
    return Path(app.evidence_center.build_bundle(report, tmp_path))


def _keys(app, tmp_path, scheme: str) -> tuple[Path, Path]:
    priv = tmp_path / "keys" / f"{scheme}.key"
    pub = tmp_path / "keys" / f"{scheme}.pub"
    app.evidence_center.generate_keypair(priv, pub, scheme=scheme)
    return priv, pub


# --- backend / capability ----------------------------------------------------
def test_backend_status_shape(app):
    st = app.evidence_center.crypto_backend_status()
    assert set(st) >= {"cryptography_installed", "ed25519_available",
                       "mldsa_available", "hmac_available", "asymmetric_schemes"}
    assert st["hmac_available"] is True
    assert isinstance(st["asymmetric_schemes"], list)


def test_resolve_scheme_aliases():
    assert signing.resolve_scheme("hybrid") == signing.SCHEME_HYBRID
    assert signing.resolve_scheme("ed25519") == signing.SCHEME_ED25519
    assert signing.resolve_scheme("ml-dsa-65") == signing.SCHEME_MLDSA65
    assert signing.resolve_scheme(signing.SCHEME_HYBRID) == signing.SCHEME_HYBRID
    with pytest.raises(ValueError):
        signing.resolve_scheme("rsa-2048")


# --- keygen ------------------------------------------------------------------
@requires_crypto
@pytest.mark.parametrize("scheme", ASYMMETRIC)
def test_keygen_writes_private_and_public(app, tmp_path, scheme):
    if scheme in ("ml-dsa-65", "hybrid") and not signing.mldsa_available():
        pytest.skip("ML-DSA not available")
    priv, pub = _keys(app, tmp_path, scheme)
    assert priv.is_file() and pub.is_file()
    # Private key must be owner-only.
    if os.name == "nt":
        assert app.evidence_center.key_permissions_private(priv)
    else:
        assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    priv_env = json.loads(priv.read_text())
    pub_env = json.loads(pub.read_text())
    assert signing.is_private_key_envelope(priv_env)
    assert signing.is_public_key_envelope(pub_env)
    assert priv_env["key_id"] == pub_env["key_id"]
    # The PUBLIC file must not contain private key material.
    assert priv_env["keys"] != pub_env["keys"]
    for algo, material in priv_env["keys"].items():
        assert material not in pub.read_text(), f"private {algo} leaked into public file"


@requires_crypto
def test_keygen_refuses_overwrite_without_force(app, tmp_path):
    priv, pub = _keys(app, tmp_path, "ed25519")
    with pytest.raises(FileExistsError):
        app.evidence_center.generate_keypair(priv, pub, scheme="ed25519")
    # Rotation is explicit.
    app.evidence_center.generate_keypair(priv, pub, scheme="ed25519", force=True)


# --- sign / verify round trips ----------------------------------------------
@requires_crypto
@pytest.mark.parametrize("scheme", ASYMMETRIC)
def test_sign_verify_roundtrip(app, bundle, tmp_path, scheme):
    if scheme in ("ml-dsa-65", "hybrid") and not signing.mldsa_available():
        pytest.skip("ML-DSA not available")
    priv, pub = _keys(app, tmp_path, scheme)
    info = app.evidence_center.sign_bundle(bundle, key_path=priv)
    sidecar = json.loads(Path(info["signature_path"]).read_text())
    assert sidecar["scheme"] == signing.resolve_scheme(scheme)
    assert set(sidecar["signatures"]) == set(signing.SCHEME_ALGORITHMS[sidecar["scheme"]])
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert res["ok"], res


@requires_crypto
def test_verify_with_public_key_only_no_private_key(app, bundle, tmp_path):
    """The non-repudiation property: a verifier needs ONLY the public key.
    Deleting the private key must not affect verification."""
    priv, pub = _keys(app, tmp_path, "ed25519")
    app.evidence_center.sign_bundle(bundle, key_path=priv)
    priv.unlink()  # verifier does not have the private key
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert res["ok"], res


@requires_crypto
def test_verify_accepts_private_envelope_too(app, bundle, tmp_path):
    priv, pub = _keys(app, tmp_path, "ed25519")
    app.evidence_center.sign_bundle(bundle, key_path=priv)
    # Pointing --pubkey at the private envelope also works (public derived).
    res = app.evidence_center.verify_signature(bundle, public_key_path=priv)
    assert res["ok"], res


# --- tamper detection --------------------------------------------------------
@requires_crypto
@pytest.mark.parametrize("scheme", ASYMMETRIC)
def test_tampered_bundle_fails(app, bundle, tmp_path, scheme):
    if scheme in ("ml-dsa-65", "hybrid") and not signing.mldsa_available():
        pytest.skip("ML-DSA not available")
    priv, pub = _keys(app, tmp_path, scheme)
    app.evidence_center.sign_bundle(bundle, key_path=priv)
    with bundle.open("ab") as fh:
        fh.write(b"X")
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert not res["ok"]
    assert any("mismatch" in p for p in res["problems"])


@requires_crypto
def test_tampered_entry_inside_zip_fails(app, bundle, tmp_path):
    priv, pub = _keys(app, tmp_path, "hybrid" if signing.mldsa_available() else "ed25519")
    app.evidence_center.sign_bundle(bundle, key_path=priv)
    rebuilt = tmp_path / "rebuilt.evidence.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(rebuilt, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "report.md":
                data = data + b"\ninjected"
            zout.writestr(item, data)
    rebuilt.replace(bundle)
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert not res["ok"]


@requires_crypto
@pytest.mark.parametrize("field,value", [
    ("signed_at", "1999-01-01T00:00:00Z"),
    ("bundle", "somewhere-else.zip"),
    ("schema_version", "9.9"),
])
def test_tampered_sidecar_metadata_fails(app, bundle, tmp_path, field, value):
    priv, pub = _keys(app, tmp_path, "ed25519")
    info = app.evidence_center.sign_bundle(bundle, key_path=priv)
    sig_path = Path(info["signature_path"])
    sidecar = json.loads(sig_path.read_text())
    sidecar[field] = value
    sig_path.write_text(json.dumps(sidecar), encoding="utf-8")
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert not res["ok"], field
    assert any("signature mismatch" in p for p in res["problems"]), (field, res["problems"])


@requires_pqc
@pytest.mark.parametrize("algo", ["ed25519", "ml-dsa-65"])
def test_hybrid_requires_both_signatures(app, bundle, tmp_path, algo):
    """Corrupting EITHER component signature must break a hybrid verification —
    that is the whole point of the classical+PQC construction."""
    priv, pub = _keys(app, tmp_path, "hybrid")
    info = app.evidence_center.sign_bundle(bundle, key_path=priv)
    sig_path = Path(info["signature_path"])
    sidecar = json.loads(sig_path.read_text())
    good = sidecar["signatures"][algo]
    # Flip the last hex nibble to a different value.
    sidecar["signatures"][algo] = good[:-1] + ("0" if good[-1] != "0" else "1")
    sig_path.write_text(json.dumps(sidecar), encoding="utf-8")
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert not res["ok"]
    assert any(algo in p and "mismatch" in p for p in res["problems"]), res["problems"]


@requires_pqc
def test_hybrid_missing_one_signature_fails(app, bundle, tmp_path):
    priv, pub = _keys(app, tmp_path, "hybrid")
    info = app.evidence_center.sign_bundle(bundle, key_path=priv)
    sig_path = Path(info["signature_path"])
    sidecar = json.loads(sig_path.read_text())
    del sidecar["signatures"]["ml-dsa-65"]
    sig_path.write_text(json.dumps(sidecar), encoding="utf-8")
    res = app.evidence_center.verify_signature(bundle, public_key_path=pub)
    assert not res["ok"]
    assert any("missing ml-dsa-65" in p for p in res["problems"])


# --- wrong / mismatched keys -------------------------------------------------
@requires_crypto
def test_wrong_public_key_fails(app, bundle, tmp_path):
    priv, pub = _keys(app, tmp_path, "ed25519")
    app.evidence_center.sign_bundle(bundle, key_path=priv)
    other_priv = tmp_path / "keys" / "other.key"
    other_pub = tmp_path / "keys" / "other.pub"
    app.evidence_center.generate_keypair(other_priv, other_pub, scheme="ed25519")
    res = app.evidence_center.verify_signature(bundle, public_key_path=other_pub)
    assert not res["ok"]
    assert any("key id mismatch" in p for p in res["problems"])


@requires_pqc
def test_cross_scheme_key_rejected(app, bundle, tmp_path):
    """An ed25519 public key must not verify a hybrid signature (and vice versa)."""
    hpriv, hpub = _keys(app, tmp_path, "hybrid")
    app.evidence_center.sign_bundle(bundle, key_path=hpriv)
    epriv = tmp_path / "keys" / "e.key"
    epub = tmp_path / "keys" / "e.pub"
    app.evidence_center.generate_keypair(epriv, epub, scheme="ed25519")
    res = app.evidence_center.verify_signature(bundle, public_key_path=epub)
    assert not res["ok"]


@requires_crypto
def test_signing_with_public_key_refused(app, bundle, tmp_path):
    priv, pub = _keys(app, tmp_path, "ed25519")
    with pytest.raises(ValueError):
        app.evidence_center.sign_bundle(bundle, key_path=pub)


@requires_crypto
def test_missing_public_key_raises(app, bundle, tmp_path):
    priv, pub = _keys(app, tmp_path, "ed25519")
    app.evidence_center.sign_bundle(bundle, key_path=priv)
    with pytest.raises(FileNotFoundError):
        app.evidence_center.verify_signature(bundle, public_key_path=tmp_path / "absent.pub")


# --- manifest advertisement --------------------------------------------------
@requires_crypto
def test_manifest_advertises_available_schemes(app, bundle):
    with zipfile.ZipFile(bundle) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    # Backward-compatible key kept, plus the new advertisement.
    assert manifest["signing"]["scheme"] == "hmac-sha256-detached"
    available = manifest["signing"]["available_schemes"]
    assert "hmac-sha256-detached" in available
    assert signing.SCHEME_ED25519 in available


# --- CLI ---------------------------------------------------------------------
@requires_pqc
def test_cli_hybrid_keygen_sign_verify(monkeypatch, home, bundle, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    assert main(["evidence", "keygen", "--scheme", "hybrid"]) == 0
    assert main(["evidence", "sign", str(bundle)]) == 0
    assert main(["evidence", "verify", str(bundle),
                 "--pubkey", str(home / "keys" / "evidence.pub")]) == 0
    out = capsys.readouterr().out
    assert "Detached signature: OK" in out
    # Tamper -> CLI exit 1.
    with bundle.open("ab") as fh:
        fh.write(b"X")
    assert main(["evidence", "verify", str(bundle),
                 "--pubkey", str(home / "keys" / "evidence.pub")]) == 1


@requires_crypto
def test_cli_backends_reports_schemes(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    assert main(["evidence", "backends"]) == 0
    out = capsys.readouterr().out
    assert "HMAC-SHA256" in out
    assert "Ed25519" in out


# --- graceful degradation when the backend is absent -------------------------
def test_keygen_without_backend_reports_install_hint(monkeypatch, home, capsys):
    monkeypatch.setenv("BASTION_HOME", str(home))
    monkeypatch.setattr(signing, "crypto_available", lambda: False)
    rc = main(["evidence", "keygen", "--scheme", "ed25519"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "cryptography" in err and "greynoc-bastion[pqc]" in err


def test_hmac_keygen_still_works_without_backend(monkeypatch, home):
    """The zero-dependency HMAC scheme must be unaffected by a missing backend."""
    monkeypatch.setenv("BASTION_HOME", str(home))
    monkeypatch.setattr(signing, "crypto_available", lambda: False)
    assert main(["evidence", "keygen"]) == 0  # default scheme = hmac
    assert (home / "keys" / "evidence.key").is_file()


# --- signing-module unit tests (validation & error paths) --------------------
@requires_crypto
def test_sign_rejects_malformed_envelopes():
    msg = b"input"
    for bad in (
        {"key_type": "wrong"},
        {"key_type": "greynoc-bastion-signing-private-key"},  # no scheme/keys
        {"key_type": "greynoc-bastion-signing-private-key", "scheme": "rsa", "keys": {}},
        {"key_type": "greynoc-bastion-signing-private-key",
         "scheme": signing.SCHEME_ED25519, "keys": {}},  # missing material
        "not-a-dict",
    ):
        with pytest.raises(ValueError):
            signing.sign(msg, bad)  # type: ignore[arg-type]


@requires_crypto
def test_verify_reports_problems_not_raises_on_bad_signatures():
    priv, pub = signing.generate_keypair("ed25519")
    msg = b"input"
    sigs = signing.sign(msg, priv)
    # Non-hex signature encoding.
    assert signing.verify(msg, {"ed25519": "zz-not-hex"}, pub)
    # Missing signature entirely.
    assert signing.verify(msg, {}, pub)
    # signatures not a dict.
    assert signing.verify(msg, "nope", pub)  # type: ignore[arg-type]
    # Wrong-message (valid hex, wrong content) -> mismatch reported, not raised.
    problems = signing.verify(b"other", sigs, pub)
    assert any("mismatch" in p for p in problems)
    # Sanity: the correct message verifies clean.
    assert signing.verify(msg, sigs, pub) == []


@requires_crypto
def test_verify_rejects_malformed_public_envelope():
    _priv, pub = signing.generate_keypair("ed25519")
    good_sig = signing.sign(b"m", _priv)
    for bad in ({"key_type": "wrong"}, {"key_type": signing._PUBLIC_KEY_TYPE},
                "not-a-dict"):
        problems = signing.verify(b"m", good_sig, bad)  # type: ignore[arg-type]
        assert problems  # reported, never raised


@requires_crypto
def test_to_public_envelope_rejects_non_envelope():
    with pytest.raises(ValueError):
        signing.to_public_envelope({"nope": True})


@requires_crypto
def test_to_public_envelope_from_private_matches_public():
    priv, pub = signing.generate_keypair("ed25519")
    derived = signing.to_public_envelope(priv)
    assert derived["key_id"] == pub["key_id"]
    assert derived["keys"] == pub["keys"]
