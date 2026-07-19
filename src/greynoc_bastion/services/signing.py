"""Asymmetric & post-quantum-hybrid detached signing for evidence bundles.

This module is the crypto backend behind ``bastion evidence`` asymmetric
signing. It is **optional**: it requires the vetted ``cryptography`` library
(install ``greynoc-bastion[pqc]``). When ``cryptography`` is absent, importing
this module still succeeds — every entry point degrades to a clear, honest
"backend unavailable" report, and the zero-dependency HMAC shared-key scheme in
:mod:`greynoc_bastion.services.evidence_center` keeps working unchanged.

Schemes
-------
* ``ed25519-detached``  — classical EdDSA (RFC 8032). Real third-party
  non-repudiation: a bundle is verifiable with the **public** key alone.
* ``ml-dsa-65-detached`` — ML-DSA-65 (FIPS 204), a NIST-standardized
  post-quantum signature. Quantum-resistant non-repudiation.
* ``hybrid-ed25519-ml-dsa-65-detached`` — **both** of the above. A verifier
  accepts only if **every** component signature is valid. This is the
  defense-in-depth construction recommended for the PQC transition: the bundle
  stays trustworthy unless an attacker breaks Ed25519 *and* ML-DSA-65.

Design rules honored here:

* **Vetted primitives only.** All signing/verification is delegated to
  ``cryptography`` (OpenSSL-backed). Nothing is hand-rolled.
* **Standards-based serialization.** Private keys are stored as PKCS#8 DER and
  public keys as SubjectPublicKeyInfo DER (base64 in a small JSON envelope), so
  they interoperate with standard tooling.
* **Public verification.** The public-key envelope carries no private material;
  it is the only artifact a third party needs to verify a bundle.
* **Honest trust model.** Distinguished in the sidecar and docs from the HMAC
  scheme's shared-key tamper-evidence.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from ..schemas import utcnow_iso

# --- scheme identifiers ------------------------------------------------------
SCHEME_ED25519 = "ed25519-detached"
SCHEME_MLDSA65 = "ml-dsa-65-detached"
SCHEME_HYBRID = "hybrid-ed25519-ml-dsa-65-detached"

# Component algorithm ids used inside key envelopes and signature sidecars.
ALG_ED25519 = "ed25519"
ALG_MLDSA65 = "ml-dsa-65"

# Which component algorithms each scheme requires. Verification demands that
# EVERY listed algorithm verify successfully (so hybrid needs both).
SCHEME_ALGORITHMS: dict[str, tuple[str, ...]] = {
    SCHEME_ED25519: (ALG_ED25519,),
    SCHEME_MLDSA65: (ALG_MLDSA65,),
    SCHEME_HYBRID: (ALG_ED25519, ALG_MLDSA65),
}

ASYMMETRIC_SCHEMES = tuple(SCHEME_ALGORITHMS.keys())

# CLI-friendly short aliases -> canonical scheme id.
SCHEME_ALIASES: dict[str, str] = {
    "ed25519": SCHEME_ED25519,
    "ml-dsa-65": SCHEME_MLDSA65,
    "mldsa65": SCHEME_MLDSA65,
    "hybrid": SCHEME_HYBRID,
}

_PRIVATE_KEY_TYPE = "greynoc-bastion-signing-private-key"
_PUBLIC_KEY_TYPE = "greynoc-bastion-signing-public-key"
_ENVELOPE_SCHEMA_VERSION = "1.0"


class SigningBackendUnavailable(RuntimeError):
    """Raised when an asymmetric operation is attempted without ``cryptography``."""


# --- capability detection ----------------------------------------------------
def _import_crypto() -> Any:
    """Import the ``cryptography`` primitives lazily. Returns a small namespace
    or raises :class:`SigningBackendUnavailable` with install guidance."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception as exc:  # pragma: no cover - exercised via monkeypatch
        raise SigningBackendUnavailable(
            "asymmetric signing needs the 'cryptography' library — "
            "install it with:  pip install 'greynoc-bastion[pqc]'"
        ) from exc
    mldsa_mod: Any = None  # older cryptography: Ed25519 works, ML-DSA does not
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa as mldsa_mod
    except Exception:
        mldsa_mod = None
    return _CryptoNS(serialization=serialization, ed25519=ed25519,
                     mldsa=mldsa_mod, InvalidSignature=InvalidSignature)


class _CryptoNS:
    """A tiny typed namespace over the lazily imported ``cryptography`` pieces.

    ``mldsa`` is ``None`` when the installed ``cryptography`` predates ML-DSA.
    """

    __slots__ = ("serialization", "ed25519", "mldsa", "InvalidSignature")

    def __init__(self, *, serialization: Any, ed25519: Any, mldsa: Any,
                 InvalidSignature: Any) -> None:
        self.serialization = serialization
        self.ed25519 = ed25519
        self.mldsa = mldsa
        self.InvalidSignature = InvalidSignature


def crypto_available() -> bool:
    """Whether the ``cryptography`` library is importable (Ed25519 at least)."""
    try:
        _import_crypto()
        return True
    except SigningBackendUnavailable:
        return False


def mldsa_available() -> bool:
    """Whether ML-DSA (FIPS 204) is available in the installed ``cryptography``."""
    try:
        return _import_crypto().mldsa is not None
    except SigningBackendUnavailable:
        return False


def available_asymmetric_schemes() -> list[str]:
    """Asymmetric schemes usable with the installed backend, in a stable order."""
    if not crypto_available():
        return []
    schemes = [SCHEME_ED25519]
    if mldsa_available():
        schemes += [SCHEME_MLDSA65, SCHEME_HYBRID]
    return schemes


def backend_status() -> dict[str, Any]:
    """A safe-to-display snapshot of the signing backend for status/doctor."""
    installed = crypto_available()
    version = ""
    if installed:
        try:
            import cryptography

            version = getattr(cryptography, "__version__", "")
        except Exception:  # pragma: no cover
            version = ""
    return {
        "cryptography_installed": installed,
        "cryptography_version": version,
        "ed25519_available": installed,
        "mldsa_available": mldsa_available(),
        "hmac_available": True,  # always: standard-library, zero dependencies
        "asymmetric_schemes": available_asymmetric_schemes(),
    }


def resolve_scheme(name: str) -> str:
    """Map a CLI alias or canonical id to a canonical asymmetric scheme id."""
    key = (name or "").strip().lower()
    if key in SCHEME_ALGORITHMS:
        return key
    if key in SCHEME_ALIASES:
        return SCHEME_ALIASES[key]
    raise ValueError(
        f"unknown signing scheme: {name!r} "
        f"(choose one of: ed25519, ml-dsa-65, hybrid)"
    )


# --- key generation / serialization -----------------------------------------
def _new_component_key(crypto: _CryptoNS, algorithm: str) -> Any:
    if algorithm == ALG_ED25519:
        return crypto.ed25519.Ed25519PrivateKey.generate()
    if algorithm == ALG_MLDSA65:
        if crypto.mldsa is None:
            raise SigningBackendUnavailable(
                "ML-DSA (post-quantum) is not available in this build of "
                "'cryptography'. Upgrade with:  pip install -U 'cryptography>=45'"
            )
        return crypto.mldsa.MLDSA65PrivateKey.generate()
    raise ValueError(f"unknown component algorithm: {algorithm!r}")


def _private_der(crypto: _CryptoNS, key: Any) -> bytes:
    return key.private_bytes(
        crypto.serialization.Encoding.DER,
        crypto.serialization.PrivateFormat.PKCS8,
        crypto.serialization.NoEncryption(),
    )


def _public_der(crypto: _CryptoNS, key: Any) -> bytes:
    return key.public_key().public_bytes(
        crypto.serialization.Encoding.DER,
        crypto.serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _key_id_from_public_ders(public_ders: dict[str, bytes]) -> str:
    """Non-reversible short id bound to the public key material (order-stable)."""
    h = hashlib.sha256(b"bastion-evidence-pubkey:v1")
    for algo in sorted(public_ders):
        h.update(algo.encode("ascii"))
        h.update(b"\x00")
        h.update(public_ders[algo])
        h.update(b"\x00")
    return h.hexdigest()[:16]


def generate_keypair(scheme: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate a keypair for ``scheme``; return ``(private_env, public_env)``.

    Both envelopes are JSON-serializable dicts. The private envelope holds
    base64 PKCS#8 DER per component algorithm and MUST be written owner-only.
    The public envelope holds base64 SubjectPublicKeyInfo DER and is safe to
    share — it is all a verifier needs.
    """
    scheme = resolve_scheme(scheme)
    crypto = _import_crypto()
    algorithms = SCHEME_ALGORITHMS[scheme]

    private_b64: dict[str, str] = {}
    public_b64: dict[str, str] = {}
    public_ders: dict[str, bytes] = {}
    for algo in algorithms:
        key = _new_component_key(crypto, algo)
        priv_der = _private_der(crypto, key)
        pub_der = _public_der(crypto, key)
        private_b64[algo] = base64.b64encode(priv_der).decode("ascii")
        public_b64[algo] = base64.b64encode(pub_der).decode("ascii")
        public_ders[algo] = pub_der

    key_id = _key_id_from_public_ders(public_ders)
    created_at = utcnow_iso()
    private_env = {
        "key_type": _PRIVATE_KEY_TYPE,
        "schema_version": _ENVELOPE_SCHEMA_VERSION,
        "scheme": scheme,
        "algorithms": list(algorithms),
        "key_id": key_id,
        "created_at": created_at,
        "keys": private_b64,
    }
    public_env = {
        "key_type": _PUBLIC_KEY_TYPE,
        "schema_version": _ENVELOPE_SCHEMA_VERSION,
        "scheme": scheme,
        "algorithms": list(algorithms),
        "key_id": key_id,
        "created_at": created_at,
        "keys": public_b64,
    }
    return private_env, public_env


# --- envelope validation -----------------------------------------------------
def is_private_key_envelope(obj: Any) -> bool:
    return isinstance(obj, dict) and obj.get("key_type") == _PRIVATE_KEY_TYPE


def is_public_key_envelope(obj: Any) -> bool:
    return isinstance(obj, dict) and obj.get("key_type") == _PUBLIC_KEY_TYPE


def _validate_envelope(env: Any, *, private: bool) -> str:
    want = _PRIVATE_KEY_TYPE if private else _PUBLIC_KEY_TYPE
    if not isinstance(env, dict):
        return "key envelope is not a JSON object"
    if env.get("key_type") != want:
        return f"not a {'private' if private else 'public'} signing key envelope"
    scheme = env.get("scheme")
    if scheme not in SCHEME_ALGORITHMS:
        return f"unsupported scheme in key envelope: {scheme!r}"
    keys = env.get("keys")
    if not isinstance(keys, dict) or not keys:
        return "key envelope has no key material"
    for algo in SCHEME_ALGORITHMS[scheme]:
        if not isinstance(keys.get(algo), str):
            return f"key envelope is missing material for {algo}"
    return ""


def public_key_id(env: dict[str, Any]) -> str:
    return str(env.get("key_id", ""))


def to_public_envelope(env: dict[str, Any]) -> dict[str, Any]:
    """Return a public-key envelope from either a public or a private envelope.

    A public envelope is returned as-is (after validation). A private envelope
    is converted by deriving each component public key — so an operator can
    verify with the private key file too, though the public file is what they
    would normally distribute.
    """
    if is_public_key_envelope(env):
        problem = _validate_envelope(env, private=False)
        if problem:
            raise ValueError(problem)
        return env
    problem = _validate_envelope(env, private=True)
    if problem:
        raise ValueError(problem)
    crypto = _import_crypto()
    scheme = env["scheme"]
    public_b64: dict[str, str] = {}
    public_ders: dict[str, bytes] = {}
    for algo in SCHEME_ALGORITHMS[scheme]:
        priv = _load_private_component(crypto, algo, env["keys"][algo])
        pub_der = _public_der(crypto, priv)
        public_b64[algo] = base64.b64encode(pub_der).decode("ascii")
        public_ders[algo] = pub_der
    return {
        "key_type": _PUBLIC_KEY_TYPE,
        "schema_version": _ENVELOPE_SCHEMA_VERSION,
        "scheme": scheme,
        "algorithms": list(SCHEME_ALGORITHMS[scheme]),
        "key_id": _key_id_from_public_ders(public_ders),
        "created_at": env.get("created_at", utcnow_iso()),
        "keys": public_b64,
    }


def _load_private_component(crypto: _CryptoNS, algo: str, b64: str) -> Any:
    der = base64.b64decode(b64, validate=True)
    key = crypto.serialization.load_der_private_key(der, password=None)
    _assert_component_type(crypto, algo, key.public_key())
    return key


def _load_public_component(crypto: _CryptoNS, algo: str, b64: str) -> Any:
    der = base64.b64decode(b64, validate=True)
    key = crypto.serialization.load_der_public_key(der)
    _assert_component_type(crypto, algo, key)
    return key


def _assert_component_type(crypto: _CryptoNS, algo: str, public_key: Any) -> None:
    if algo == ALG_ED25519:
        if not isinstance(public_key, crypto.ed25519.Ed25519PublicKey):
            raise ValueError("key material does not match algorithm 'ed25519'")
    elif algo == ALG_MLDSA65:
        if crypto.mldsa is None or not isinstance(public_key, crypto.mldsa.MLDSA65PublicKey):
            raise ValueError("key material does not match algorithm 'ml-dsa-65'")
    else:  # pragma: no cover - guarded by SCHEME_ALGORITHMS
        raise ValueError(f"unknown component algorithm: {algo!r}")


# --- sign / verify -----------------------------------------------------------
def sign(signing_input: bytes, private_env: dict[str, Any]) -> dict[str, str]:
    """Sign ``signing_input`` with every component key in ``private_env``.

    Returns ``{algorithm: hex_signature}``. The caller is responsible for
    building the canonical ``signing_input`` (Bastion covers the bundle digest
    plus the attested sidecar metadata, exactly like the HMAC scheme).
    """
    problem = _validate_envelope(private_env, private=True)
    if problem:
        raise ValueError(problem)
    crypto = _import_crypto()
    scheme = private_env["scheme"]
    signatures: dict[str, str] = {}
    for algo in SCHEME_ALGORITHMS[scheme]:
        key = _load_private_component(crypto, algo, private_env["keys"][algo])
        signatures[algo] = key.sign(signing_input).hex()
    return signatures


def verify(signing_input: bytes, signatures: dict[str, Any],
           public_env: dict[str, Any]) -> list[str]:
    """Verify ``signatures`` against ``signing_input`` using ``public_env``.

    Returns a list of problem strings (empty means the signature is valid).
    EVERY component algorithm required by the envelope's scheme must have a
    valid signature — so a hybrid bundle is rejected unless both the Ed25519
    and the ML-DSA-65 signatures verify. Never raises for a bad signature;
    only genuine backend/format errors surface as problems.
    """
    problem = _validate_envelope(public_env, private=False)
    if problem:
        return [problem]
    try:
        crypto = _import_crypto()
    except SigningBackendUnavailable as exc:
        return [str(exc)]
    if not isinstance(signatures, dict):
        return ["signature block is not an object"]

    scheme = public_env["scheme"]
    problems: list[str] = []
    for algo in SCHEME_ALGORITHMS[scheme]:
        sig_hex = signatures.get(algo)
        if not isinstance(sig_hex, str) or not sig_hex:
            problems.append(f"missing {algo} signature")
            continue
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            problems.append(f"malformed {algo} signature encoding")
            continue
        try:
            pub = _load_public_component(crypto, algo, public_env["keys"][algo])
        except Exception as exc:
            problems.append(f"unusable {algo} public key: {exc}")
            continue
        try:
            pub.verify(sig, signing_input)
        except crypto.InvalidSignature:
            problems.append(f"{algo} signature mismatch: bundle or signature tampered with")
        except Exception as exc:  # pragma: no cover - defensive
            problems.append(f"{algo} verification error: {exc}")
    return problems


def trust_model(scheme: str) -> str:
    """A one-line, honest trust statement for a sidecar/report."""
    if scheme == SCHEME_ED25519:
        return ("asymmetric Ed25519: verifiable by anyone holding the public key; "
                "third-party non-repudiation (not quantum-resistant)")
    if scheme == SCHEME_MLDSA65:
        return ("post-quantum ML-DSA-65 (FIPS 204): verifiable with the public key; "
                "quantum-resistant non-repudiation")
    if scheme == SCHEME_HYBRID:
        return ("hybrid Ed25519 + ML-DSA-65: verify requires BOTH signatures; "
                "quantum-resistant non-repudiation with a classical safety net "
                "(secure unless both primitives are broken)")
    return "unknown scheme"
