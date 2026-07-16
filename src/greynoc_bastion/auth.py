"""Operator accounts, password verification, and RBAC.

Local-first multi-operator authentication:

  * Passwords are never stored — only PBKDF2-HMAC-SHA256 hashes with a unique
    random salt and a high iteration count.
  * Verification is constant-time (``hmac.compare_digest``) and hashes a decoy
    for unknown usernames so a login probe cannot distinguish "no such user"
    from "wrong password" by timing.
  * Roles: ``viewer`` < ``operator`` < ``admin`` (:class:`OperatorRole`).
  * Single-operator mode: with **no** accounts defined, the dashboard keeps its
    original local-trust behavior (loopback bind + optional bearer token).
    Creating the first account switches the dashboard to login-required.
  * The last enabled admin can never be disabled, demoted, or deleted.

Every mutation and every login attempt is written to the audit log. Nothing
here ever logs a password.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from .db import Database
from .schemas import OperatorRole, utcnow_iso
from .utils.logging import get_logger

PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_MIN_PASSWORD_LEN = 10
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")

# A fixed decoy verification target so unknown-user logins cost the same
# PBKDF2 work as real ones (timing-equalized rejection).
_DECOY_SALT = b"bastion-decoy-salt"
_DECOY_HASH = hashlib.pbkdf2_hmac("sha256", b"decoy-password", _DECOY_SALT, PBKDF2_ITERATIONS)


class AuthError(ValueError):
    """Raised for invalid account operations. Never carries a password."""


def hash_password(password: str, *, salt: bytes | None = None,
                  iterations: int = PBKDF2_ITERATIONS) -> tuple[str, str, int]:
    """Return ``(hash_hex, salt_hex, iterations)`` for storage."""
    salt = salt if salt is not None else secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return digest.hex(), salt.hex(), iterations


def _check_password_strength(password: str, username: str) -> None:
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD_LEN:
        raise AuthError(f"password must be at least {_MIN_PASSWORD_LEN} characters")
    if password.strip().lower() == username.strip().lower():
        raise AuthError("password must not equal the username")


class OperatorStore:
    """Account CRUD + verification over the ``operators`` table."""

    def __init__(self, db: Database):
        self.db = db
        self.log = get_logger("auth")

    # --- mode -------------------------------------------------------------
    def multi_operator_mode(self) -> bool:
        """True once at least one enabled account exists (login required)."""
        return self.db.count_operators(include_disabled=False) > 0

    # --- account management -------------------------------------------------
    def add(self, username: str, password: str, role: OperatorRole | str = OperatorRole.OPERATOR,
            *, actor: str = "system") -> dict:
        username = str(username or "").strip().lower()
        if not _USERNAME_RE.match(username):
            raise AuthError(
                "username must be 2-32 chars: lowercase letters, digits, '.', '_', '-' "
                "(starting with a letter or digit)")
        role_member = OperatorRole.coerce(role, None)
        if role_member is None:
            raise AuthError(f"unknown role: {role!r} (viewer, operator, admin)")
        if self.db.get_operator(username):
            raise AuthError(f"operator already exists: {username}")
        _check_password_strength(password, username)

        pw_hash, pw_salt, iterations = hash_password(password)
        record = {
            "username": username,
            "role": role_member.value,
            "pw_hash": pw_hash,
            "pw_salt": pw_salt,
            "pw_iterations": iterations,
            "disabled": False,
            "created_at": utcnow_iso(),
        }
        self.db.save_operator(record)
        self.db.audit("operator_added", actor=actor, detail=f"username={username} role={role_member.value}")
        return {"username": username, "role": role_member.value}

    def set_password(self, username: str, password: str, *, actor: str = "system") -> None:
        record = self._require(username)
        _check_password_strength(password, record["username"])
        pw_hash, pw_salt, iterations = hash_password(password)
        record.update(pw_hash=pw_hash, pw_salt=pw_salt, pw_iterations=iterations)
        self.db.save_operator(record)
        self.db.audit("operator_password_reset", actor=actor, detail=f"username={record['username']}")

    def set_role(self, username: str, role: OperatorRole | str, *, actor: str = "system") -> None:
        record = self._require(username)
        role_member = OperatorRole.coerce(role, None)
        if role_member is None:
            raise AuthError(f"unknown role: {role!r} (viewer, operator, admin)")
        if (record["role"] == OperatorRole.ADMIN.value
                and role_member != OperatorRole.ADMIN
                and self._is_last_enabled_admin(record["username"])):
            raise AuthError("cannot demote the last enabled admin")
        record["role"] = role_member.value
        self.db.save_operator(record)
        self.db.audit("operator_role_changed", actor=actor,
                      detail=f"username={record['username']} role={role_member.value}")

    def set_disabled(self, username: str, disabled: bool, *, actor: str = "system") -> None:
        record = self._require(username)
        if disabled and record["role"] == OperatorRole.ADMIN.value \
                and self._is_last_enabled_admin(record["username"]):
            raise AuthError("cannot disable the last enabled admin")
        record["disabled"] = bool(disabled)
        self.db.save_operator(record)
        action = "operator_disabled" if disabled else "operator_enabled"
        self.db.audit(action, actor=actor, detail=f"username={record['username']}")

    def delete(self, username: str, *, actor: str = "system") -> None:
        record = self._require(username)
        if record["role"] == OperatorRole.ADMIN.value and self._is_last_enabled_admin(record["username"]):
            raise AuthError("cannot delete the last enabled admin")
        self.db.delete_operator(record["username"])
        self.db.audit("operator_deleted", actor=actor, detail=f"username={record['username']}")

    def list_operators(self) -> list[dict]:
        return self.db.list_operators()

    # --- verification ---------------------------------------------------------
    def verify(self, username: str, password: str) -> OperatorRole | None:
        """Return the operator's role on success, else ``None``.

        Constant-time; disabled accounts and unknown usernames both pay full
        PBKDF2 cost and both return ``None``. Every attempt is audited (without
        the password).
        """
        username = str(username or "").strip().lower()
        record = self.db.get_operator(username) if username else None
        if not record:
            # Equalize timing for unknown users.
            candidate = hashlib.pbkdf2_hmac(
                "sha256", str(password or "").encode("utf-8"), _DECOY_SALT, PBKDF2_ITERATIONS)
            hmac.compare_digest(candidate, _DECOY_HASH)
            self.db.audit("login_failed", actor=username or "(empty)", detail="unknown user")
            return None

        candidate = hashlib.pbkdf2_hmac(
            "sha256", str(password or "").encode("utf-8"),
            bytes.fromhex(record["pw_salt"]), int(record["pw_iterations"]))
        ok = hmac.compare_digest(candidate.hex(), record["pw_hash"])
        if not ok or record.get("disabled"):
            reason = "disabled account" if (ok and record.get("disabled")) else "bad credentials"
            self.db.audit("login_failed", actor=username, detail=reason)
            return None
        self.db.audit("login_success", actor=username)
        return OperatorRole.coerce(record["role"], OperatorRole.VIEWER)

    # --- internals -----------------------------------------------------------
    def _require(self, username: str) -> dict:
        record = self.db.get_operator(str(username or "").strip().lower())
        if not record:
            raise AuthError(f"operator not found: {username}")
        record["disabled"] = bool(record.get("disabled"))
        return record

    def _is_last_enabled_admin(self, username: str) -> bool:
        admins = [o for o in self.db.list_operators()
                  if o["role"] == OperatorRole.ADMIN.value and not o["disabled"]]
        return len(admins) == 1 and admins[0]["username"] == username
