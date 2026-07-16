"""Operator accounts, password hashing, RBAC, and the dashboard login gate."""

from __future__ import annotations

import pytest

from greynoc_bastion.auth import AuthError, OperatorStore, hash_password
from greynoc_bastion.schemas import OperatorRole
from greynoc_bastion.web.server import create_app

PW = "correct-horse-battery"


# --- store ---------------------------------------------------------------------
def test_password_hashing_salted_and_unique():
    h1, s1, i1 = hash_password(PW)
    h2, s2, i2 = hash_password(PW)
    assert h1 != h2 and s1 != s2          # unique salt every time
    assert i1 == i2 >= 100_000
    assert PW not in h1 and PW not in s1


def test_add_verify_roundtrip(app):
    store = OperatorStore(app.db)
    assert not store.multi_operator_mode()
    store.add("alice", PW, "admin")
    assert store.multi_operator_mode()
    assert store.verify("alice", PW) == OperatorRole.ADMIN
    assert store.verify("alice", "wrong-password") is None
    assert store.verify("mallory", PW) is None
    # Stored record never contains the password.
    record = app.db.get_operator("alice")
    assert PW not in str(record)


def test_account_validation_rules(app):
    store = OperatorStore(app.db)
    with pytest.raises(AuthError):
        store.add("x", PW)                       # too-short username
    with pytest.raises(AuthError):
        store.add("Bad User!", PW)               # invalid chars
    with pytest.raises(AuthError):
        store.add("alice", "short")              # weak password
    with pytest.raises(AuthError):
        store.add("alice", "alice")              # equals username (and short)
    store.add("alice", PW)
    with pytest.raises(AuthError):
        store.add("alice", PW)                   # duplicate
    with pytest.raises(AuthError):
        store.add("bob", PW, role="superuser")   # unknown role


def test_disabled_account_cannot_login(app):
    store = OperatorStore(app.db)
    store.add("alice", PW, "admin")
    store.add("bob", PW, "operator")
    store.set_disabled("bob", True)
    assert store.verify("bob", PW) is None
    store.set_disabled("bob", False)
    assert store.verify("bob", PW) == OperatorRole.OPERATOR


def test_last_admin_is_protected(app):
    store = OperatorStore(app.db)
    store.add("alice", PW, "admin")
    with pytest.raises(AuthError):
        store.set_role("alice", "viewer")
    with pytest.raises(AuthError):
        store.set_disabled("alice", True)
    with pytest.raises(AuthError):
        store.delete("alice")
    # With a second admin, the first may be demoted.
    store.add("carol", PW, "admin")
    store.set_role("alice", "viewer")
    assert store.verify("alice", PW) == OperatorRole.VIEWER


def test_auth_events_are_audited(app):
    store = OperatorStore(app.db)
    store.add("alice", PW, "admin")
    store.verify("alice", PW)
    store.verify("alice", "nope")
    actions = [e["action"] for e in app.db.recent_audit(limit=20)]
    assert "operator_added" in actions
    assert "login_success" in actions
    assert "login_failed" in actions
    # No password material anywhere in the audit trail.
    trail = str(app.db.recent_audit(limit=20))
    assert PW not in trail and "nope" not in trail


def test_role_ordering():
    assert OperatorRole.ADMIN.allows(OperatorRole.OPERATOR)
    assert OperatorRole.OPERATOR.allows(OperatorRole.VIEWER)
    assert not OperatorRole.VIEWER.allows(OperatorRole.OPERATOR)
    assert not OperatorRole.OPERATOR.allows(OperatorRole.ADMIN)


# --- dashboard gate ---------------------------------------------------------------
def _login(client, username, password):
    """Establish a session (CSRF) then post credentials."""
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": csrf})


def test_no_accounts_keeps_local_trust_mode(app):
    client = create_app(app).test_client()
    assert client.get("/").status_code == 200
    assert client.get("/cases").status_code == 200
    # Login page just bounces back when no accounts exist.
    assert client.get("/login").status_code == 302


def test_first_account_switches_to_login_required(app):
    app.operators.add("alice", PW, "admin")
    client = create_app(app).test_client()
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.get("/healthz").status_code == 200   # health stays open
    # POSTs without login are refused outright (401, not redirect).
    with client.session_transaction() as sess:
        sess["_csrf"] = "t"
    assert client.post("/run/detections", data={"csrf_token": "t"}).status_code == 401


def test_login_logout_flow(app):
    app.operators.add("alice", PW, "admin")
    client = create_app(app).test_client()
    r = _login(client, "alice", PW)
    assert r.status_code == 302
    assert client.get("/").status_code == 200
    assert client.get("/users").status_code == 200      # admin page visible
    # Logout invalidates the session.
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    client.post("/logout", data={"csrf_token": csrf})
    assert client.get("/").status_code == 302


def test_bad_login_rejected(app):
    app.operators.add("alice", PW, "admin")
    client = create_app(app).test_client()
    _login(client, "alice", "wrong-password!")
    assert client.get("/").status_code == 302           # still logged out


def test_login_throttled_after_repeated_failures(app):
    app.operators.add("alice", PW, "admin")
    client = create_app(app).test_client()
    for _ in range(5):
        _login(client, "alice", "wrong-password!")
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    r = client.post("/login", data={"username": "alice", "password": PW, "csrf_token": csrf})
    assert r.status_code == 429                          # even the right password now waits


def test_viewer_cannot_post_operator_can(app):
    app.operators.add("admin1", PW, "admin")
    app.operators.add("viewer1", PW, "viewer")
    app.operators.add("op1", PW, "operator")

    client = create_app(app).test_client()
    _login(client, "viewer1", PW)
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    assert client.post("/run/detections", data={"csrf_token": csrf}).status_code == 403
    assert client.get("/audit").status_code == 403       # audit is operator+
    assert client.get("/users").status_code == 403       # users is admin-only
    assert client.get("/cases").status_code == 200       # reading is fine

    client2 = create_app(app).test_client()
    _login(client2, "op1", PW)
    with client2.session_transaction() as sess:
        csrf2 = sess["_csrf"]
    assert client2.post("/run/detections", data={"csrf_token": csrf2}).status_code == 302
    assert client2.get("/audit").status_code == 200
    assert client2.get("/users").status_code == 403      # operator still not admin
    assert client2.post("/users/add", data={"csrf_token": csrf2, "username": "x",
                                            "password": PW}).status_code == 403


def test_viewer_can_always_log_out(app):
    # Regression: the RBAC floor must not trap a viewer in-session. Logout is a
    # POST but any authenticated role must be able to end its own session.
    app.operators.add("admin1", PW, "admin")
    app.operators.add("viewer1", PW, "viewer")
    client = create_app(app).test_client()
    _login(client, "viewer1", PW)
    assert client.get("/").status_code == 200
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    assert client.post("/logout", data={"csrf_token": csrf}).status_code == 302
    assert client.get("/").status_code == 302            # session ended -> back to login


def test_login_throttle_map_is_bounded(app):
    # Regression: an unauthenticated sprayer must not grow the throttle map
    # without bound. Feed far more distinct keys than the cap and assert the
    # map stays bounded.
    from greynoc_bastion.web.server import _THROTTLE_MAX_KEYS, _LoginThrottle
    throttle = _LoginThrottle()
    for i in range(_THROTTLE_MAX_KEYS + 500):
        throttle.record_failure(f"10.0.0.{i}|user{i}")
    assert len(throttle._failures) <= _THROTTLE_MAX_KEYS


def test_admin_manages_users_via_web(app):
    app.operators.add("admin1", PW, "admin")
    client = create_app(app).test_client()
    _login(client, "admin1", PW)
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    r = client.post("/users/add", data={"csrf_token": csrf, "username": "dave",
                                        "password": PW, "role": "viewer"})
    assert r.status_code == 302
    assert any(o["username"] == "dave" for o in app.operators.list_operators())
    r = client.post("/users/dave/role", data={"csrf_token": csrf, "role": "operator"})
    assert r.status_code == 302
    assert app.db.get_operator("dave")["role"] == "operator"


def test_role_change_takes_effect_immediately(app):
    app.operators.add("admin1", PW, "admin")
    app.operators.add("eve", PW, "operator")
    client = create_app(app).test_client()
    _login(client, "eve", PW)
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    assert client.post("/run/detections", data={"csrf_token": csrf}).status_code == 302
    # Demote eve mid-session: her next POST must be refused without re-login.
    app.operators.set_role("eve", "viewer", actor="admin1")
    assert client.post("/run/detections", data={"csrf_token": csrf}).status_code == 403
    # Disable eve entirely: even reads now bounce to login.
    app.operators.set_disabled("eve", True, actor="admin1")
    assert client.get("/").status_code == 302


def test_static_token_still_works_but_is_not_admin(app):
    app.operators.add("alice", PW, "admin")
    app.config.dashboard_token = "tkn-abc"
    client = create_app(app).test_client()
    headers = {"Authorization": "Bearer tkn-abc"}
    assert client.get("/", headers=headers).status_code == 200
    # Token = machine channel = operator level: module runs OK…
    assert client.post("/run/detections", headers=headers).status_code == 302
    # …but never account management.
    assert client.post("/users/add", headers=headers,
                       data={"username": "x", "password": PW}).status_code == 403


def test_combined_token_and_accounts_allows_remote_login(app):
    # Regression: with BOTH a dashboard token AND operator accounts (the remote
    # multi-operator scenario — remote bind requires a token), form login must
    # still work. The token gate must not hard-401 the login page or a
    # logged-in session that lacks the token.
    app.operators.add("alice", PW, "admin")
    app.config.dashboard_token = "tkn-abc"
    client = create_app(app).test_client()
    assert client.get("/login").status_code == 200            # login page reachable
    r = _login(client, "alice", PW)
    assert r.status_code == 302
    assert client.get("/").status_code == 200                 # logged-in session works w/o token
    # An anonymous client is still bounced to login (not served, not hard-401).
    anon = create_app(app).test_client()
    r = anon.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    # The bearer token remains a valid machine channel.
    assert anon.get("/", headers={"Authorization": "Bearer tkn-abc"}).status_code == 200


def test_pure_token_mode_still_requires_token(app):
    # With a token but NO accounts, the token remains mandatory on every request.
    app.config.dashboard_token = "tkn-abc"
    client = create_app(app).test_client()
    assert client.get("/").status_code == 401
    assert client.get("/", headers={"Authorization": "Bearer tkn-abc"}).status_code == 200


def test_login_open_redirect_refused(app):
    app.operators.add("alice", PW, "admin")
    client = create_app(app).test_client()
    # Absolute URL, protocol-relative //host, and the backslash bypass /\host
    # (browsers fold \ to /) must all be refused; a plain in-app path is kept.
    for bad in ("https://evil.example", "//evil.example", "/\\evil.example",
                "/\\/evil.example", "https:evil.example"):
        client.get("/login")
        with client.session_transaction() as sess:
            csrf = sess["_csrf"]
        r = client.post("/login", data={"username": "alice", "password": PW,
                                        "csrf_token": csrf, "next": bad})
        assert r.status_code == 302
        assert "evil.example" not in r.headers["Location"], bad
        client.post("/logout", data={"csrf_token": csrf})
    # A legitimate in-app next is honored.
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    r = client.post("/login", data={"username": "alice", "password": PW,
                                    "csrf_token": csrf, "next": "/cases"})
    assert r.headers["Location"].endswith("/cases")


def test_token_bootstrap_is_bound_to_current_token(app):
    # Regression: a ?token= bootstrap stores a fingerprint of the CURRENT token,
    # not a bare "authed" flag, so a session bootstrapped from an OLD token is
    # revoked the moment the token is rotated (even with a persistent cookie).
    from greynoc_bastion.web.server import _token_fingerprint

    app.config.dashboard_token = "tkn-new"
    client = create_app(app).test_client()
    # A session carrying the fingerprint of the CURRENT token authenticates.
    with client.session_transaction() as sess:
        sess["_token_fp"] = _token_fingerprint("tkn-new")
    assert client.get("/").status_code == 200
    # A session carrying a stale fingerprint (from a rotated-away token) does not.
    with client.session_transaction() as sess:
        sess["_token_fp"] = _token_fingerprint("tkn-old")
    assert client.get("/").status_code == 401
    # The bare legacy flag no longer grants anything.
    with client.session_transaction() as sess:
        sess.pop("_token_fp", None)
        sess["_authed"] = True
    assert client.get("/").status_code == 401


def test_query_token_bootstrap_persists_within_token(app):
    # A ?token= visit bootstraps a session that keeps working without re-supplying
    # the token — as long as the token is unchanged.
    app.config.dashboard_token = "tkn-abc"
    client = create_app(app).test_client()
    assert client.get("/?token=tkn-abc").status_code == 200
    assert client.get("/").status_code == 200
