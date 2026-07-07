"""Identity scan fixture-flow tests + the no-full-secrets guarantee."""

from __future__ import annotations

import json

from greynoc_bastion.adapters.nhi_adapter import NhiAdapter

# Full synthetic secrets that live in the sample project — none of these may
# ever appear in scan output, findings, or the database.
FULL_SECRETS = [
    "AKIAZ7GNOCFAKE4XZ9Q2W",
    "wJalrXUtnFGNOCK7MDbPxRfiCYzKq0011223344ab",
    "sk-proj-GN0Cfake1234567890abcdefghijklmnopqrstuv",
    "ghp_GN0Cfake1234567890abcdefghijklmnopqrst",
    "GN0C_synthetic_stripe_key_for_tests_01",
]


def test_scan_finds_expected_identities(sample_project):
    ids = NhiAdapter().scan_repo(sample_project)
    types = {i.identity_type.value for i in ids}
    # AWS cloud creds, github CI token, model gateway, MCP + AI agent surfaces.
    assert "cloud_workload" in types
    assert "ci_cd_token" in types
    assert "model_gateway" in types
    assert "mcp_server" in types
    assert "ai_agent" in types
    assert len(ids) >= 7


def test_placeholders_are_suppressed(sample_project):
    ids = NhiAdapter().scan_repo(sample_project)
    blob = json.dumps([i.to_dict() for i in ids])
    for placeholder in ("changeme", "your-client-secret-here", "xxxxxxxxxxxx"):
        assert placeholder not in blob


def test_no_full_secret_in_identity_records(sample_project):
    ids = NhiAdapter().scan_repo(sample_project)
    blob = json.dumps([i.to_dict() for i in ids])
    for secret in FULL_SECRETS:
        assert secret not in blob, f"leaked: {secret}"
    for i in ids:
        if i.masked_preview:
            assert "*" in i.masked_preview


def test_identities_never_marked_live(sample_project):
    ids = NhiAdapter().scan_repo(sample_project)
    # Bastion never validates credentials; liveness is always unknown.
    assert all(i.is_active_unknown for i in ids)


def test_service_persists_and_findings_have_no_secrets(app, sample_project):
    ids = app.identity.scan(sample_project, persist=True)
    assert ids
    # Stored findings
    findings = app.db.list_findings(category="identity")
    assert findings
    blob = json.dumps([f.to_dict() for f in findings])
    for secret in FULL_SECRETS:
        assert secret not in blob


def test_scan_result_is_deterministic_fingerprint(sample_project):
    a = NhiAdapter().scan_repo(sample_project)
    b = NhiAdapter().scan_repo(sample_project)
    fa = sorted(i.secret_fingerprint for i in a if i.secret_fingerprint)
    fb = sorted(i.secret_fingerprint for i in b if i.secret_fingerprint)
    assert fa == fb
