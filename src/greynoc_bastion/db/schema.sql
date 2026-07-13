-- GreyNOC Bastion — SQLite schema (MVP).
--
-- Design: each entity keeps its canonical form as a JSON document in `data`,
-- with a few promoted columns for indexing/filtering. This keeps schemas
-- flexible during the MVP and makes the future Postgres migration a matter of
-- swapping the driver and (optionally) promoting more columns / JSONB.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS threats (
    threat_id     TEXT PRIMARY KEY,
    category      TEXT,
    title         TEXT,
    severity      TEXT,
    urgency       REAL,
    kev           INTEGER DEFAULT 0,
    last_updated  TEXT,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threats_urgency ON threats(urgency DESC);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);

CREATE TABLE IF NOT EXISTS identities (
    identity_id       TEXT PRIMARY KEY,
    identity_type     TEXT,
    provider          TEXT,
    severity          TEXT,
    exposure          TEXT,
    repo_path         TEXT,
    secret_fingerprint TEXT,
    discovered_at     TEXT,
    data              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identities_type ON identities(identity_type);
CREATE INDEX IF NOT EXISTS idx_identities_fp ON identities(secret_fingerprint);

CREATE TABLE IF NOT EXISTS detections (
    detection_id  TEXT PRIMARY KEY,
    name          TEXT,
    severity      TEXT,
    status        TEXT,
    updated_at    TEXT,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);

CREATE TABLE IF NOT EXISTS validation_results (
    result_id     TEXT PRIMARY KEY,
    detection_id  TEXT,
    scenario      TEXT,
    verdict       TEXT,
    passed        INTEGER DEFAULT 0,
    ran_at        TEXT,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validation_detection ON validation_results(detection_id);

CREATE TABLE IF NOT EXISTS playbooks (
    slug          TEXT PRIMARY KEY,
    name          TEXT,
    category      TEXT,
    severity      TEXT,
    updated_at    TEXT,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_playbooks_category ON playbooks(category);

CREATE TABLE IF NOT EXISTS assets (
    asset_id      TEXT PRIMARY KEY,
    kind          TEXT,
    host          TEXT,
    port          INTEGER,
    exposure      TEXT,
    severity      TEXT,
    risky         INTEGER DEFAULT 0,
    last_seen     TEXT,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_risky ON assets(risky);

CREATE TABLE IF NOT EXISTS findings (
    correlation_id TEXT PRIMARY KEY,
    title          TEXT,
    severity       TEXT,
    confidence     TEXT,
    category       TEXT,
    validation_status TEXT,
    ref_type       TEXT,
    ref_id         TEXT,
    timestamp      TEXT,
    data           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);

CREATE TABLE IF NOT EXISTS reports (
    report_id     TEXT PRIMARY KEY,
    title         TEXT,
    generated_at  TEXT,
    data          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id   TEXT PRIMARY KEY,
    kind          TEXT,
    source        TEXT,
    collected_at  TEXT,
    data          TEXT NOT NULL
);

-- Append-only audit log for privileged / safety-relevant actions
-- (active checks, AI command execution, live fetches, config changes).
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    action        TEXT NOT NULL,
    actor         TEXT,
    detail        TEXT,
    correlation_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS meta (
    key           TEXT PRIMARY KEY,
    value         TEXT
);

-- Case management: assigned/tracked/closed response work built from findings.
CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    title         TEXT,
    status        TEXT,
    severity      TEXT,
    assignee      TEXT,
    created_at    TEXT,
    updated_at    TEXT,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assignee ON cases(assignee);

-- Operator accounts for multi-operator auth + RBAC. Only a salted, iterated
-- one-way hash of the password is ever stored (PBKDF2-HMAC-SHA256).
CREATE TABLE IF NOT EXISTS operators (
    username      TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    pw_hash       TEXT NOT NULL,
    pw_salt       TEXT NOT NULL,
    pw_iterations INTEGER NOT NULL,
    disabled      INTEGER DEFAULT 0,
    created_at    TEXT,
    updated_at    TEXT
);

-- Report / workflow schedules (local runner; nothing fires on its own —
-- `bastion schedule run-due` executes what is due).
CREATE TABLE IF NOT EXISTS schedules (
    schedule_id   TEXT PRIMARY KEY,
    name          TEXT,
    kind          TEXT,
    interval_hours REAL,
    next_run_at   TEXT,
    last_run_at   TEXT,
    enabled       INTEGER DEFAULT 1,
    data          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules(next_run_at);
