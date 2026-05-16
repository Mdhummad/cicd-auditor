-- SQLite schema for cicd-auditor history database
-- Applied automatically by intelligence/history.py

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url     TEXT NOT NULL,
    scanned_at   TEXT NOT NULL,
    total_count  INTEGER DEFAULT 0,
    critical     INTEGER DEFAULT 0,
    high         INTEGER DEFAULT 0,
    medium       INTEGER DEFAULT 0,
    low          INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    file_path     TEXT,
    line_number   INTEGER,
    finding_type  TEXT,       -- 'secret' | 'misconfig' | 'dependency'
    rule_id       TEXT,
    severity      TEXT,
    risk_score    REAL,
    status        TEXT DEFAULT 'new',   -- 'new' | 'persisting' | 'fixed'
    description   TEXT,
    fix_snippet   TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_url);
