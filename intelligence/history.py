"""
SQLite-backed scan history manager.
Tracks findings over time to detect regressions and show improvement.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from dataclasses import asdict

DB_PATH = Path(__file__).parent.parent / 'db' / 'audit_history.sqlite'

SCHEMA = """
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
    scan_id       INTEGER REFERENCES scans(id),
    file_path     TEXT,
    line_number   INTEGER,
    finding_type  TEXT,
    rule_id       TEXT,
    severity      TEXT,
    risk_score    REAL,
    status        TEXT DEFAULT 'new',
    description   TEXT,
    fix_snippet   TEXT
);
"""


def _connect():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_scan(repo_url: str, findings: list) -> int:
    """Persist a completed scan and its findings. Returns the scan ID."""
    conn = _connect()
    now = datetime.utcnow().isoformat()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = getattr(f, 'severity', 'LOW').upper()
        counts[sev] = counts.get(sev, 0) + 1

    cur = conn.execute(
        "INSERT INTO scans(repo_url, scanned_at, total_count, critical, high, medium, low) "
        "VALUES(?,?,?,?,?,?,?)",
        (repo_url, now, len(findings),
         counts['CRITICAL'], counts['HIGH'], counts['MEDIUM'], counts['LOW'])
    )
    scan_id = cur.lastrowid

    # Determine status relative to last scan
    prev_keys = _get_previous_finding_keys(conn, repo_url, scan_id)

    for f in findings:
        key = f"{getattr(f,'rule_id','')}|{getattr(f,'file_path','')}"
        status = 'persisting' if key in prev_keys else 'new'
        conn.execute(
            "INSERT INTO findings(scan_id, file_path, line_number, finding_type, "
            "rule_id, severity, risk_score, status, description, fix_snippet) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                scan_id,
                getattr(f, 'file_path', ''),
                getattr(f, 'line_number', 0),
                getattr(f, 'finding_type', 'unknown'),
                getattr(f, 'rule_id', ''),
                getattr(f, 'severity', ''),
                getattr(f, 'risk_score', 0.0),
                status,
                getattr(f, 'description', ''),
                getattr(f, 'fix_suggestion', ''),
            )
        )

    # Mark fixed findings
    if prev_keys:
        current_keys = {
            f"{getattr(f,'rule_id','')}|{getattr(f,'file_path','')}"
            for f in findings
        }
        fixed_keys = prev_keys - current_keys
        if fixed_keys:
            conn.execute(
                f"UPDATE findings SET status='fixed' WHERE scan_id=? AND "
                f"(rule_id || '|' || file_path) IN ({','.join('?' * len(fixed_keys))})",
                [scan_id] + list(fixed_keys)
            )

    conn.commit()
    conn.close()
    return scan_id


def _get_previous_finding_keys(conn, repo_url: str, current_scan_id: int) -> set:
    """Return rule_id|file_path keys from the most recent previous scan."""
    prev = conn.execute(
        "SELECT id FROM scans WHERE repo_url=? AND id!=? ORDER BY id DESC LIMIT 1",
        (repo_url, current_scan_id)
    ).fetchone()
    if not prev:
        return set()
    rows = conn.execute(
        "SELECT rule_id, file_path FROM findings WHERE scan_id=?",
        (prev['id'],)
    ).fetchall()
    return {f"{r['rule_id']}|{r['file_path']}" for r in rows}


def get_scan_history(repo_url: str, limit: int = 10) -> list:
    """Return the last N scan summaries for a repo."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM scans WHERE repo_url=? ORDER BY id DESC LIMIT ?",
        (repo_url, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
