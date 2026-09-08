from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from app.config import DB_PATH, DATA_DIR


SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('reviewer', 'patient')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    full_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    member_id TEXT NOT NULL UNIQUE,
    zip_code TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id),
    policy_number TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to TEXT NOT NULL,
    annual_limit REAL NOT NULL,
    used_to_date REAL NOT NULL DEFAULT 0,
    deductible REAL NOT NULL,
    deductible_met REAL NOT NULL DEFAULT 0,
    network TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    patient_id INTEGER NOT NULL REFERENCES patients(id),
    policy_id INTEGER REFERENCES policies(id),
    submitted_by INTEGER REFERENCES users(id),
    provider_name TEXT NOT NULL,
    provider_npi TEXT NOT NULL,
    facility TEXT,
    date_of_service TEXT NOT NULL,
    diagnosis_code TEXT NOT NULL,
    procedure_code TEXT NOT NULL,
    amount REAL NOT NULL,
    place_of_service TEXT NOT NULL,
    is_emergency INTEGER NOT NULL DEFAULT 0,
    preauth_number TEXT,
    notes TEXT,
    status TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    fraud_probability REAL NOT NULL,
    coverage_ok INTEGER NOT NULL,
    confidence REAL NOT NULL,
    rationale TEXT NOT NULL,
    reviewer_id INTEGER REFERENCES users(id),
    reviewer_action TEXT,
    reviewer_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    doc_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decision_factors (
    id INTEGER PRIMARY KEY,
    claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    score_delta REAL NOT NULL,
    passed INTEGER NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id TEXT,
    detail TEXT,
    ip TEXT,
    created_at TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]
