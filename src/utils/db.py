"""
SQLite database initialisation and connection management.
Schema: alerts, network_events, host_events, model_performance.
"""
import sqlite3
import threading
from contextlib import contextmanager
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    alert_type      TEXT NOT NULL,        -- NETWORK | HOST
    severity        TEXT NOT NULL,        -- LOW | MEDIUM | HIGH | CRITICAL
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    description     TEXT NOT NULL,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    confidence      REAL,
    model_votes     INTEGER,
    raw_features    TEXT,                 -- JSON blob of features
    notified        INTEGER DEFAULT 0,
    acknowledged    INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS network_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    bytes_sent      INTEGER,
    bytes_recv      INTEGER,
    packets         INTEGER,
    duration_ms     REAL,
    flags           TEXT,
    anomaly_score   REAL,
    label           TEXT DEFAULT 'benign'
);

CREATE TABLE IF NOT EXISTS host_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,       -- AUTH_FAIL | FILE_CHANGE | PROC_ANOMALY | SUDO
    hostname        TEXT,
    user            TEXT,
    pid             INTEGER,
    process_name    TEXT,
    file_path       TEXT,
    description     TEXT,
    anomaly_score   REAL
);

CREATE TABLE IF NOT EXISTS model_performance (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    model_name      TEXT NOT NULL,
    precision_val   REAL,
    recall_val      REAL,
    f1_score        REAL,
    false_pos_rate  REAL,
    total_scored    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_net_events_ts      ON network_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_host_events_ts     ON host_events(timestamp);
"""

def init_db():
    """Create tables and indexes if they don't exist."""
    import os
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.executescript(SCHEMA)
        conn.commit()
    logger.info("database_initialised", path=config.DB_PATH)

@contextmanager
def get_db():
    """Thread-safe SQLite connection context manager."""
    with _lock:
        conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

def insert_alert(alert: dict) -> int:
    """Insert an alert record. Returns the new row ID."""
    cols = ", ".join(alert.keys())
    placeholders = ", ".join("?" * len(alert))
    sql = f"INSERT INTO alerts ({cols}) VALUES ({placeholders})"
    with get_db() as conn:
        cur = conn.execute(sql, list(alert.values()))
        return cur.lastrowid

def insert_network_event(event: dict):
    cols = ", ".join(event.keys())
    placeholders = ", ".join("?" * len(event))
    sql = f"INSERT INTO network_events ({cols}) VALUES ({placeholders})"
    with get_db() as conn:
        conn.execute(sql, list(event.values()))

def insert_host_event(event: dict):
    cols = ", ".join(event.keys())
    placeholders = ", ".join("?" * len(event))
    sql = f"INSERT INTO host_events ({cols}) VALUES ({placeholders})"
    with get_db() as conn:
        conn.execute(sql, list(event.values()))

def get_recent_alerts(limit: int = 100, severity: str = None) -> list:
    sql = "SELECT * FROM alerts"
    params = []
    if severity:
        sql += " WHERE severity = ?"
        params.append(severity)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

def get_alert_counts_by_severity() -> dict:
    sql = "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    with get_db() as conn:
        rows = conn.execute(sql).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}
