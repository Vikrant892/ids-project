"""
Alert Store helpers — convenience wrappers over db.py for the dashboard.
"""
from src.utils.db import get_recent_alerts, get_alert_counts_by_severity, get_db


def get_alerts(limit: int = 200, severity: str = None) -> list:
    return get_recent_alerts(limit=limit, severity=severity)


def get_severity_counts() -> dict:
    return get_alert_counts_by_severity()


def acknowledge_alert(alert_id: int):
    with get_db() as conn:
        conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )


def get_alert_timeline(hours: int = 24) -> list:
    """Return hourly alert counts for the past N hours."""
    sql = """
        SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
               COUNT(*) as count
        FROM alerts
        WHERE timestamp >= datetime('now', ?)
        GROUP BY hour
        ORDER BY hour
    """
    param = f"-{hours} hours"
    with get_db() as conn:
        rows = conn.execute(sql, (param,)).fetchall()
        return [dict(r) for r in rows]


def get_top_source_ips(limit: int = 10) -> list:
    sql = """
        SELECT src_ip, COUNT(*) as cnt
        FROM alerts
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT ?
    """
    with get_db() as conn:
        rows = conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]
