"""
Alert Manager.
Central hub for all alerts (NIDS ML, NIDS signature, HIDS).
Responsibilities:
  1. Deduplication: suppress repeat alerts within DEDUP_WINDOW seconds
  2. Rate limiting: throttle alert flood (max N alerts/minute)
  3. Severity normalisation
  4. DB persistence
  5. Fan-out to notifiers
"""
import time
import hashlib
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, List
from src.utils.config import config
from src.utils.db import insert_alert, get_alert_counts_by_severity
from src.utils.logger import get_logger

logger = get_logger(__name__)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _alert_fingerprint(alert: dict) -> str:
    """Stable hash for deduplication. Same src/dst/type = same fingerprint."""
    key = "|".join([
        str(alert.get("alert_type", "")),
        str(alert.get("src_ip", "")),
        str(alert.get("dst_ip", "")),
        str(alert.get("dst_port", "")),
        str(alert.get("description", "")[:50]),
    ])
    return hashlib.md5(key.encode()).hexdigest()


class AlertManager:
    """
    Thread-safe alert manager.
    Call process(alert_dict) from any thread.
    """

    def __init__(self):
        self._notifiers: List[Callable] = []
        self._dedup: dict = {}          # fingerprint -> last_seen timestamp
        self._rate_window: deque = deque()  # timestamps in current minute
        self._lock = threading.Lock()

    def register_notifier(self, fn: Callable):
        """Register a notification callback (email, Slack, console, etc.)."""
        self._notifiers.append(fn)

    def process(self, alert: dict):
        """
        Accept an alert dict, apply dedup + rate-limit, persist, notify.
        """
        now = time.time()

        with self._lock:
            # ── Rate limit ──────────────────────────────────────────────────
            self._rate_window = deque(
                t for t in self._rate_window if now - t < 60
            )
            if len(self._rate_window) >= config.ALERT_RATE_LIMIT:
                logger.warning("alert_rate_limit_reached")
                return
            self._rate_window.append(now)

            # ── Deduplication ───────────────────────────────────────────────
            fp = _alert_fingerprint(alert)
            last = self._dedup.get(fp, 0)
            if now - last < config.ALERT_DEDUP_WINDOW:
                return   # Suppress duplicate
            self._dedup[fp] = now

        # ── Enrich with timestamp ────────────────────────────────────────────
        alert.setdefault("timestamp", datetime.utcnow().isoformat())
        alert.setdefault("severity", "LOW")
        alert.setdefault("alert_type", "UNKNOWN")
        alert.setdefault("notified", 0)

        # ── Persist ──────────────────────────────────────────────────────────
        try:
            alert_id = insert_alert(alert)
            alert["id"] = alert_id
        except Exception as e:
            logger.error("alert_persist_failed", error=str(e))

        # ── Log ──────────────────────────────────────────────────────────────
        logger.warning(
            "alert_raised",
            severity=alert.get("severity"),
            type=alert.get("alert_type"),
            src=alert.get("src_ip"),
            dst=alert.get("dst_ip"),
            description=alert.get("description", "")[:100],
        )

        # ── Notify ───────────────────────────────────────────────────────────
        for notifier in self._notifiers:
            try:
                notifier(alert)
            except Exception as e:
                logger.error("notifier_failed", error=str(e))

    def stats(self) -> dict:
        """Return alert counts grouped by severity."""
        return get_alert_counts_by_severity()
