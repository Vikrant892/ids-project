"""Unit tests — Alert Manager (deduplication + rate limiting)"""
import time
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

# Patch DB before importing alert_manager
import unittest.mock as mock

def make_alert(**kwargs):
    defaults = {
        "alert_type": "NETWORK", "severity": "HIGH",
        "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
        "src_port": 1234, "dst_port": 22,
        "description": "Test alert", "protocol": "TCP",
        "mitre_tactic": "Reconnaissance", "confidence": 0.9,
        "model_votes": 2, "raw_features": "{}",
    }
    defaults.update(kwargs)
    return defaults


class TestAlertManager:
    @mock.patch("src.utils.db.insert_alert", return_value=1)
    def test_alert_processed(self, mock_insert):
        from src.alerts.alert_manager import AlertManager
        received = []
        mgr = AlertManager()
        mgr.register_notifier(lambda a: received.append(a))
        mgr.process(make_alert())
        assert len(received) == 1

    @mock.patch("src.utils.db.insert_alert", return_value=1)
    def test_deduplication_suppresses_repeat(self, mock_insert):
        from src.alerts.alert_manager import AlertManager
        received = []
        mgr = AlertManager()
        mgr.register_notifier(lambda a: received.append(a))
        alert = make_alert()
        mgr.process(alert)
        mgr.process(alert)   # Identical — should be suppressed
        assert len(received) == 1

    @mock.patch("src.utils.db.insert_alert", return_value=1)
    def test_different_src_ip_not_deduplicated(self, mock_insert):
        from src.alerts.alert_manager import AlertManager
        received = []
        mgr = AlertManager()
        mgr.register_notifier(lambda a: received.append(a))
        mgr.process(make_alert(src_ip="1.1.1.1"))
        mgr.process(make_alert(src_ip="2.2.2.2"))
        assert len(received) == 2

    @mock.patch("src.utils.db.insert_alert", return_value=1)
    def test_rate_limit(self, mock_insert):
        from src.alerts.alert_manager import AlertManager
        from src.utils.config import config
        original = config.ALERT_RATE_LIMIT
        config.ALERT_RATE_LIMIT = 3
        received = []
        mgr = AlertManager()
        mgr.register_notifier(lambda a: received.append(a))
        # Send 5 distinct alerts
        for i in range(5):
            mgr.process(make_alert(src_ip=f"10.0.0.{i}", description=f"Alert {i}"))
        assert len(received) == 3   # Rate limit at 3
        config.ALERT_RATE_LIMIT = original
