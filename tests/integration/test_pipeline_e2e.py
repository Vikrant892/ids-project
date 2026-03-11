"""
Integration test — Full NIDS pipeline (without real packets).
Simulates: flow dict → feature extraction → signature engine → alert manager.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
import unittest.mock as mock

BENIGN_FLOW = {
    "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
    "src_port": 54000, "dst_port": 443, "protocol": 6,
    "start_time": 1700000000.0, "duration_ms": 250.0,
    "total_packets": 8, "fwd_packets": 5, "bwd_packets": 3,
    "total_bytes": 2000, "fwd_bytes": 1200, "bwd_bytes": 800,
    "pkt_rate": 32.0, "byte_rate": 8000.0,
    "has_syn": True, "has_fin": True, "has_rst": False, "flags": "SF",
}

PORTSCAN_FLOW_TEMPLATE = {
    "src_ip": "10.0.0.99", "dst_ip": "192.168.1.1",
    "src_port": 60000, "dst_port": 0,   # will be varied
    "protocol": 6, "start_time": 1700000000.0,
    "duration_ms": 10.0, "total_packets": 1, "fwd_packets": 1, "bwd_packets": 0,
    "total_bytes": 60, "fwd_bytes": 60, "bwd_bytes": 0,
    "pkt_rate": 100.0, "byte_rate": 6000.0,
    "has_syn": True, "has_fin": False, "has_rst": False, "flags": "S",
}


class TestSignatureEngine:
    def test_port_scan_detection(self):
        from src.nids.signature_engine import SignatureEngine, PORT_SCAN_UNIQUE_PORTS
        engine = SignatureEngine()
        match = None
        for port in range(1, PORT_SCAN_UNIQUE_PORTS + 5):
            flow = {**PORTSCAN_FLOW_TEMPLATE, "dst_port": port}
            match = engine.check_flow(flow)
        assert match is not None
        assert match.rule_name == "PORT_SCAN"
        assert match.severity == "HIGH"

    def test_malicious_port_detection(self):
        from src.nids.signature_engine import SignatureEngine
        engine = SignatureEngine()
        flow = {**BENIGN_FLOW, "dst_port": 4444}   # Metasploit default
        match = engine.check_flow(flow)
        assert match is not None
        assert match.rule_name == "KNOWN_MALICIOUS_PORT"

    def test_benign_flow_no_match(self):
        from src.nids.signature_engine import SignatureEngine
        engine = SignatureEngine()
        match = engine.check_flow(BENIGN_FLOW)
        assert match is None

    def test_sensitive_port_medium_severity(self):
        from src.nids.signature_engine import SignatureEngine
        engine = SignatureEngine()
        flow = {**BENIGN_FLOW, "dst_port": 22}
        match = engine.check_flow(flow)
        assert match is not None
        assert match.severity == "MEDIUM"


class TestFeaturePipeline:
    def test_flow_to_features_no_error(self):
        from src.nids.feature_extractor import extract_features, NUM_FEATURES
        import numpy as np
        f = extract_features(BENIGN_FLOW)
        assert f.shape == (NUM_FEATURES,)
        assert not any(v != v for v in f)   # No NaN (NaN != NaN)


class TestAlertPipelineIntegration:
    @mock.patch("src.utils.db.insert_alert", return_value=1)
    @mock.patch("src.utils.db.insert_network_event")
    def test_signature_match_raises_alert(self, mock_net, mock_alert):
        from src.nids.signature_engine import SignatureEngine
        from src.alerts.alert_manager import AlertManager
        received = []
        mgr = AlertManager()
        mgr.register_notifier(lambda a: received.append(a))
        engine = SignatureEngine()

        flow = {**BENIGN_FLOW, "dst_port": 4444}
        match = engine.check_flow(flow)
        assert match is not None

        alert = {
            "alert_type": "NETWORK", "severity": match.severity,
            "src_ip": match.src_ip, "dst_ip": match.dst_ip,
            "src_port": match.src_port, "dst_port": match.dst_port,
            "protocol": "TCP", "description": match.description,
            "mitre_tactic": match.mitre_tactic,
            "mitre_technique": match.mitre_technique,
            "confidence": 1.0, "model_votes": 0, "raw_features": "{}",
        }
        mgr.process(alert)
        assert len(received) == 1
        assert received[0]["severity"] == "HIGH"
