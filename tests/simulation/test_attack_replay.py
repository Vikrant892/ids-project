"""
Simulation tests — Replay known attack patterns.
Verifies that known attacks are detected at expected severity levels.
These tests use the full signature engine with realistic flow data.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from src.nids.signature_engine import SignatureEngine


class TestAttackSimulations:
    def setup_method(self):
        self.engine = SignatureEngine()

    def _make_flow(self, **kwargs):
        base = {
            "src_ip": "attacker", "dst_ip": "victim",
            "src_port": 60000, "dst_port": 80, "protocol": 6,
            "start_time": 1700000000.0, "duration_ms": 10.0,
            "total_packets": 1, "fwd_packets": 1, "bwd_packets": 0,
            "total_bytes": 60, "fwd_bytes": 60, "bwd_bytes": 0,
            "pkt_rate": 100.0, "byte_rate": 6000.0,
            "has_syn": False, "has_fin": False, "has_rst": False, "flags": "",
        }
        base.update(kwargs)
        return base

    def test_syn_flood_critical(self):
        """100+ SYN-only packets/sec from same src → CRITICAL."""
        match = None
        for i in range(110):
            flow = self._make_flow(
                has_syn=True, flags="S",
                src_ip="evil.attacker",
                start_time=1700000000.0 + i * 0.005  # 0.5s window
            )
            match = self.engine.check_flow(flow)
        assert match is not None
        assert match.rule_name == "SYN_FLOOD"
        assert match.severity == "CRITICAL"

    def test_dns_amplification(self):
        """Large UDP 53 response vs tiny request → amplification."""
        flow = self._make_flow(
            protocol=17, src_port=53, dst_port=0,
            fwd_bytes=50, bwd_bytes=5000,
            total_bytes=5050, total_packets=2,
        )
        match = self.engine.check_flow(flow)
        assert match is not None
        assert match.rule_name == "DNS_AMPLIFICATION"

    def test_metasploit_port(self):
        flow = self._make_flow(dst_port=4444)
        match = self.engine.check_flow(flow)
        assert match is not None
        assert match.severity == "HIGH"

    def test_rdp_access(self):
        flow = self._make_flow(dst_port=3389)
        match = self.engine.check_flow(flow)
        assert match is not None
        assert match.severity == "MEDIUM"

    def test_benign_https_no_alert(self):
        flow = self._make_flow(dst_port=443, src_ip="office.user")
        match = self.engine.check_flow(flow)
        assert match is None
