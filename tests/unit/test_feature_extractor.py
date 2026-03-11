"""Unit tests — Feature Extractor"""
import numpy as np
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from src.nids.feature_extractor import extract_features, FEATURE_NAMES, NUM_FEATURES


def make_flow(**kwargs):
    defaults = {
        "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1",
        "src_port": 12345, "dst_port": 80, "protocol": 6,
        "duration_ms": 100.0, "total_packets": 10, "total_bytes": 1500,
        "fwd_packets": 6, "bwd_packets": 4, "fwd_bytes": 900, "bwd_bytes": 600,
        "pkt_rate": 100.0, "byte_rate": 15000.0,
        "has_syn": True, "has_fin": True, "has_rst": False, "flags": "SF",
    }
    defaults.update(kwargs)
    return defaults


class TestExtractFeatures:
    def test_output_shape(self):
        f = extract_features(make_flow())
        assert f.shape == (NUM_FEATURES,), f"Expected ({NUM_FEATURES},), got {f.shape}"

    def test_output_dtype(self):
        f = extract_features(make_flow())
        assert f.dtype == np.float32

    def test_no_nan_or_inf(self):
        f = extract_features(make_flow())
        assert not np.isnan(f).any(), "NaN in features"
        assert not np.isinf(f).any(), "Inf in features"

    def test_zero_flow_no_crash(self):
        """All-zero flow must not crash or produce NaN."""
        f = extract_features({})
        assert f.shape == (NUM_FEATURES,)
        assert not np.isnan(f).any()

    def test_high_traffic_flow(self):
        f = extract_features(make_flow(total_bytes=10_000_000, total_packets=50000))
        assert not np.isinf(f).any()

    def test_feature_names_count(self):
        assert len(FEATURE_NAMES) == NUM_FEATURES

    def test_tcp_protocol_flag(self):
        f = extract_features(make_flow(protocol=6))
        # is_tcp is at index FEATURE_NAMES.index("is_tcp")
        idx = FEATURE_NAMES.index("is_tcp")
        assert f[idx] == 1.0

    def test_udp_protocol_flag(self):
        f = extract_features(make_flow(protocol=17, dst_port=53))
        idx = FEATURE_NAMES.index("is_udp")
        assert f[idx] == 1.0

    def test_well_known_port(self):
        f = extract_features(make_flow(dst_port=443))
        idx = FEATURE_NAMES.index("dst_port_well_known")
        assert f[idx] == 1.0

    def test_ephemeral_port(self):
        f = extract_features(make_flow(dst_port=55000))
        idx = FEATURE_NAMES.index("dst_port_ephemeral")
        assert f[idx] == 1.0
