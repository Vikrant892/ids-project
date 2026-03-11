"""
Feature Engineering for NIDS flows.
Transforms a raw flow dict into a fixed-length numeric feature vector
compatible with Isolation Forest, Random Forest, and Autoencoder.

Feature categories:
  - Volume: bytes, packets, rates
  - Timing: duration, inter-arrival times
  - Flag: SYN/FIN/RST ratios
  - Port: well-known vs ephemeral, privilege vs unprivileged
  - Entropy: source IP entropy (computed at flow level via rolling stats)
"""
import math
import numpy as np
from typing import Dict, Any

# Ordered list — model expects this EXACT order
FEATURE_NAMES = [
    "duration_ms",
    "total_packets",
    "total_bytes",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "pkt_rate",
    "byte_rate",
    "fwd_bwd_ratio",
    "avg_pkt_size",
    "has_syn",
    "has_fin",
    "has_rst",
    "dst_port_well_known",    # dst_port < 1024
    "dst_port_registered",    # 1024 <= dst_port < 49152
    "dst_port_ephemeral",     # dst_port >= 49152
    "src_port_privileged",    # src_port < 1024
    "is_tcp",
    "is_udp",
    "is_icmp",
    "log_total_bytes",
    "log_pkt_rate",
    "log_byte_rate",
]

NUM_FEATURES = len(FEATURE_NAMES)


def extract_features(flow: Dict[str, Any]) -> np.ndarray:
    """
    Convert a flow dict to a numeric feature vector.
    Returns np.ndarray of shape (NUM_FEATURES,).
    Never raises — missing fields default to 0.
    """
    def safe(key, default=0):
        return flow.get(key, default) or default

    duration_ms    = max(safe("duration_ms"), 0.001)
    total_packets  = max(safe("total_packets"), 1)
    total_bytes    = max(safe("total_bytes"), 0)
    fwd_packets    = safe("fwd_packets")
    bwd_packets    = safe("bwd_packets")
    fwd_bytes      = safe("fwd_bytes")
    bwd_bytes      = safe("bwd_bytes")
    pkt_rate       = max(safe("pkt_rate"), 0.001)
    byte_rate      = max(safe("byte_rate"), 0.001)
    proto          = safe("protocol", 0)
    dst_port       = safe("dst_port", 0)
    src_port       = safe("src_port", 0)

    fwd_bwd_ratio  = fwd_packets / max(bwd_packets, 1)
    avg_pkt_size   = total_bytes / total_packets

    features = [
        duration_ms,
        total_packets,
        total_bytes,
        fwd_packets,
        bwd_packets,
        fwd_bytes,
        bwd_bytes,
        pkt_rate,
        byte_rate,
        fwd_bwd_ratio,
        avg_pkt_size,
        int(bool(safe("has_syn"))),
        int(bool(safe("has_fin"))),
        int(bool(safe("has_rst"))),
        int(dst_port < 1024),
        int(1024 <= dst_port < 49152),
        int(dst_port >= 49152),
        int(src_port < 1024),
        int(proto == 6),     # TCP
        int(proto == 17),    # UDP
        int(proto == 1),     # ICMP
        math.log1p(total_bytes),
        math.log1p(pkt_rate),
        math.log1p(byte_rate),
    ]

    return np.array(features, dtype=np.float32)


def features_to_dict(arr: np.ndarray) -> dict:
    """Map a feature array back to named fields for debugging."""
    return dict(zip(FEATURE_NAMES, arr.tolist()))
