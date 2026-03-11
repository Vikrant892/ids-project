"""
Real-Time ML Inference Engine.
Receives feature vectors from the NIDS pipeline, scores them,
and publishes results to the alert pipeline.
Thread-safe. Models are loaded once at startup.
"""
import json
import numpy as np
from typing import Callable, Optional
from src.ml.ensemble import EnsembleDetector
from src.nids.feature_extractor import extract_features, FEATURE_NAMES
from src.utils.logger import get_logger

logger = get_logger(__name__)


class InferenceEngine:
    """
    Wraps EnsembleDetector for the hot path (per-flow scoring).
    Provides score_flow(flow_dict) → optional alert dict.
    """

    def __init__(self, alert_callback: Optional[Callable] = None):
        self.ensemble = EnsembleDetector()
        self.alert_callback = alert_callback
        self._total_scored = 0
        self._total_flagged = 0

    def load(self):
        self.ensemble.load_models()

    def score_flow(self, flow: dict) -> Optional[dict]:
        """
        Score a completed flow dict.
        If ensemble flags it as attack, constructs and returns an alert dict.
        Also calls alert_callback if provided.
        """
        features = extract_features(flow)
        label, confidence, details = self.ensemble.predict(features)
        self._total_scored += 1

        # Store raw event
        from src.utils.db import insert_network_event
        try:
            insert_network_event({
                "timestamp":    flow.get("start_time", ""),
                "src_ip":       flow.get("src_ip", ""),
                "dst_ip":       flow.get("dst_ip", ""),
                "src_port":     flow.get("src_port", 0),
                "dst_port":     flow.get("dst_port", 0),
                "protocol":     flow.get("protocol", 0),
                "bytes_sent":   flow.get("fwd_bytes", 0),
                "bytes_recv":   flow.get("bwd_bytes", 0),
                "packets":      flow.get("total_packets", 0),
                "duration_ms":  flow.get("duration_ms", 0),
                "flags":        flow.get("flags", ""),
                "anomaly_score": confidence,
                "label":        "attack" if label else "benign",
            })
        except Exception as e:
            logger.warning("db_insert_failed", error=str(e))

        if label == 0:
            return None

        self._total_flagged += 1
        alert = self._build_alert(flow, confidence, details, features)

        if self.alert_callback:
            self.alert_callback(alert)

        return alert

    def _build_alert(self, flow: dict, confidence: float,
                     details: dict, features: np.ndarray) -> dict:
        severity = self._severity_from_confidence(confidence)
        return {
            "alert_type":    "NETWORK",
            "severity":      severity,
            "src_ip":        flow.get("src_ip", ""),
            "dst_ip":        flow.get("dst_ip", ""),
            "src_port":      flow.get("src_port", 0),
            "dst_port":      flow.get("dst_port", 0),
            "protocol":      str(flow.get("protocol", "")),
            "description":   (
                f"ML anomaly detected: confidence={confidence:.2%}, "
                f"votes={details['total_votes']}/3"
            ),
            "mitre_tactic":    "Unknown",
            "mitre_technique": "Unknown",
            "confidence":      confidence,
            "model_votes":     details["total_votes"],
            "raw_features":    json.dumps(
                dict(zip(FEATURE_NAMES, features.tolist()))
            ),
        }

    @staticmethod
    def _severity_from_confidence(conf: float) -> str:
        if conf >= 0.90:  return "CRITICAL"
        if conf >= 0.75:  return "HIGH"
        if conf >= 0.55:  return "MEDIUM"
        return "LOW"

    @property
    def stats(self) -> dict:
        rate = (self._total_flagged / max(self._total_scored, 1)) * 100
        return {
            "total_scored":  self._total_scored,
            "total_flagged": self._total_flagged,
            "flag_rate_pct": round(rate, 2),
        }
