"""
IDS Main Entry Point.
Wires all components together and starts:
  1. Database init
  2. ML model loading
  3. Alert manager + notifiers
  4. NIDS pipeline (packet capture → flow builder → inference)
  5. HIDS pipeline (log parser + FIM + process monitor)

Signal handlers ensure clean shutdown on SIGINT/SIGTERM.
"""
import signal
import sys
import threading
from src.utils.config import config
from src.utils.db import init_db
from src.utils.logger import get_logger
from src.nids.capture import PacketCapture
from src.nids.flow_builder import FlowBuilder
from src.nids.signature_engine import SignatureEngine
from src.nids.feature_extractor import extract_features
from src.ml.inference import InferenceEngine
from src.hids.log_parser import LogParser
from src.hids.file_integrity import FileIntegrityMonitor
from src.hids.process_monitor import ProcessMonitor
from src.alerts.alert_manager import AlertManager
from src.alerts.notifier import get_all_notifiers

logger = get_logger(__name__)

_components = []   # Track stoppable components for clean shutdown


def build_hids_alert(event, event_type: str) -> dict:
    """Convert a HIDS event object to an alert dict."""
    if hasattr(event, "__dict__"):
        d = event.__dict__.copy()
    elif hasattr(event, "to_dict"):
        d = event.to_dict()
    else:
        d = {}

    return {
        "alert_type":     "HOST",
        "severity":       d.get("severity", "MEDIUM"),
        "src_ip":         d.get("source_ip", "localhost"),
        "dst_ip":         "localhost",
        "src_port":       0,
        "dst_port":       0,
        "protocol":       "",
        "description":    d.get("description", str(d)[:120]),
        "mitre_tactic":   _hids_mitre_tactic(event_type),
        "mitre_technique": _hids_mitre_technique(event_type),
        "confidence":     0.9,
        "model_votes":    0,
        "raw_features":   "{}",
    }


def _hids_mitre_tactic(event_type: str) -> str:
    mapping = {
        "AUTH_FAIL": "Credential Access", "BRUTE_FORCE": "Credential Access",
        "AUTH_SUCCESS": "Initial Access",  "SUDO": "Privilege Escalation",
        "SUDO_FAIL": "Privilege Escalation", "USER_ADDED": "Persistence",
        "USER_DELETED": "Impact", "FILE_CHANGE": "Persistence",
        "MODIFIED": "Persistence", "CREATED": "Persistence",
        "DELETED": "Impact", "SUSPICIOUS_SPAWN": "Execution",
        "SUSPICIOUS_PROCESS": "Execution",
    }
    return mapping.get(event_type, "Unknown")


def _hids_mitre_technique(event_type: str) -> str:
    mapping = {
        "AUTH_FAIL": "T1110", "BRUTE_FORCE": "T1110.001",
        "SUDO": "T1548.003", "USER_ADDED": "T1136",
        "FILE_CHANGE": "T1565", "SUSPICIOUS_SPAWN": "T1059",
    }
    return mapping.get(event_type, "Unknown")


def main():
    logger.info("ids_starting", version="1.0.0", env=config.ENV)
    config.ensure_dirs()
    init_db()

    # ── Alert Manager ────────────────────────────────────────────────────────
    alert_mgr = AlertManager()
    for notifier in get_all_notifiers():
        alert_mgr.register_notifier(notifier)

    # ── ML Inference Engine ──────────────────────────────────────────────────
    inference = InferenceEngine(alert_callback=alert_mgr.process)
    try:
        inference.load()
    except Exception as e:
        logger.warning("models_not_loaded_running_without_ml", error=str(e))

    # ── Signature Engine ─────────────────────────────────────────────────────
    sig_engine = SignatureEngine()

    # ── NIDS Pipeline ────────────────────────────────────────────────────────
    def on_flow_complete(flow: dict):
        """Called by FlowBuilder when a flow is ready for analysis."""
        # 1. Signature check (fast path)
        sig_match = sig_engine.check_flow(flow)
        if sig_match:
            alert = {
                "alert_type":     "NETWORK",
                "severity":       sig_match.severity,
                "src_ip":         sig_match.src_ip,
                "dst_ip":         sig_match.dst_ip,
                "src_port":       sig_match.src_port,
                "dst_port":       sig_match.dst_port,
                "protocol":       "TCP",
                "description":    sig_match.description,
                "mitre_tactic":   sig_match.mitre_tactic,
                "mitre_technique": sig_match.mitre_technique,
                "confidence":     1.0,
                "model_votes":    0,
                "raw_features":   "{}",
            }
            alert_mgr.process(alert)

        # 2. ML scoring (slower path)
        if inference.is_ready():
            inference.score_flow(flow)

    flow_builder = FlowBuilder(on_flow_complete=on_flow_complete)
    capture = PacketCapture(callback=flow_builder.process_packet)
    _components.append(capture)

    # ── HIDS Pipeline ────────────────────────────────────────────────────────
    def on_hids_event(event):
        alert = build_hids_alert(event, getattr(event, "event_type", "UNKNOWN"))
        alert_mgr.process(alert)
        from src.utils.db import insert_host_event
        try:
            insert_host_event({
                "timestamp":   getattr(event, "timestamp", ""),
                "event_type":  getattr(event, "event_type", ""),
                "hostname":    getattr(event, "hostname", ""),
                "user":        getattr(event, "user", ""),
                "description": getattr(event, "description", "")[:500],
                "anomaly_score": 0.9,
            })
        except Exception:
            pass

    log_parser = LogParser(callback=on_hids_event)
    fim = FileIntegrityMonitor(callback=on_hids_event)
    proc_monitor = ProcessMonitor(callback=on_hids_event)
    _components.extend([log_parser, fim, proc_monitor])

    # ── Signal Handlers ──────────────────────────────────────────────────────
    def shutdown(sig, frame):
        logger.info("ids_shutting_down")
        for c in _components:
            try: c.stop()
            except Exception: pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start All Components ─────────────────────────────────────────────────
    log_parser.start()
    fim.start()
    proc_monitor.start()

    logger.info("ids_running",
                capture_mode=config.CAPTURE_MODE,
                interface=config.CAPTURE_INTERFACE)

    # Capture runs in foreground (blocks)
    capture.start()


if __name__ == "__main__":
    main()
