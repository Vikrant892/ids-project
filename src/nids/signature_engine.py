"""
Signature-Based Detection Engine.
Runs BEFORE the ML engine as a fast pre-filter.
Detects well-known attack patterns deterministically:
  - Port scan (many distinct dst_ports from one src in short window)
  - SYN flood (high SYN rate, low ACK rate)
  - Known bad ports (common C2/malware ports)
  - ICMP flood
  - DNS amplification (UDP 53 with large response)

Returns a SignatureMatch or None.
"""
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Ports historically associated with malware C2 / backdoors
MALICIOUS_PORTS = {
    31337, 4444, 1337, 6666, 6667, 6668,  # Metasploit / backdoors
    12345, 54321, 27374,                    # SubSeven, NetBus
    3128, 8080, 9050,                       # Common proxies/TOR
}

SENSITIVE_PORTS = {22, 23, 3389, 5900, 445, 139, 135}  # SSH, Telnet, RDP, VNC, SMB

# Thresholds
PORT_SCAN_UNIQUE_PORTS = 20     # distinct dst_ports in window → port scan
PORT_SCAN_WINDOW_SEC = 10
SYN_FLOOD_RATE = 100            # SYN packets/sec from one src
ICMP_FLOOD_RATE = 200           # ICMP packets/sec


@dataclass
class SignatureMatch:
    rule_name: str
    description: str
    severity: str                # LOW | MEDIUM | HIGH | CRITICAL
    mitre_tactic: str
    mitre_technique: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int


class SignatureEngine:
    """
    Stateful signature engine. Maintains rolling counters per source IP.
    Call check_flow(flow_dict) for each completed flow.
    """

    def __init__(self):
        # src_ip -> list of (timestamp, dst_port)
        self._port_scan_tracker: defaultdict = defaultdict(list)
        # src_ip -> list of timestamps (SYN packets)
        self._syn_tracker: defaultdict = defaultdict(list)
        # src_ip -> list of timestamps (ICMP)
        self._icmp_tracker: defaultdict = defaultdict(list)

    def check_flow(self, flow: dict) -> Optional[SignatureMatch]:
        """
        Run all signature checks against a completed flow.
        Returns first match (highest severity wins if multiple).
        """
        checks = [
            self._check_malicious_port,
            self._check_port_scan,
            self._check_syn_flood,
            self._check_icmp_flood,
            self._check_dns_amplification,
            self._check_sensitive_port_access,
        ]
        matches = []
        for check in checks:
            match = check(flow)
            if match:
                matches.append(match)

        if not matches:
            return None

        # Return highest severity match
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return max(matches, key=lambda m: severity_order.get(m.severity, 0))

    def _check_malicious_port(self, flow: dict) -> Optional[SignatureMatch]:
        dst_port = flow.get("dst_port", 0)
        if dst_port in MALICIOUS_PORTS:
            return SignatureMatch(
                rule_name="KNOWN_MALICIOUS_PORT",
                description=f"Connection to known malicious/C2 port {dst_port}",
                severity="HIGH",
                mitre_tactic="Command and Control",
                mitre_technique="T1071",
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                src_port=flow.get("src_port", 0),
                dst_port=dst_port,
            )
        return None

    def _check_port_scan(self, flow: dict) -> Optional[SignatureMatch]:
        src = flow.get("src_ip", "")
        dst_port = flow.get("dst_port", 0)
        now = flow.get("start_time", time.time())

        tracker = self._port_scan_tracker[src]
        tracker.append((now, dst_port))

        # Evict entries outside window
        tracker[:] = [(t, p) for t, p in tracker if now - t <= PORT_SCAN_WINDOW_SEC]
        unique_ports = len(set(p for _, p in tracker))

        if unique_ports >= PORT_SCAN_UNIQUE_PORTS:
            return SignatureMatch(
                rule_name="PORT_SCAN",
                description=f"{src} scanned {unique_ports} unique ports in {PORT_SCAN_WINDOW_SEC}s",
                severity="HIGH",
                mitre_tactic="Reconnaissance",
                mitre_technique="T1046",
                src_ip=src,
                dst_ip=flow.get("dst_ip", ""),
                src_port=flow.get("src_port", 0),
                dst_port=dst_port,
            )
        return None

    def _check_syn_flood(self, flow: dict) -> Optional[SignatureMatch]:
        if not flow.get("has_syn") or flow.get("has_ack"):
            return None
        src = flow.get("src_ip", "")
        now = flow.get("start_time", time.time())
        tracker = self._syn_tracker[src]
        tracker.append(now)
        tracker[:] = [t for t in tracker if now - t <= 1.0]  # 1-second window
        if len(tracker) >= SYN_FLOOD_RATE:
            return SignatureMatch(
                rule_name="SYN_FLOOD",
                description=f"SYN flood from {src}: {len(tracker)} SYNs/sec",
                severity="CRITICAL",
                mitre_tactic="Impact",
                mitre_technique="T1499",
                src_ip=src,
                dst_ip=flow.get("dst_ip", ""),
                src_port=flow.get("src_port", 0),
                dst_port=flow.get("dst_port", 0),
            )
        return None

    def _check_icmp_flood(self, flow: dict) -> Optional[SignatureMatch]:
        if flow.get("protocol") != 1:
            return None
        src = flow.get("src_ip", "")
        now = flow.get("start_time", time.time())
        tracker = self._icmp_tracker[src]
        tracker.append(now)
        tracker[:] = [t for t in tracker if now - t <= 1.0]
        if len(tracker) >= ICMP_FLOOD_RATE:
            return SignatureMatch(
                rule_name="ICMP_FLOOD",
                description=f"ICMP flood from {src}: {len(tracker)} packets/sec",
                severity="HIGH",
                mitre_tactic="Impact",
                mitre_technique="T1498",
                src_ip=src,
                dst_ip=flow.get("dst_ip", ""),
                src_port=0,
                dst_port=0,
            )
        return None

    def _check_dns_amplification(self, flow: dict) -> Optional[SignatureMatch]:
        """Large UDP responses on port 53 with inverted fwd/bwd ratio → amplification."""
        if flow.get("protocol") != 17:
            return None
        if flow.get("src_port") != 53 and flow.get("dst_port") != 53:
            return None
        bwd = flow.get("bwd_bytes", 0)
        fwd = flow.get("fwd_bytes", 1)
        if bwd > 0 and (bwd / max(fwd, 1)) > 10 and bwd > 4000:
            return SignatureMatch(
                rule_name="DNS_AMPLIFICATION",
                description=f"Possible DNS amplification: {fwd}B req → {bwd}B resp",
                severity="HIGH",
                mitre_tactic="Impact",
                mitre_technique="T1498.002",
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                src_port=flow.get("src_port", 0),
                dst_port=flow.get("dst_port", 0),
            )
        return None

    def _check_sensitive_port_access(self, flow: dict) -> Optional[SignatureMatch]:
        dst_port = flow.get("dst_port", 0)
        if dst_port in SENSITIVE_PORTS:
            return SignatureMatch(
                rule_name="SENSITIVE_PORT_ACCESS",
                description=f"Access to sensitive service port {dst_port}",
                severity="MEDIUM",
                mitre_tactic="Initial Access",
                mitre_technique="T1190",
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                src_port=flow.get("src_port", 0),
                dst_port=dst_port,
            )
        return None
