"""
TCP/UDP Flow Aggregation.
Aggregates individual packets into bidirectional flows using a (src_ip, dst_ip,
src_port, dst_port, protocol) 5-tuple key.
A flow is completed when:
  - A TCP FIN/RST is observed, or
  - The flow idle timeout (default 60s) is exceeded.
"""
import time
import threading
from collections import defaultdict
from typing import Callable, Dict, List
from src.utils.logger import get_logger

logger = get_logger(__name__)

FLOW_TIMEOUT = 60       # seconds — idle timeout
MAX_FLOW_PACKETS = 1000 # cap to prevent memory exhaustion


class Flow:
    """Represents a single bidirectional network flow."""

    def __init__(self, key: tuple, first_packet: dict):
        self.key = key                   # (src_ip, dst_ip, sport, dport, proto)
        self.start_time = first_packet["timestamp"]
        self.last_seen = first_packet["timestamp"]
        self.packets: List[dict] = [first_packet]
        self.fwd_packets = 1
        self.bwd_packets = 0
        self.fwd_bytes = first_packet["length"]
        self.bwd_bytes = 0
        self.flags_seen = set()
        self._add_flags(first_packet)

    def add_packet(self, pkt: dict, is_forward: bool):
        self.last_seen = pkt["timestamp"]
        self.packets.append(pkt)
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt["length"]
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt["length"]
        self._add_flags(pkt)

    def _add_flags(self, pkt: dict):
        if pkt.get("flags"):
            self.flags_seen.update(list(str(pkt["flags"])))

    @property
    def duration_ms(self) -> float:
        return max((self.last_seen - self.start_time) * 1000, 0.001)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    def is_complete(self) -> bool:
        """Flow is complete on FIN/RST or if max packets exceeded."""
        return (
            "F" in self.flags_seen or "R" in self.flags_seen
            or len(self.packets) >= MAX_FLOW_PACKETS
        )

    def to_dict(self) -> dict:
        key = self.key
        return {
            "src_ip":         key[0],
            "dst_ip":         key[1],
            "src_port":       key[2],
            "dst_port":       key[3],
            "protocol":       key[4],
            "start_time":     self.start_time,
            "duration_ms":    self.duration_ms,
            "fwd_packets":    self.fwd_packets,
            "bwd_packets":    self.bwd_packets,
            "total_packets":  self.total_packets,
            "fwd_bytes":      self.fwd_bytes,
            "bwd_bytes":      self.bwd_bytes,
            "total_bytes":    self.total_bytes,
            "flags":          "".join(sorted(self.flags_seen)),
            "has_syn":        "S" in self.flags_seen,
            "has_fin":        "F" in self.flags_seen,
            "has_rst":        "R" in self.flags_seen,
            "byte_rate":      self.total_bytes / (self.duration_ms / 1000 + 1e-9),
            "pkt_rate":       self.total_packets / (self.duration_ms / 1000 + 1e-9),
        }


class FlowBuilder:
    """
    Maintains an active flow table and emits completed flows to a callback.
    A background reaper thread purges idle/timed-out flows.
    """

    def __init__(self, on_flow_complete: Callable[[dict], None]):
        self.on_flow_complete = on_flow_complete
        self._flows: Dict[tuple, Flow] = {}
        self._lock = threading.Lock()
        self._start_reaper()

    def process_packet(self, pkt: dict):
        """Add packet to its flow. Emit if complete."""
        key_fwd = (pkt["src_ip"], pkt["dst_ip"],
                   pkt["src_port"], pkt["dst_port"], pkt["protocol"])
        key_rev = (pkt["dst_ip"], pkt["src_ip"],
                   pkt["dst_port"], pkt["src_port"], pkt["protocol"])

        with self._lock:
            if key_fwd in self._flows:
                flow = self._flows[key_fwd]
                flow.add_packet(pkt, is_forward=True)
                key = key_fwd
            elif key_rev in self._flows:
                flow = self._flows[key_rev]
                flow.add_packet(pkt, is_forward=False)
                key = key_rev
            else:
                flow = Flow(key_fwd, pkt)
                self._flows[key_fwd] = flow
                key = key_fwd

            if flow.is_complete():
                self._emit_flow(key)

    def _emit_flow(self, key: tuple):
        """Emit completed flow and remove from table. Must hold _lock."""
        flow = self._flows.pop(key, None)
        if flow:
            self.on_flow_complete(flow.to_dict())

    def _start_reaper(self):
        """Background thread to evict timed-out flows."""
        def reap():
            while True:
                time.sleep(FLOW_TIMEOUT // 2)
                now = time.time()
                with self._lock:
                    expired = [
                        k for k, f in self._flows.items()
                        if now - f.last_seen > FLOW_TIMEOUT
                    ]
                    for k in expired:
                        self._emit_flow(k)
                if expired:
                    logger.info("flows_reaped", count=len(expired))

        t = threading.Thread(target=reap, daemon=True)
        t.start()
