"""
NIDS Packet Capture Module.
Supports two modes:
  - live: Capture from network interface using Scapy (requires root/NET_RAW)
  - pcap: Replay a PCAP file (safe for testing on Windows Docker)

On Windows Docker, live capture runs inside the Linux container via NET_RAW capability.
"""
import time
from typing import Callable, Optional
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PacketCapture:
    """
    Captures raw packets and passes them to a callback for flow building.
    Uses Scapy sniff() for both live capture and PCAP replay.
    """

    def __init__(self, callback: Callable, interface: Optional[str] = None,
                 pcap_file: Optional[str] = None, mode: str = None):
        self.callback = callback
        self.interface = interface or config.CAPTURE_INTERFACE
        self.pcap_file = pcap_file or config.PCAP_FILE
        self.mode = mode or config.CAPTURE_MODE
        self._running = False

    def start(self):
        """Start packet capture. Blocks until stop() is called."""
        self._running = True
        if self.mode == "live":
            self._capture_live()
        elif self.mode == "pcap":
            self._capture_pcap()
        else:
            raise ValueError(f"Unknown capture mode: {self.mode}")

    def stop(self):
        self._running = False
        logger.info("capture_stopped")

    def _capture_live(self):
        """Live packet capture from network interface."""
        try:
            from scapy.all import sniff
            logger.info("capture_started", mode="live", interface=self.interface)
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except ImportError:
            logger.error("scapy_not_available")
            raise
        except PermissionError:
            logger.error("capture_permission_denied",
                         hint="Run Docker with NET_RAW capability or as root")
            raise

    def _capture_pcap(self):
        """Replay packets from a PCAP file."""
        try:
            from scapy.all import rdpcap
            logger.info("capture_started", mode="pcap", file=self.pcap_file)
            packets = rdpcap(self.pcap_file)
            for pkt in packets:
                if not self._running:
                    break
                self._process_packet(pkt)
                time.sleep(0.0001)   # Simulate realistic timing
            logger.info("pcap_replay_complete", packet_count=len(packets))
        except FileNotFoundError:
            logger.error("pcap_file_not_found", path=self.pcap_file)
            raise

    def _process_packet(self, packet):
        """Extract basic fields and pass to callback."""
        try:
            pkt_data = self._parse_packet(packet)
            if pkt_data:
                self.callback(pkt_data)
        except Exception as e:
            logger.warning("packet_parse_error", error=str(e))

    @staticmethod
    def _parse_packet(packet) -> Optional[dict]:
        """Parse Scapy packet into a flat dictionary."""
        from scapy.all import IP, TCP, UDP, ICMP
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        pkt = {
            "timestamp": float(packet.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol": ip.proto,
            "length": len(packet),
            "ttl": ip.ttl,
            "src_port": 0,
            "dst_port": 0,
            "flags": "",
            "seq": 0,
            "ack": 0,
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            pkt["src_port"] = tcp.sport
            pkt["dst_port"] = tcp.dport
            pkt["flags"] = str(tcp.flags)
            pkt["seq"] = tcp.seq
            pkt["ack"] = tcp.ack
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            pkt["src_port"] = udp.sport
            pkt["dst_port"] = udp.dport
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            pkt["icmp_type"] = icmp.type
            pkt["icmp_code"] = icmp.code

        return pkt
