"""
Generates a realistic synthetic test PCAP file containing:
  - Normal HTTPS/HTTP/DNS traffic
  - Port scan simulation
  - SYN flood simulation
  - Connection to known malicious ports
  - DNS amplification-like pattern

Run: python scripts/generate_pcap.py
Output: data/pcap/test.pcap
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Ether
except ImportError:
    print("ERROR: scapy not installed. Run: pip install scapy")
    sys.exit(1)

packets = []
ts = 1700000000.0

def pkt(src, dst, sport, dport, proto="TCP", flags="S", size=60, icmp_type=None):
    """Build a single packet."""
    global ts
    ts += 0.001
    ip = IP(src=src, dst=dst)
    if proto == "TCP":
        l4 = TCP(sport=sport, dport=dport, flags=flags)
    elif proto == "UDP":
        l4 = UDP(sport=sport, dport=dport) / (b"\x00" * size)
    elif proto == "ICMP":
        l4 = ICMP(type=icmp_type or 8)
    else:
        l4 = TCP(sport=sport, dport=dport, flags=flags)
    p = ip / l4
    p.time = ts
    return p

# ── Normal traffic ─────────────────────────────────────────────────────────
print("Generating normal traffic...")
for i in range(100):
    packets.append(pkt("192.168.1.10", "8.8.8.8",     50000+i, 443,  "TCP", "S"))
    packets.append(pkt("8.8.8.8",      "192.168.1.10", 443,   50000+i, "TCP", "SA"))
    packets.append(pkt("192.168.1.10", "8.8.8.8",     50000+i, 443,  "TCP", "A"))

# ── DNS queries ────────────────────────────────────────────────────────────
for i in range(20):
    packets.append(pkt("192.168.1.10", "8.8.8.8", 54000+i, 53, "UDP", size=40))
    packets.append(pkt("8.8.8.8", "192.168.1.10", 53, 54000+i, "UDP", size=400))

# ── Port scan (triggers PORT_SCAN rule) ────────────────────────────────────
print("Generating port scan...")
for port in range(1, 120):
    packets.append(pkt("10.0.0.99", "192.168.1.1", 60000, port, "TCP", "S"))

# ── SYN flood (triggers SYN_FLOOD rule) ───────────────────────────────────
print("Generating SYN flood...")
for i in range(150):
    packets.append(pkt(f"172.16.{i%10}.{i%255}", "192.168.1.100", 60000+i, 80, "TCP", "S"))

# ── Known malicious port (triggers KNOWN_MALICIOUS_PORT) ──────────────────
print("Generating C2 traffic...")
for i in range(5):
    packets.append(pkt("10.0.0.55", "192.168.1.50", 60000+i, 4444, "TCP", "S"))

# ── DNS amplification (triggers DNS_AMPLIFICATION) ────────────────────────
for i in range(10):
    packets.append(pkt("1.2.3.4", "192.168.1.200", 53, 50000+i, "UDP", size=50))
    for _ in range(20):
        packets.append(pkt("192.168.1.200", "1.2.3.4", 50000+i, 53, "UDP", size=4096))

# ── ICMP sweep ─────────────────────────────────────────────────────────────
for i in range(50):
    packets.append(pkt("10.0.0.88", f"192.168.1.{i+1}", 0, 0, "ICMP"))

os.makedirs("data/pcap", exist_ok=True)
wrpcap("data/pcap/test.pcap", packets)
print(f"\nGenerated {len(packets)} packets → data/pcap/test.pcap")
print("Attack patterns included:")
print("  - Port scan (ports 1-119)")
print("  - SYN flood (150 packets)")
print("  - C2 port 4444 access")
print("  - DNS amplification")
print("  - ICMP sweep")
