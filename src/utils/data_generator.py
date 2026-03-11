"""
data_generator.py
─────────────────
Generates synthetic network flows and syslog entries for testing.
Run: python -m src.utils.data_generator
Produces:
  data/sample/synthetic_flows.csv   — labelled network flows
  data/sample/synthetic_auth.log    — fake auth.log entries
  data/pcap/test_traffic.pcap       — basic PCAP for NIDS replay
"""

import csv
import json
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
from faker import Faker

fake = Faker()
random.seed(42)
np.random.seed(42)

ATTACK_LABELS = [
    "BENIGN", "DoS Hulk", "PortScan", "DDoS",
    "FTP-Patator", "SSH-Patator", "DoS slowloris",
    "Bot", "Infiltration", "Web Attack"
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = [22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443]


def _random_ip(private: bool = True) -> str:
    if private:
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    return fake.ipv4_public()


def _generate_benign_flow() -> dict:
    src_port = random.randint(49152, 65535)
    dst_port = random.choice(COMMON_PORTS)
    duration = random.uniform(0.1, 30.0)
    fwd_pkts = random.randint(5, 500)
    bwd_pkts = random.randint(3, 300)
    return {
        "src_ip": _random_ip(private=True),
        "dst_ip": _random_ip(private=False),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": random.choice(PROTOCOLS),
        "duration": round(duration, 6),
        "fwd_packets": fwd_pkts,
        "bwd_packets": bwd_pkts,
        "fwd_bytes": fwd_pkts * random.randint(50, 1400),
        "bwd_bytes": bwd_pkts * random.randint(50, 1400),
        "packet_rate": round(fwd_pkts / max(duration, 0.001), 4),
        "byte_rate": round((fwd_pkts * 700) / max(duration, 0.001), 4),
        "syn_count": random.randint(1, 3),
        "fin_count": random.randint(1, 2),
        "rst_count": random.randint(0, 1),
        "ack_count": random.randint(fwd_pkts // 2, fwd_pkts),
        "psh_count": random.randint(1, 10),
        "urg_count": 0,
        "avg_packet_size": random.uniform(200, 1200),
        "flow_iat_mean": round(random.uniform(0.001, 0.1), 6),
        "flow_iat_std": round(random.uniform(0.0, 0.05), 6),
        "label": "BENIGN",
    }


def _generate_attack_flow(attack_type: str) -> dict:
    flow = _generate_benign_flow()
    flow["label"] = attack_type

    if "PortScan" in attack_type:
        flow["dst_port"] = random.randint(1, 1024)
        flow["fwd_packets"] = random.randint(1, 3)
        flow["bwd_packets"] = 0
        flow["packet_rate"] = random.uniform(50, 500)
        flow["syn_count"] = flow["fwd_packets"]
        flow["rst_count"] = flow["fwd_packets"]

    elif "DoS" in attack_type or "DDoS" in attack_type:
        flow["packet_rate"] = random.uniform(1000, 10000)
        flow["fwd_packets"] = random.randint(5000, 50000)
        flow["byte_rate"] = random.uniform(500000, 5000000)
        flow["flow_iat_mean"] = round(random.uniform(0.00001, 0.0001), 8)

    elif "Patator" in attack_type or "Brute" in attack_type:
        flow["packet_rate"] = random.uniform(5, 50)
        flow["fwd_packets"] = random.randint(100, 1000)
        flow["avg_packet_size"] = random.uniform(50, 200)

    elif "Bot" in attack_type:
        flow["dst_ip"] = _random_ip(private=False)
        flow["dst_port"] = random.choice([6667, 8080, 443, 4444])
        flow["urg_count"] = random.randint(0, 5)

    return flow


def generate_synthetic_flows(n_samples: int = 5000, output_path: str = "data/sample/synthetic_flows.csv") -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    rows = []
    # 70% benign, 30% attacks
    n_benign = int(n_samples * 0.7)
    n_attack = n_samples - n_benign

    for _ in range(n_benign):
        rows.append(_generate_benign_flow())

    attack_types = ATTACK_LABELS[1:]  # exclude BENIGN
    for _ in range(n_attack):
        rows.append(_generate_attack_flow(random.choice(attack_types)))

    random.shuffle(rows)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Generated {n_samples} flow records → {output_path}")


def generate_synthetic_auth_log(n_lines: int = 1000, output_path: str = "data/sample/auth.log") -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    lines = []
    base_time = datetime.now() - timedelta(hours=6)

    for i in range(n_lines):
        ts = base_time + timedelta(seconds=i * 10)
        ts_str = ts.strftime("%b %d %H:%M:%S")
        host = fake.hostname()
        user = fake.user_name()
        ip = _random_ip(private=False)
        r = random.random()

        if r < 0.6:
            line = f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(49152,65535)} ssh2"
        elif r < 0.8:
            line = f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(49152,65535)} ssh2"
        elif r < 0.88:
            line = f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: Failed password for invalid user {user} from {ip} port {random.randint(49152,65535)} ssh2"
        elif r < 0.93:
            line = f"{ts_str} {host} sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
        elif r < 0.96:
            line = f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: Connection closed by {ip} port {random.randint(49152,65535)} [preauth]"
        else:
            # Brute-force burst
            for _ in range(10):
                bf_ts = (ts + timedelta(seconds=random.uniform(0, 5))).strftime("%b %d %H:%M:%S")
                lines.append(
                    f"{bf_ts} {host} sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for root from {ip} port {random.randint(49152,65535)} ssh2"
                )
            continue

        lines.append(line)

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(f"[OK] Generated {len(lines)} auth.log lines → {output_path}")


def generate_file_baseline(
    paths: list = None,
    output_path: str = "data/baselines/file_integrity.json"
) -> None:
    """Generate a fake baseline for testing without real system files."""
    if paths is None:
        paths = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "/usr/bin/python3", "/usr/bin/ssh",
        ]

    import hashlib
    baseline = {}
    for path in paths:
        # Fake hash — in real use, file_integrity.py reads actual files
        fake_hash = hashlib.sha256(
            (path + str(random.random())).encode()
        ).hexdigest()
        baseline[path] = {
            "sha256": fake_hash,
            "size": random.randint(1000, 500000),
            "modified": datetime.now().isoformat(),
        }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"[OK] File baseline → {output_path}")


if __name__ == "__main__":
    print("Generating synthetic test data...")
    generate_synthetic_flows(5000)
    generate_synthetic_auth_log(1000)
    generate_file_baseline()
    print("Done. All sample data written to data/sample/ and data/baselines/")
