"""
src/utils/traffic_simulator.py
Generates synthetic network flows and syslog events for demo/testing.
"""
from __future__ import annotations
import json, os, random, time
from datetime import datetime
from pathlib import Path
from faker import Faker

fake = Faker()

QUEUE_FILE = "data/traffic_queue.jsonl"
HIDS_QUEUE_FILE = "data/hids_queue.jsonl"

ATTACK_SCENARIOS = {
    "PORT_SCAN": {
        "severity": "MEDIUM",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Discovery",
        "description": "Sequential port scan detected from single source",
    },
    "SSH_BRUTE_FORCE": {
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
        "description": "Multiple SSH authentication failures from single IP",
    },
    "SYN_FLOOD": {
        "severity": "HIGH",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498.001 - Network DoS: Direct Network Flood",
        "description": "SYN flood detected — abnormally high SYN rate",
    },
    "DATA_EXFILTRATION": {
        "severity": "CRITICAL",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1041 - Exfiltration Over C2 Channel",
        "description": "Unusually large outbound data transfer detected",
    },
    "LATERAL_MOVEMENT": {
        "severity": "HIGH",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.002 - Remote Services: SMB/Windows Admin Shares",
        "description": "Unusual internal east-west traffic pattern detected",
    },
    "SQL_INJECTION": {
        "severity": "CRITICAL",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "SQL injection payload detected in HTTP traffic",
    },
}


def _random_private_ip():
    prefixes = ["192.168", "10.0", "172.16"]
    p = random.choice(prefixes)
    return f"{p}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _random_external_ip():
    return f"{random.randint(1, 223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_benign_flow():
    common_ports = [80, 443, 8080, 53, 22, 25, 3306, 5432]
    protocols = ["TCP", "UDP", "ICMP"]
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "flow_type": "BENIGN",
        "src_ip": _random_private_ip(),
        "dst_ip": _random_external_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice(common_ports),
        "protocol": random.choice(protocols),
        "duration": round(random.uniform(0.01, 5.0), 4),
        "packet_count": random.randint(2, 50),
        "byte_count": random.randint(100, 50000),
        "flag_syn": random.randint(0, 1),
        "flag_fin": random.randint(0, 1),
        "flag_rst": 0,
        "flag_psh": random.randint(0, 1),
        "flag_ack": 1,
        "packets_per_second": round(random.uniform(1, 20), 2),
        "bytes_per_second": round(random.uniform(100, 10000), 2),
        "avg_packet_size": round(random.uniform(64, 1500), 2),
        "syn_ratio": round(random.uniform(0.0, 0.3), 4),
    }


def generate_attack_flow(attack_type: str):
    flow = generate_benign_flow()
    flow["flow_type"] = attack_type
    if attack_type == "PORT_SCAN":
        flow.update({"src_ip": _random_external_ip(), "dst_port": random.randint(1, 1024),
            "packet_count": random.randint(1, 3), "byte_count": random.randint(40, 120),
            "duration": round(random.uniform(0.001, 0.1), 4),
            "flag_syn": 1, "flag_fin": 0, "flag_ack": 0, "syn_ratio": 1.0,
            "packets_per_second": round(random.uniform(50, 500), 2)})
    elif attack_type == "SYN_FLOOD":
        flow.update({"src_ip": _random_external_ip(), "packet_count": random.randint(5000, 50000),
            "byte_count": random.randint(200000, 2000000),
            "flag_syn": random.randint(5000, 50000), "flag_ack": 0, "flag_fin": 0,
            "syn_ratio": round(random.uniform(0.9, 1.0), 4),
            "packets_per_second": round(random.uniform(1000, 10000), 2),
            "duration": round(random.uniform(0.001, 0.5), 4)})
    elif attack_type == "DATA_EXFILTRATION":
        flow.update({"dst_ip": _random_external_ip(), "dst_port": random.choice([443, 8443, 4444, 1234]),
            "byte_count": random.randint(10_000_000, 100_000_000),
            "duration": round(random.uniform(60, 300), 2),
            "bytes_per_second": round(random.uniform(100000, 1000000), 2)})
    elif attack_type == "LATERAL_MOVEMENT":
        flow.update({"src_ip": _random_private_ip(), "dst_ip": _random_private_ip(),
            "dst_port": random.choice([445, 139, 3389, 5985])})
    elif attack_type == "SQL_INJECTION":
        flow.update({"src_ip": _random_external_ip(), "dst_port": random.choice([80, 443, 8080]),
            "byte_count": random.randint(500, 5000), "packet_count": random.randint(5, 30)})
    return flow


def generate_hids_auth_event(attack=False):
    ip = _random_external_ip() if attack else _random_private_ip()
    if attack:
        return {"timestamp": datetime.utcnow().isoformat(), "event_type": "AUTH_FAIL",
            "user": random.choice(["root", "admin"]), "source_ip": ip, "service": "sshd",
            "details": f"Failed password for invalid user root from {ip} port 22 ssh2",
            "severity": "HIGH", "count": random.randint(5, 50)}
    return {"timestamp": datetime.utcnow().isoformat(), "event_type": "AUTH_SUCCESS",
        "user": "ubuntu", "source_ip": ip, "service": "sshd",
        "details": f"Accepted password for ubuntu from {ip}", "severity": "LOW", "count": 1}


def generate_hids_file_event():
    paths = ["/etc/passwd", "/etc/shadow", "/bin/bash", "/etc/crontab", "/etc/ssh/sshd_config"]
    return {"timestamp": datetime.utcnow().isoformat(), "event_type": "FILE_CHANGE",
        "path": random.choice(paths), "change_type": "MODIFIED", "severity": "HIGH",
        "details": "Unexpected modification to critical system file",
        "old_hash": fake.sha256(), "new_hash": fake.sha256()}


def run_simulator():
    Path("data").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    import logging
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("simulator")
    log.info("Traffic simulator started")
    attack_types = list(ATTACK_SCENARIOS.keys())
    tick = 0
    with open(QUEUE_FILE, "a") as net_q, open(HIDS_QUEUE_FILE, "a") as hids_q:
        while True:
            tick += 1
            for _ in range(random.randint(5, 15)):
                net_q.write(json.dumps(generate_benign_flow()) + "\n")
            net_q.flush()
            if tick % 30 == 0:
                at = random.choice(attack_types)
                n = 50 if at == "PORT_SCAN" else random.randint(1, 5)
                for _ in range(n):
                    net_q.write(json.dumps(generate_attack_flow(at)) + "\n")
                net_q.flush()
                log.info(f"[SIM] Injected: {at} ({n} flows)")
            if tick % 20 == 0:
                hids_q.write(json.dumps(generate_hids_auth_event(attack=True)) + "\n")
                hids_q.flush()
            if tick % 60 == 0:
                hids_q.write(json.dumps(generate_hids_file_event()) + "\n")
                hids_q.flush()
            if tick % 5 == 0:
                hids_q.write(json.dumps(generate_hids_auth_event(attack=False)) + "\n")
                hids_q.flush()
            time.sleep(1)


if __name__ == "__main__":
    run_simulator()
