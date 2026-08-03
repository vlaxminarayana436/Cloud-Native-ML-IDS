"""Simple Sentinel packet/flow agent.

Simulation mode is the default for safe demonstrations.  Live mode uses Scapy
and keeps a small table of 5-tuple flows.
"""

import os
import random
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

import requests

try:
    from scapy.all import IP, TCP, UDP, sniff
except ImportError:
    IP = TCP = UDP = None
    sniff = None


BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000/api/v1/flows/process")
MODE = os.getenv("SNIFFER_MODE", "simulate").lower()
INTERFACE = os.getenv("INTERFACE", "eth0")
FLOW_TIMEOUT = float(os.getenv("FLOW_TIMEOUT", "2"))
AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())

FlowKey = Tuple[str, str, Optional[int], Optional[int], str]


@dataclass
class Flow:
    """Small object containing the statistics of one 5-tuple flow."""

    key: FlowKey
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    total_iat: float = 0.0
    syn_count: int = 0
    ack_count: int = 0

    def add_packet(self, timestamp: float, packet_length: int, flags: Set[str]):
        if self.packet_count > 0:
            self.total_iat += timestamp - self.last_seen
        self.last_seen = timestamp
        self.packet_count += 1
        self.byte_count += packet_length
        if "S" in flags:
            self.syn_count += 1
        if "A" in flags:
            self.ack_count += 1

    def as_json(self) -> Dict:
        source_ip, destination_ip, source_port, destination_port, protocol = self.key
        average_size = self.byte_count / self.packet_count if self.packet_count else 0
        iat_mean = self.total_iat / (self.packet_count - 1) if self.packet_count > 1 else 0
        ratio = self.syn_count / self.ack_count if self.ack_count else self.syn_count

        return {
            "timestamp": self.last_seen,
            "agent_id": AGENT_ID,
            "src_ip": source_ip,
            "dst_ip": destination_ip,
            "src_port": source_port,
            "dst_port": destination_port,
            "protocol": protocol,
            "flow_duration": max(0, self.last_seen - self.first_seen),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "iat_mean": iat_mean,
            "average_packet_size": average_size,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "syn_ack_ratio": ratio,
        }


def send_flow(flow_data: Dict):
    """Send one completed flow to the Commander."""

    try:
        response = requests.post(BACKEND_URL, json=flow_data, timeout=2)
        result = response.json()
        print(
            f"{result['classification']}: {flow_data['src_ip']} -> "
            f"{flow_data['dst_ip']} confidence={result['confidence']:.3f}"
        )
    except requests.RequestException as error:
        print(f"Backend unavailable: {error}")


def create_demo_flow(rng: random.Random, malicious: bool) -> Dict:
    """Create one easy-to-understand normal or malicious flow."""

    if malicious:
        source_ip = rng.choice(["10.10.10.10", "172.16.20.5", "192.168.2.99"])
        packet_count = rng.randint(70, 130)
        average_size = rng.randint(40, 100)
        syn_count = int(packet_count * 0.9)
        ack_count = rng.randint(0, 3)
        duration = rng.uniform(0.5, 10)
        iat_mean = rng.uniform(0.001, 0.04)
        destination_port = 2323
    else:
        source_ip = "10.0.0.25"
        packet_count = rng.randint(5, 25)
        average_size = rng.randint(300, 1200)
        syn_count = 1
        ack_count = max(1, int(packet_count * 0.8))
        duration = rng.uniform(2, 40)
        iat_mean = rng.uniform(0.1, 1.5)
        destination_port = 443

    return {
        "timestamp": time.time(),
        "src_ip": source_ip,
        "dst_ip": "192.168.1.50",
        "src_port": rng.randint(40000, 65000),
        "dst_port": destination_port,
        "protocol": "TCP",
        "flow_duration": duration,
        "packet_count": packet_count,
        "byte_count": packet_count * average_size,
        "iat_mean": iat_mean,
        "average_packet_size": average_size,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_ack_ratio": syn_count / ack_count if ack_count else syn_count,
        "agent_id": AGENT_ID,
    }


def run_simulation():
    print("Sentinel simulation mode started. Press Ctrl+C to stop.")
    print(f"Sending flows to {BACKEND_URL}")
    rng = random.Random(42)

    while True:
        send_flow(create_demo_flow(rng, malicious=True))
        send_flow(create_demo_flow(rng, malicious=False))
        time.sleep(3)


def packet_details(packet):
    """Return the 5-tuple, timestamp, size, and TCP flags for a Scapy packet."""

    if IP is None or IP not in packet:
        return None

    ip = packet[IP]
    protocol = "OTHER"
    source_port = None
    destination_port = None
    flags = set()

    if TCP is not None and TCP in packet:
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        flags = set(str(packet[TCP].flags))
    elif UDP is not None and UDP in packet:
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    key = (str(ip.src), str(ip.dst), source_port, destination_port, protocol)
    return key, float(getattr(packet, "time", time.time())), len(packet), flags


def run_live_capture():
    if sniff is None:
        raise RuntimeError("Install Scapy before using live mode")

    print(f"Live capture started on {INTERFACE}. Press Ctrl+C to stop.")
    flows: Dict[FlowKey, Flow] = {}

    def handle_packet(packet):
        details = packet_details(packet)
        if details is None:
            return

        key, timestamp, packet_length, flags = details
        if key not in flows:
            flows[key] = Flow(key, timestamp, timestamp)
        flows[key].add_packet(timestamp, packet_length, flags)

    try:
        while True:
            sniff(iface=INTERFACE, prn=handle_packet, store=False, timeout=1)
            now = time.time()
            expired_keys = [
                key for key, flow in flows.items()
                if now - flow.last_seen >= FLOW_TIMEOUT
            ]
            for key in expired_keys:
                send_flow(flows.pop(key).as_json())
    except KeyboardInterrupt:
        for flow in flows.values():
            send_flow(flow.as_json())


def main():
    if MODE == "live":
        run_live_capture()
    else:
        run_simulation()


if __name__ == "__main__":
    main()
