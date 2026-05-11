# Cloud-Native ML-IDS: Behavioral Packet Sniffing & Firewall Security

**Research Paper accepted at ESCI IEEE 2026**.

This project implements a distributed, lightweight Intrusion Detection System (IDS) optimized for Kubernetes environments. It uses a **Random Forest** engine to identify threats based on behavioral anomalies.

## -> Architecture
* **sniffer-agent/**: The "Sentinel" Python/Scapy agent (DaemonSet).
* **backend-api/**: The "Commander" FastAPI asynchronous alert aggregator.
* **frontend-dashboard/**: React.js SPA for real-time threat visualization.
* **k8s/**: Kubernetes manifests (DaemonSets, Services).

## -> Performance Metrics
| Metric | Result |
| :--- | :--- |
| **Detection Accuracy** | 98.4% |
| **Precision / Recall** | 98.2% / 98.6% |
| **Detection Latency (TTD)** | < 200ms at 1,000 flows |

## -> Key Features
* **Node-Level Visibility**: Uses the DaemonSet pattern for 100% coverage.
* **Intelligent Detection**: Extracts 5-tuple flow statistics (IAT, SYN/ACK ratios).
* **Real-time Reaction**: Automatically triggers `iptables` to block malicious IPs.

## ⚙️ Installation
```bash
docker-compose up --build
