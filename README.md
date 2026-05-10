# Cloud-Native ML-IDS: Behavioral Packet Sniffing & Firewall Security

**Research Paper accepted at ESCI IEEE 2026**.

[cite_start]This project implements a distributed, lightweight Intrusion Detection System (IDS) specifically optimized for Kubernetes environments. [cite_start]By integrating real-time packet sniffing with a Random Forest classification engine, the system identifies zero-day threats through behavioral analysis.

## 🏗️ Architecture & Directory Structure
[cite_start]The system is designed as a distributed sensor network feeding a centralized analysis backend.

* [cite_start]**sniffer-agent/**: The "Sentinel" Python/Scapy agent (DaemonSet).
* [cite_start]**backend-api/**: The "Commander" FastAPI asynchronous alert aggregator.
* [cite_start]**frontend-dashboard/**: React.js SPA for real-time threat visualization.
* [cite_start]**k8s/**: Kubernetes manifests (DaemonSets, Services).

## 🚀 Key Features
* [cite_start]**Node-Level Visibility**: Uses the DaemonSet pattern to ensure 100% coverage.
* [cite_start]**Intelligent Detection**: Extracts 5-tuple flow statistics to detect complex attacks.
* [cite_start]**Real-time Reaction**: Automatically triggers iptables rules when the malicious threshold (0.75) is exceeded.
* [cite_start]**High Efficiency**: Theoretical O(1) space and inference complexity.

## 📊 Empirical Performance Results
| Metric | Result |
| :--- | :--- |
| Detection Accuracy | [cite_start]98.4%  |
| Precision / Recall | [cite_start]98.2% / 98.6%  |
| False Positive Rate | [cite_start]< 0.5%  |
| Detection Latency (TTD) | [cite_start]< 200ms  |

## ⚙️ Installation & Testing
```bash
docker-compose up --build
