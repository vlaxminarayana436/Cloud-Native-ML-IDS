# Cloud-Based Network Packet Sniffer with Integrated ML and Firewall Security

This is a **small educational implementation** of the research-paper idea. It
keeps the main paper concepts but avoids production-level complexity:

- a Sentinel packet/flow agent;
- simple 5-tuple flow statistics;
- a Random Forest classifier;
- a FastAPI Commander backend;
- SQLite alert storage;
- a React dashboard;
- Docker Compose and a Kubernetes DaemonSet example.

The default mode uses simulated flows so that it is safe and easy to run on a
student laptop. Scapy live capture is available as an optional mode.

## Simple architecture

```text
Sentinel agent
(simulated or Scapy flow)
        |
        | HTTP POST flow data
        v
FastAPI Commander
(Random Forest + SQLite + optional iptables)
        |
        | HTTP GET alerts
        v
React dashboard
```

In Kubernetes, the Sentinel is represented by a DaemonSet, so one agent can run
on each node. To keep this educational version easy to follow, the Sentinel
extracts the flow summary and the Commander performs model prediction,
logging, and the optional firewall action. The paper describes the same stages
with more of the intelligence placed at the edge.

## Files to learn first

```text
backend-api/main.py                    Backend API and prediction
backend-api/train_model.py             Small model-training script
backend-api/random_forest_model.joblib Saved Random Forest model
sniffer-agent/sniffer.py               Flow generator and optional Scapy capture
frontend-dashboard/src/components/Dashboard.js  Alert screen
docker-compose.yml                     Local three-container setup
k8s/                                   Kubernetes examples
```

You do not need to understand every dependency or every Kubernetes setting to
explain the project.

## Run the project with Docker

### Requirements

- Docker Desktop or Docker Engine
- Docker Compose
- Ports `3000` and `8000` available

From the repository root:

```bash
docker compose up --build
```

Open the dashboard:

```text
http://localhost:3000
```

The Sentinel simulation sends one malicious-looking flow and one normal flow
every three seconds. View the logs with:

```bash
docker compose logs -f sniffer-agent
```

Useful API URLs:

```text
http://localhost:8000/health
http://localhost:8000/api/v1/alerts
http://localhost:8000/api/v1/summary
```

Stop the application with `Ctrl+C`, or run:

```bash
docker compose down
```

The default firewall mode is `ALERT_ONLY`, so the demo does not change your
computer's firewall.

## Run without Docker

Create and activate an environment:

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install backend and agent packages:

```bash
pip install -r backend-api/requirements.txt
pip install -r sniffer-agent/requirements.txt
```

### Terminal 1: backend

```bash
cd backend-api
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Terminal 2: Sentinel

From the repository root:

```bash
python sniffer-agent/sniffer.py
```

### Terminal 3: frontend, optional

```bash
cd frontend-dashboard
npm ci
```

Linux/macOS:

```bash
REACT_APP_API_URL=http://127.0.0.1:8000 npm start
```

Windows PowerShell:

```powershell
$env:REACT_APP_API_URL = "http://127.0.0.1:8000"
npm start
```

Then open `http://localhost:3000`.

## Retrain the model

The model uses eight understandable flow features:

```text
flow_duration
packet_count
byte_count
iat_mean
average_packet_size
syn_count
ack_count
syn_ack_ratio
```

Train the included demo model:

```bash
cd backend-api
python train_model.py
```

This performs:

1. synthetic normal/malicious flow generation;
2. a 70/30 train/test split;
3. MinMax scaling;
4. Random Forest training;
5. accuracy/precision/recall/F1 reporting;
6. model saving to `random_forest_model.joblib`.

A CSV with the same eight feature columns plus a `label` column can be used:

```bash
python train_model.py --data my_flows.csv
```

The default demo dataset is not the CIC-IDS-2017 dataset. Therefore, do not
claim the paper's 98.4% accuracy unless you reproduce the CIC-IDS-2017
experiment separately.

## How the code works

### 1. Sentinel creates or captures a flow

In simulation mode, `sniffer.py` creates simple examples:

```text
Malicious flow:
- many packets
- small packet size
- many SYN flags
- few ACK flags
- short inter-arrival time

Normal flow:
- fewer packets
- larger packets
- one SYN
- many ACKs
- longer inter-arrival time
```

In live mode, Scapy reads packets and groups them using the five-tuple:

```text
source IP, destination IP, source port, destination port, protocol
```

Start live mode only on a Linux system or test container that you control:

```bash
sudo -E SNIFFER_MODE=live INTERFACE=eth0 python sniffer-agent/sniffer.py
```

### 2. Sentinel sends flow information

The agent sends JSON to:

```text
POST /api/v1/flows/process
```

### 3. Backend creates the feature row

FastAPI converts the JSON into the same eight columns used during training.
Using the same feature order during training and prediction is important.

### 4. Random Forest predicts

The model returns a malicious probability. The decision threshold is `0.75`:

```text
probability >= 0.75  -> Malicious
probability <  0.75  -> Normal
```

### 5. Backend logs and responds

The backend stores the event in:

```text
data/security_events.db
```

If traffic is malicious, it can attempt an `iptables` DROP rule when
`FIREWALL_MODE=BLOCK_SOURCE_IP` is enabled. Keep `ALERT_ONLY` for normal demos.

### 6. Dashboard displays alerts

The React application polls:

```text
GET /api/v1/alerts
GET /api/v1/summary
```

and displays the recent malicious flows, confidence, protocol, and action.

## Kubernetes

The canonical manifests are in `k8s/`:

```text
k8s/backend-deployment.yaml
k8s/sniffer-daemonset.yaml
k8s/frontend-deployment.yaml
```

Build images using the repository's Dockerfiles, replace the placeholder image
names, and apply the files:

```bash
kubectl apply -f k8s/backend-deployment.yaml
kubectl apply -f k8s/sniffer-daemonset.yaml
kubectl apply -f k8s/frontend-deployment.yaml
```

The DaemonSet is the paper's cloud-native idea: one Sentinel pod per node.
`hostNetwork` and raw-network capabilities are required for live capture, so
use them only in a controlled cluster.

## What this project honestly demonstrates

This simplified version demonstrates the research architecture and workflow.
It is not a reproduction of the paper's full large-scale experiment. The
included model uses synthetic data for easy execution. CIC-IDS-2017 data,
traffic replay, 1,000-flow latency testing, shared production storage, and
secure cluster-wide firewall policy would be additional research work.
