# Cloud-Based Network Packet Sniffer with Integrated Machine Learning and Firewall Security

A local-first, cloud-native **network monitoring and analyst review prototype**. Cloud-Native ML-IDS combines flow collection, a hybrid machine-learning detector, policy evaluation and a responsive security console. It is designed to run on a student laptop without paid cloud services.

> **Safety and scope:** The default setup does not generate traffic and records simulated block entries; it does not drop packets. The model is trained on artificial data and is not validated for production. Live capture requires permission, and actual firewall enforcement is a separate, explicitly enabled, on-path Linux component. Do not use this prototype as your only security control.

## What it does

- **Collects flow summaries** from a synthetic Sentinel, an authorized live IPv4 capture interface, or an uploaded PCAP. The dashboard keeps those sources distinguishable.
- **Applies two detection approaches:** a Random Forest for several synthetic known-pattern classes and an Isolation Forest for unusual flow characteristics. An anomaly is a signal for investigation, not proof of a zero-day attack.
- **Separates policy and attack decisions.** Narrow trusted office/VPN networks and protected internal services can be monitored or evaluated for denial; trusted traffic is still inspected by ML. IP addresses are not employee identities.
- **Supports analyst feedback.** Review anomaly candidates, approve source-scoped learned rules, train a candidate with feedback, inspect its evaluation, and activate or roll back the model.
- **Records response entries** with source and eligibility information. An optional IPv4 enforcer can apply eligible entries or supported access-policy rules only when it is deliberately enabled and positioned on the traffic path.
- **Provides a monitoring console** with source filters, event trends, alerts and CSV export, blocklist management, offline PCAP analysis, policy controls, and model health. Sidebar navigation smoothly scrolls the page to each section.

```text
 Synthetic / live Sentinel ──┐
                             ├──> Commander API ──> ML + policy ──> SQLite
 Offline PCAP upload ────────┘           │                           │
                                         ├──> Dashboard / CSV / WebSocket
                                         └──> simulated decisions
                                               │
                         optional, separately enabled on-path IPv4 enforcer
```

The dashboard is **SIEM-adjacent** (centralized events, filters, export) and **SOC-adjacent** (review and feedback), but is not a full SIEM or SOC platform. It does **not** perform vulnerability scanning, CVE matching, incident management, identity authentication, or comprehensive threat correlation.

## Quick start with Docker Compose

Prerequisites: Docker Engine/Desktop with Compose, and enough free RAM for a Python model and three small containers. A GPU is not required. The default is intended to be usable on an 8 GB laptop; actual resource use varies.

The clone command below checks out `main`. When testing a preview branch, clone that branch instead with `git clone --branch <branch-name> https://github.com/vlaxminarayana436/Cloud-Native-ML-IDS.git`.

For a smaller checkout that omits the retained legacy dependencies, add `--filter=blob:none --sparse` to the clone command, then run `git sparse-checkout set backend agent frontend docs k8s lab` from the cloned directory.

```bash
git clone https://github.com/vlaxminarayana436/Cloud-Native-ML-IDS.git
cd Cloud-Native-ML-IDS
cp .env.example .env                 # Windows PowerShell: Copy-Item .env.example .env
docker compose up --build
```

Open **http://127.0.0.1:3000**. The console starts without fabricated traffic; connect an authorized live Sentinel or upload a PCAP to add records. The API is available locally at **http://127.0.0.1:8000/docs**.

To generate labeled synthetic traffic intentionally, start the optional profile:

```bash
docker compose --profile synthetic up -d --build sentinel
```

Stop with `Ctrl+C` and `docker compose --profile synthetic down`. Named volumes retain events and models; adding `-v` removes those volumes and their data.

Compose binds published ports to localhost and grants the default services no capture or firewall capabilities. The optional lab and Kubernetes manifests are examples, not a production deployment; they have not been runtime-verified in this environment.

## Run without Docker

Use Python **3.11**, Node.js **20 or 22**, and npm. Open the repository in three terminals.

**Terminal 1 — Commander**

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS / Linux:      source .venv/bin/activate
python -m pip install -r backend/requirements.txt -r agent/requirements.txt
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — dashboard**

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open **http://127.0.0.1:5173**. The dev server proxies API and WebSocket requests to Commander; the browser does not need a separate backend URL.

**Terminal 3 — optional synthetic Sentinel**

```bash
# From the repository root; activate the same .venv first.
cd agent
python agent.py --mode synthetic
```

Stop each process with `Ctrl+C`. Native runs store the SQLite database in `backend/data/`. The `.env` file is read by Compose; for native runs, set environment variables in each relevant terminal. If `COMMANDER_API_KEY` is configured, set the same variable for Sentinel. The dashboard asks for the key only when a protected action needs it, then keeps it in the current tab session. The key protects mutations only; it is not a complete authentication solution.

## Using the console

1. Choose **Synthetic**, **Live capture**, **Offline PCAP**, or **All sources** from the source selector. These are reported labels, not cryptographically verified provenance.
2. Inspect the overview and alert feed. Counts refer to stored **flows**, not individual packets; the displayed model scores are uncalibrated and are not accuracy measurements. The dashboard CSV export contains the currently filtered rows among the latest 100 loaded alerts.
3. Upload a `.pcap`, `.pcapng`, or `.cap` under **PCAP analysis**. Supported IPv4 TCP/UDP flows are analyzed offline and never create live block entries. Limits: 25 MiB, 200,000 packets and 5,000 distinct flows.
4. Under **Access policy**, add authorized networks and protected services. A new installation starts with no configured scopes. Monitor mode records would-deny decisions. Deny mode records policy decisions; it does not itself install a firewall rule.
5. Review anomaly candidates under **Adaptive learning**. Approval creates a source-scoped rule and feedback example; candidate training and activation are separate actions. A candidate's augmented feedback can overlap its evaluation split, so its metrics can be optimistic.

### Understanding dashboard percentages

- **Alert categories** show the rounded share of each category among recorded ML and policy-only alerts for the selected source. Only the three largest categories are displayed, so their shares need not add up to 100%.
- **Alert and anomaly scores** come from the detector. The average model score covers recorded supervised/hybrid ML alerts in the selected source and can include scores from earlier model versions. Scores are uncalibrated indicators, not verified probabilities or measured detection accuracy.
- **Feature importances** describe the active model; held-out accuracy, weighted F1, and false-flag/attack-flag rates describe its evaluation dataset. They change when the model changes, not with each live flow. The bundled baseline uses synthetic data, not a real-world accuracy test.
- Counts, category shares, and recorded scores refresh on WebSocket notifications and approximately every five seconds. They describe received records, not necessarily all traffic. Live capture requires an authorized running sensor; PCAP is offline, and a selected synthetic source reports generated flows.

### Authorized live capture

Only capture networks and interfaces you are authorized to monitor. Live mode observes what the selected interface can see; it does not magically see an entire network. It aggregates directional IPv4 TCP/UDP flows into short windows and sends features, not packet payloads, to Commander.

- **Windows:** install Npcap, run the terminal with suitable capture permissions, and select the appropriate Scapy/Npcap interface.
- **Linux:** grant the required packet-capture permissions or run the Sentinel with appropriate privileges. Do not grant firewall privileges merely to capture.
- To list Scapy interfaces: `python -c "from scapy.all import show_interfaces; show_interfaces()"`.

```bash
# From agent/ with the virtual environment active; replace the interface name.
python agent.py --mode live --interface "YOUR_AUTHORIZED_INTERFACE"
```

Windows/macOS capture behavior depends on local drivers and permissions and was not independently verified here. The bounded in-memory capture and send queues can drop data under load or during network outages; warnings are logged. See [operations and safety](docs/operations.md) before enabling a live sensor or enforcer.

## Model evaluation and limitations

The committed baseline is trained on **20,000 synthetic examples**, with 6,000 held-out synthetic examples. The metrics below are generated by the training script and also available in `backend/models/model_metrics.json` and the console. They are **not real-world accuracy**.

| Measurement | Result | Scope |
|---|---:|---|
| Random Forest accuracy | 97.83% | Held-out synthetic examples |
| Weighted F1 | 97.83% | Held-out synthetic examples |
| Reference F1 | 97.20% | Separate synthetic seed, 2,500 examples |
| Isolation Forest normal false-flag rate | 1.08% | Held-out synthetic normal examples |
| Isolation Forest known-attack flag rate | 59.96% | Held-out synthetic attack examples; anomaly component only |

A small Linux loopback smoke test of two benign HTTP requests produced four captured flow windows. An earlier baseline marked all four as anomalies; after adding short-flow examples to the synthetic baseline, the current model classified all four as normal. This tiny, correlated test is **not** an estimate of real false-positive or false-negative rates. Independent, labeled, representative traffic is essential before making operational decisions.

A five-tuple flow summary cannot reliably establish credential abuse, a distributed scan, an application-layer attack, or a vulnerability. Encrypted content, traffic outside the sensor's view, non-IPv4 live traffic, evasion, packet loss, and changes in normal behavior can all limit detection. No detector can guarantee that every attack or unknown pattern will be detected.

Retrain the baseline explicitly if desired:

```bash
cd backend
python -m ml.train --rows 20000
```

Restart a native Commander process to load the regenerated artifact. A Compose model volume is separate and may retain an older artifact; back up any model before replacing it.

Only load model artifacts you trust: Joblib files can execute code during deserialization. The application does not upload external model files.

## Firewall and access-policy boundaries

- `SIMULATE_BLOCK` is the default Commander mode; `ALERT_ONLY` disables automatic block-entry creation. Neither mode writes firewall rules. Manual entries can still be recorded in either mode.
- A separate opt-in Linux enforcer uses iptables for eligible **IPv4** entries and supported policy rules. It needs `NET_ADMIN` and must be on the path of the traffic it is meant to affect. A recorded or simulated block is not proof of packet loss.
- Synthetic, offline and unspecified automatic detections are not eligible for the current enforcer. Manual entries and captured-source entries can be eligible; a source label can be spoofed by an untrusted client. Loopback, unspecified, multicast, link-local and reserved addresses are excluded, but **not every address belonging to the host** is protected.
- Trusted CIDRs must be IPv4 `/16` or IPv6 `/48` or narrower. Protected services and managed egress scopes must be private IPv4 `/24` or IPv6 `/64` or narrower. The optional enforcer supports only IPv4 and has additional limitations.
- Use identity-aware VPN and MFA for employee access. CIDRs describe network location, not who the user is. A trusted source can still trigger an ML alert or an eligible block.

Actual firewall changes and Kubernetes deployment were **not tested** in this environment. Read [operations and safety](docs/operations.md) for the opt-in lab, placement, cleanup, and security limitations.

## Repository layout

```text
backend/app/          Commander API, SQLite, policy, models and PCAP analysis
backend/ml/           Synthetic training pipeline
backend/models/       Committed baseline artifact and synthetic metrics
backend/tests/        Isolated API, policy, model and mocked enforcer tests
agent/                Synthetic/live Sentinel and optional Linux enforcer
frontend/             React console, Vite proxy, production web image
lab/                  Optional containerized capture lab and opt-in overlay
k8s/                  Illustrative single-replica Kubernetes manifests
docs/                 Architecture, operations and safety guidance
```

`backend-api/`, `frontend-dashboard/`, and `sniffer-agent/` are the original educational implementation, retained as **legacy** code. The root Compose file and the instructions above use the new `backend/`, `frontend/`, and `agent/` components. There is no automatic migration of databases from the legacy implementation. On startup, the new Commander removes only its two exact, previously seeded starter policy entries; user-created and modified entries and historical events remain. Review your policy scopes after upgrading.

## Development checks

```bash
# From the repository root with .venv activated
python -m pip install -r backend/requirements-dev.txt -r agent/requirements.txt
cd backend && python -m pytest -q

# In a separate terminal
cd frontend && npm ci && npm run build
```

For browser smoke tests, start Commander and the Vite dashboard against a **disposable database**, install a Playwright Chromium browser (`npx playwright install chromium`), then run `npm run test:browser` in `frontend/`. The test submits synthetic and unspecified-source flows. Setting `TEST_MUTATIONS=1` also uploads a small test PCAP and creates/removes a test policy entry. `TEST_LIFECYCLE=1` additionally trains, activates and rolls back a model: use a **disposable `MODEL_DIR` as well as a disposable database**. Never run these tests against an operational installation or an enabled enforcer.

## Next steps

Useful extensions include authenticated and encrypted API access, durable queues and retention controls, representative labeled evaluation, correlation and incident cases, and ingestion of reports from an authorized vulnerability scanner. These are proposed work, not existing capabilities. See [architecture and detection](docs/architecture.md) for design and trade-offs.

### Background reading

- [NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901146) — operational trade-offs, false positives and response practices.
- [Verizon 2025 Data Breach Investigations Report overview](https://www.verizon.com/about/news/2025-data-breach-investigations-report) — context on diverse breach and initial-access patterns.
- [A review of intrusion-detection approaches](https://www.mdpi.com/2073-431X/14/3/87) — background on signature and anomaly detection and their limitations.

These references motivate the design; they do not evaluate or endorse this prototype.
