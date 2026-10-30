# Operations and safety

## Default behavior

- Root Compose starts without a Sentinel. The optional `synthetic` profile generates labeled synthetic traffic only when selected. `FIREWALL_MODE=SIMULATE_BLOCK` records temporary simulated entries; `ALERT_ONLY` stops automatic block-entry creation. Neither mode changes a firewall.
- The access policy starts in **monitor** mode with no trusted networks or protected services configured. Add authorized scopes before evaluating traffic. On startup, Commander removes only its two exact legacy starter entries; it preserves user-created and modified entries and past events. Review the policy after upgrading, especially if an enforcer is active. Policy `enforce` means the API records deny decisions; only a separately enabled on-path enforcer can install supported rules.
- `COMMANDER_API_KEY`, when set before starting Commander, is required for mutation requests. Supply the same key to Sentinel. The dashboard asks for it only when a protected action is rejected and keeps it in the current tab session; canceling does not perform the action. **Reads, CSV exports and WebSocket are still open**, even with a key. The API has no TLS, user authentication, authorization, or audit-grade identity. Keep it local or put every route and WebSocket behind an authenticated TLS proxy with appropriate access controls.
- The Compose `.env` file is consumed by Docker Compose; native Python processes need their environment variables set explicitly. `KNOWN_BLOCK_MINUTES` defaults to 60 and `UNKNOWN_BLOCK_MINUTES` to 30. Manual block entries do not expire automatically and can be enforced if an opt-in enforcer is running, including when Commander is in `ALERT_ONLY` mode.
- Counts, model scores and source selectors are based on recorded data. The source is a self-reported label, not an attested property; do not expose ingestion to untrusted clients. A current enforcer ignores automatic entries labeled synthetic or unknown, but a malicious client could claim `capture`. Offline uploads never create blocks.

## Live capture

Select a local interface you are explicitly authorized to inspect. Windows generally requires Npcap and suitable privileges; Linux needs raw packet capture capability. Test platform and driver behavior on the intended machine. The Sentinel aggregates only IPv4 TCP/UDP packets visible at its interface into unidirectional windows, with a default 5-second window/idle timeout. Loopback captures may duplicate packets. It attempts to exclude Commander traffic by resolving the API endpoint and comparing its address and port; unresolved or changing addresses can affect that exclusion.

At most 10,000 active flows and 2,000 queued windows are held in memory. Overflow, failed sends, or process exit can lose telemetry; the sender does not persist or retry a failed window. Watch Sentinel logs and independently measure coverage and drops for any real use. Time on agents and Commander should be synchronized. Offline uploads support up to 25 MiB, 200,000 packets and 5,000 distinct flows; only supported IPv4 TCP/UDP packets are aggregated.

## Isolated container lab (optional)

The following adds a harmless HTTP target, a probe, and a live Sentinel sharing the target's network namespace. No enforcer is enabled and no `NET_ADMIN` capability is granted by this lab file.

```bash
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml --profile lab up --build
# Stop and remove lab containers; named Commander volumes remain.
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml --profile lab down
```

The probe is attached to an internal Docker network and no target port is published. The target is **dual-homed** to the internal and default Compose networks so its Sentinel can reach Commander; it is not air-gapped. `LAB_CAPTURE_INTERFACE` defaults to `eth0`, but interface ordering is platform-dependent. Inspect the target's interfaces and choose the one carrying the probe traffic if necessary. The lab, interface selection and Compose networking have not been runtime-verified here.

### Enforcer opt-in for the lab only

**Do not enable automated blocking on a laptop or production network with this synthetic model.** The enforcer can interrupt connectivity, and the address guards do not exclude every address assigned to the host. Before any experiment, obtain authorization, back up rules, establish a recovery path, and verify the exact network namespace and scope. The enforcer is IPv4-only, has no enforcement acknowledgement, and cannot guarantee packet drops. This lab overlay and actual iptables enforcement were not tested in this environment.

To grant `NET_ADMIN` only to the lab Sentinel and explicitly select its blocklist enforcement, an authorized operator may add the overlay and environment variable:

```bash
LAB_ENFORCE_BLOCKLIST=true docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml -f lab/enforcer.yml --profile lab up --build
```

`LAB_ENFORCE_ACCESS_POLICY=true` separately selects supported access rules; policy must also be enabled and set to `enforce`. For PowerShell, set the environment variable with `$env:LAB_ENFORCE_BLOCKLIST = 'true'` before the Compose command. Use `down` with the same files when finished. The agent tries to remove its chains during graceful shutdown; crashes, forced kills, permission errors or chain conflicts can leave rules behind. Inspect and clean the **correct namespace** using your organization's approved procedure. Never run competing instances in the same namespace using the same chain names.

The lab target shares its network namespace with the Sentinel. This is an example of where a rule might apply, not proof that it protects another container or the host. For real infrastructure, the enforcer must be deliberately placed on-path with network ownership, a rollback plan, independent verification, and a validated policy. Established connections bypass the access-policy chain, and IP/CIDR is not authentication. See [architecture](architecture.md) for other differences between API decisions and iptables rules.

## Kubernetes example

The three manifests in `k8s/` use local image tags, one Commander replica and a synthetic Sentinel scaled to zero by default. They are illustrative and **not runtime-verified**. They do not capture host traffic or grant firewall capabilities. Build and load the images into your local cluster before applying them:

```bash
docker build -f backend/Dockerfile -t cloud-native-ml-ids/commander:local .
docker build -f frontend/Dockerfile -t cloud-native-ml-ids/dashboard:local .
docker build -f agent/Dockerfile -t cloud-native-ml-ids/sentinel:local .
# Load the images into kind/minikube/your cluster as appropriate.
kubectl apply -f k8s/
kubectl port-forward service/ids-dashboard 3000:80
```

To explicitly generate synthetic traffic in that cluster, scale the optional sensor with `kubectl scale deployment/sentinel-synthetic --replicas=1`. Its records remain labeled synthetic.

The SQLite `emptyDir` is deleted with the pod; the writable model directory is also ephemeral. Configure persistent storage, authenticated TLS ingress for **all** API and WebSocket traffic, network policies, resource sizing, secrets management, backups and monitoring before any broader deployment. SQLite and a single in-process model are not a horizontally scalable architecture.

## Data and models

Native data lives at `backend/data/security_events.db`; Compose uses named `ids_data` and `ids_models` volumes. Protect and back up both. A pre-existing named model volume retains its contents across image rebuilds, so it may not automatically receive a newly committed baseline. `docker compose down -v` is destructive: it deletes named data and model volumes. No automatic migration from the legacy project is provided.

The baseline and candidate Joblib artifacts must come from trusted sources. Candidate metrics use synthetic data plus augmented feedback; duplicated/related feedback can appear in both partitions and exaggerate performance. The UI's score averages are not ground-truth accuracy. Validate against independent labeled traffic, measure loss and both error types, and keep enforcement disabled until a qualified operator has accepted the residual risk.
