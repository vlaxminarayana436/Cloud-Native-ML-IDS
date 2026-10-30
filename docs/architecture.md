# Architecture and detection

## Components

| Component | Responsibility | Important boundaries |
|---|---|---|
| Sentinel | Produces synthetic features or aggregates authorized live IPv4 TCP/UDP packets into directional 5-tuple windows; sends heartbeats and flow records. | Raw capture is opt-in. A bounded in-memory queue can lose records; there is no durable spool. The source label is supplied by the client. |
| Commander | FastAPI validates flow inputs, evaluates policy, runs the active model and source-scoped learned rules, and stores events and response entries in SQLite. | It never writes kernel firewall rules. One SQLite writer and one API worker are appropriate for the example; this is not a distributed control plane. |
| Console | Reads source-filtered summaries and alerts; sends review, configuration and PCAP requests; refreshes on WebSocket notifications with polling fallback. | Read endpoints and WebSocket are not authenticated by the optional API key. The browser accesses Commander through a relative-path proxy. |
| Optional enforcer | Polls eligible active block entries and/or policy configuration; stages and swaps IPv4 iptables chains. | Off by default, Linux only, needs `NET_ADMIN` and on-path placement. No enforcement acknowledgement is sent to Commander. |

SQLite stores features, IP addresses, event timestamps, labels, policy decisions, feedback, rules and heartbeats. PCAP uploads are copied to a bounded temporary file and deleted after analysis, but derived events remain in the database. Protect access to these records and plan a retention policy; no automated retention or backup mechanism is included.

## Flow and policy decisions

Live flow windows are keyed by source/destination IP, source/destination port, and protocol. Counts, byte volume, duration, average packet size, inter-arrival time and TCP flags are transformed into rates and ratios. Short windows and a directional view can differ substantially from a real bidirectional session. They do not include payload inspection, TLS decryption, process identity or authentication events.

1. A narrow trusted source can be recognized by CIDR, but always goes through ML and learned-rule inspection.
2. An untrusted source matching an enabled protected service receives a separate access-policy decision. Optional managed egress applies to configured private source CIDRs. In monitor mode the policy records a would-deny; in enforce mode the API records a deny decision.
3. A policy-only denial is not labeled as an ML attack and does not create a global source block. A flow that is both suspicious and a policy violation remains an ML alert with its policy decision attached.
4. ML-detected live or synthetic threats may create expiring simulated entries unless Commander runs in `ALERT_ONLY`. Offline PCAPs never create block entries. Manual entries are non-expiring until removed.
5. The enforcer acts independently: it checks `active` and explicit `enforceable` on the current blocklist. It does not authenticate source labels and cannot prove that any packet has been dropped. Older or third-party enforcers might not honor those eligibility flags.

The policy API supports IPv6 CIDRs but the optional iptables enforcer is IPv4 only. Its egress exclusions are a fixed list of private/special ranges; Commander uses Python's `is_global` when evaluating egress, so decisions for uncommon special-purpose addresses can differ. Existing connections bypass the enforcer's access-policy chains via `ESTABLISHED,RELATED`; blocklist chains do not have that bypass. These are not comprehensive network-policy semantics.

## ML and feedback

The committed classifier is a Random Forest trained on generated examples for `Normal`, `DDoS_SYN_Flood`, `Port_Scan`, `Brute_Force`, and `UDP_Flood`. These labels describe the synthetic generator, not verified traffic classes. An Isolation Forest trained on synthetic normal examples provides a separate anomaly score. If supervised attack score crosses its threshold, the best known class is returned; otherwise a high anomaly score produces `Unknown_Anomaly`.

Scores are uncalibrated and can combine different signals; they are not probabilities of correctness. The baseline includes short synthetic normal windows because an earlier loopback smoke test over-flagged them. This adjustment does not establish real-world reliability. The synthetic attack flag rate of the anomaly model is not overall system recall, and detecting a previously unknown attack is not guaranteed.

Anomaly candidates are grouped by coarse feature buckets, separately per source. Approving a candidate creates a bounded, source-scoped heuristic rule and one labeled exemplar; rejecting it disables its rule and removes the feedback. Rejection does not suppress future ML anomaly alerts or simulated automatic blocks for similar flows. Matching a learned rule does not bypass ML. Feedback-based candidate training combines a synthetic baseline with jittered copies of approved examples. Since related copies can fall into both train and evaluation partitions, candidate held-out metrics can be optimistic. Review them and validate on a truly independent labeled set before activation. Activation keeps one previous artifact for rollback; a second activation replaces that rollback point.

The downloadable baseline is a Joblib artifact. Do not accept or deserialize untrusted artifacts. Stored metrics correspond to the active artifact; `model_metrics.json` records the originally committed baseline, not later activated models.

## Deployment and observability

Compose starts a single Commander and an Nginx-hosted dashboard; the synthetic Sentinel is opt-in. Kubernetes files are illustrative, use an ephemeral SQLite volume and a synthetic sensor scaled to zero by default, and are not a scale-out or high-availability design. Neither route provides production-ready authentication, TLS, authorization, durable ingestion, multi-node consistency, backup or disaster recovery.

The application offers event filtering, CSV export and analyst feedback, but no full SIEM ingestion pipeline, case management, threat intelligence enrichment or vulnerability scanner. Potential future work: integrate authorized scanner reports and CVE remediation workflows, add incident ownership/correlation, implement authenticated and encrypted transport for all endpoints and sensors, and evaluate on labeled traffic with site-specific false-positive and false-negative analysis.
