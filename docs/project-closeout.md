# AgentProvenance closeout criteria

This document defines the finish line for the portfolio project. It deliberately
stops before AgentProvenance becomes a virtualization platform or a centralized
SaaS product.

## Portable Producer Profiles

The KVM/microVM profile proves portability only:

- guest init starts the sensor automatically;
- VM identity, cgroup, and process identity map to an Execution Scope;
- teardown flushes and exports a signed bundle;
- the same workload produces semantically equivalent evidence graphs under
  local, Kubernetes, and KVM profiles;
- the dashboard reports substrate, VM ID, captured capabilities, and confidence.

KVM validation requires a separate Linux/KVM environment and is tracked
independently from the single-node scale work.

## Single-node scale boundary

AgentProvenance must prove:

- one node sensor observes multiple independent workloads;
- queued telemetry is bounded by batch count, total bytes, and per-batch bytes;
- ingest supports batches, durable spool, backpressure, and explicit
  `reject`/`drop_oldest` behavior;
- producer health reports accepted/processed/failed/dropped batches, queued
  bytes, sensor drops, event source counts, and correlation coverage;
- a 100k-event acceptance run emits a machine-readable report containing ingest
  throughput, health/query p50/p95/p99, daemon CPU/RSS peaks, queue state, drop
  state, final event count, and coverage;
- evidence queries remain bounded and graph verification remains consistent.

The pressure report is a measured baseline, not a production SLA. Different
hosts may produce different latency and throughput values.

Reference run on the macOS development host (2026-08-04, 100,000 synthetic
Falco events): all 100,000 events were ingested with zero failed/dropped batches;
health p95 was 1.209 ms, paged-query p95 was 9.182 ms, peak daemon RSS was about
55 MiB, and end-to-end spool drain throughput was 134.14 events/s. The query and
memory behavior meet this portfolio closeout target. The throughput is an honest
single-node SQLite baseline, not a production streaming claim.
The compact checked result is
[`benchmarks/telemetry-100k-macos-arm64.json`](benchmarks/telemetry-100k-macos-arm64.json).

The Kubernetes node gate was validated on 2026-08-05 on the arm64 Ubuntu 6.8
lab VM with single-node K3s. The gate built and deployed the real privileged
sensor DaemonSet, collected its stdout JSONL, resolved Kubernetes
pod/container identity to the cgroup ids present in that kernel stream, and
bound 8 independently scheduled BusyBox pods into one run. It observed 8
distinct cgroups, ingested 1,140 pod-scoped runtime events, and completed
`graph verify` with zero errors and zero warnings. This proves the per-node
producer shape; it is not a cluster-wide throughput benchmark. The generated
machine-readable report stays outside Git with the environment-gated artifacts.

The lightweight attribution controller was validated separately on the same
node against K3s 1.36.2. A filtered `client-go` informer established the first
container binding, observed a real container restart under the same Pod UID,
closed/replaced that binding, and closed the replacement after Pod deletion.
The final report contained 2 created and 2 closed bindings, 0 active bindings,
1 restart, and 0 retry/failure/resolution failure. This closes the node-local
lifecycle gap; it is not a claim of operator HA or multi-node shared state.

## Central service boundary

The central evidence service is architecture-only. See
[central-evidence-service-design.md](central-evidence-service-design.md).

The project does not implement:

- multi-tenancy or billing;
- a generic cluster control plane;
- a scheduler or sandbox lifecycle platform;
- distributed total ordering or exactly-once delivery;
- production object-store/index-store deployment.

## Acceptance commands

```sh
go test ./...
./scripts/accept_telemetry_spool_backpressure.sh
AGENTPROV_ACCEPT_100K_REPORT=/tmp/agentprov-100k.json \
  ./scripts/accept_telemetry_100k_pressure.sh

# Linux/Kubernetes environment gate; defaults to 8 workloads.
AGENTPROV=/path/to/agentprov SENSOR=/path/to/agentprov-sensor \
  AGENTPROV_MULTIWORKLOAD_REPORT=/tmp/agentprov-k8s-multiworkload.json \
  ./scripts/accept_k8s_node_multiworkload.sh

# Linux/Kubernetes informer lifecycle gate.
AGENTPROV=/path/to/agentprov \
  AGENTPROV_K8S_INFORMER_REPORT=/tmp/agentprov-k8s-informer.json \
  ./scripts/accept_k8s_informer_controller.sh
```

Kubernetes and KVM parity are environment-gated acceptance paths and must retain
their captured reports/bundles outside the Git repository.
