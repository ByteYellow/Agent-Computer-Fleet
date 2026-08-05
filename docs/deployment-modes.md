# Deployment Modes

AgentProvenance should be adoptable without forcing every user into a platform
deployment. The product has three deployment shapes.

## 1. Library / CLI-only Recorder

This is the default entry point for RL, benchmark, evaluator, CI, and local
red-team harnesses.

Shape:

```text
agent / evaluator / batch job
  -> agentprov record -- <command>
  -> local SQLite + local content-addressed objects
  -> evidence manifest / EvalContext / trajectory signals
```

Expected properties:

- one Go binary;
- optional thin Python helper package, installable locally with
  `pip install -e .`;
- no long-running service required;
- no framework integration required;
- default capture stays lightweight: process, file diff, artifact, exit,
  resource, and summary runtime evidence;
- on Linux, optional supervised capture can pair `record` with a per-node
  `sensor stream`; the recorder creates a real cgroup scope and kernel events
  from the subtree correlate back by `cgroup_id`;
- every trajectory can have its own `run_id`;
- batch jobs can use `agentprov record batch --file jobs.jsonl --json` to get
  one `agentprovenance.record_batch/v1` manifest across many trajectories;
- `agentprov evidence batch-summary --shard/--job/--run` lets a pipeline query
  stored batch status without parsing stdout logs;
- `agentprov signal batch-context --batch/--shard/--runs` exports matching
  trajectories as EvalContext JSONL for reward, filtering, or benchmark
  consumers;
- Python users can define offline evaluator functions with `Registry` and
  `@rule`; those functions return `EvalSignal` records such as reward
  features, penalties, dataset labels, and quality signals;
- Python users can call `run_batch_pipeline(...)` to run the Deploy 1 offline
  loop in one step: record batch, export EvalContext records, evaluate Python
  rules, import EvalSignal reports, export batch forensics, and return a
  summary;
- `agentprov signal import-batch --file reports.jsonl` validates JSONL
  `EvalReport` batches after offline scoring, so RL pipelines do not need one
  import command per trajectory;
- `agentprov forensics export-batch --batch/--shard/--latest` writes one
  sha256-verified batch audit bundle with batch summary, per-run forensics
  refs, optional EvalContext records, and replay/query commands;
- outputs are JSON-friendly and batch-friendly.

Boundary:

- this mode does not provide shared query service, central retention, or
  multi-host telemetry aggregation;
- it is the easiest path for RL pipelines because the pipeline keeps ownership
  of scheduling, reward, ranking, and dataset policy.
- online security actions such as deny, kill, quarantine, or taint are not
  required for RL mode; they are opt-in controls for security deployments.
- if no sensor is enabled, synthetic scope ids plus process/file evidence are
  expected; this is not a degraded sensor path, it is the correct lightweight
  record-only path.

## 2. Sidecar / Local Daemon

This is the medium-complexity shape for sandbox workers, CI workers, local
security harnesses, or teams that need local ingest/query APIs.

Shape:

```text
agent / sandbox worker / CLI / SDK
  -> local agentprov daemon
  -> spool / backpressure / retention
  -> local query + graph verify + forensics API
```

Expected properties:

- daemon owns SQLite, object store, correlation, policy, risk, response, graph
  verification, forensics export, and telemetry spool;
- per-node native `sensor stream` can run beside the daemon or local store and
  feed normalized runtime events through the same ingest/correlation path;
- `accept_k8s_node_multiworkload.sh` is the environment gate for the actual
  sensor DaemonSet observing a configurable number of independent pod cgroups;
  it builds/imports the sensor image, deploys the DaemonSet, resolves
  pod/container metadata to kernel cgroups, ingests stdout JSONL, and verifies
  one evidence graph;
- `agentprov sandbox watch` is the node-local `client-go` informer companion:
  it List/Watches only Pods scheduled on its node, maintains exact
  container-to-cgroup bindings across restart/delete, and requires only Pod
  `get/list/watch` RBAC;
- CLI and Python helpers act as clients;
- raw telemetry can be queued and drained without blocking the control/query
  path;
- spool capacity is bounded independently by queued batch count, total queued
  bytes, and per-batch bytes;
- `telemetry producer-health` reports spool state, drops, source counts, and
  correlation coverage;
- local APIs expose observability, timeline, graph explain, security evidence,
  evidence manifest, forensics export, and signal import.

Boundary:

- this is still local-first;
- it is not a multi-tenant central service;
- it should be deployable beside a worker without requiring Kubernetes or a
  central database.
- the K8s gates prove one-node producer placement, passive attribution, and
  informer lifecycle handling. A full operator (CRDs, HA/leader election,
  upgrade control) and cluster-wide evidence service remain outside this
  mode's implemented boundary.

## 3. Central Evidence Service (design only)

This is the later enterprise shape for security, audit, SRE, compliance, and
incident review.

It is intentionally **not implemented** in the current project scope. The
component boundaries, failure model, capacity signals, and trust assumptions are
documented in [central-evidence-service-design.md](central-evidence-service-design.md).

Shape:

```text
many workers / sidecars / collectors
  -> central evidence ingest
  -> object storage + retention + auth
  -> query API + UI + audit export
```

Expected properties:

- shared ingest and query service;
- object storage for forensics and content-addressed evidence objects;
- retention, auth, tenant isolation, and audit controls;
- UI/API for investigation and evidence review;
- integration points for Falco/Tetragon/LoongCollector, webhook, Feishu,
  DingTalk, CI, and enterprise security workflows.

Boundary:

- this is not the default RL adoption path;
- it should reuse the same evidence schemas and graph invariants from the
  local modes;
- it requires explicit productization work rather than hidden assumptions in
  the local CLI.
- multi-tenancy, billing, and a complex cluster control plane are out of scope.

## Design Rule

The three modes share one evidence model:

```text
Execution Context
  -> Evidence Ingest
  -> Runtime Causality Graph
  -> Git-like Provenance DAG
  -> Evidence Query / Risk / Replay / Audit
```

Only the deployment boundary changes. RL users should be able to stay in
Library / CLI-only mode. Enterprise users can move to sidecar or central service
mode when they need shared operations.
