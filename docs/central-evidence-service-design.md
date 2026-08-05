# Central Evidence Service: design boundary

Status: architecture only. AgentProvenance does not implement this service in
the current project scope.

## Purpose

The local and per-node modes already prove the product's core contract:
execution context and runtime telemetry become the same verifiable evidence
graph. A future central service would preserve that contract across many nodes;
it would not become a scheduler, sandbox platform, or generic telemetry lake.

## Logical architecture

```text
node / microVM producer
  -> bounded local spool
  -> authenticated batch ingest
  -> durable ingest log
  -> correlation + evidence materialization workers
  -> content-addressed object storage
  -> graph/index store
  -> query / verify / replay / forensics API
```

The node producer remains responsible for sensor placement, substrate identity,
local filtering, queue bounds, drop accounting, and an honest capability report.
The central service owns durable receipt, cross-node indexing, retention policy,
and shared investigation APIs.

## Reused contracts

- Normalized telemetry and application-context schemas remain unchanged.
- `execution_context_bindings` remains the scope-attribution contract.
- Telemetry batches retain source hash, event IDs, counts, and producer identity.
- Content-addressed evidence objects and signed forensics bundles remain portable.
- Local `graph verify` semantics remain valid after central import.

## Proposed components

| Component | Responsibility | Must not own |
|---|---|---|
| Node producer | capture, filter, batch, spool, drop/coverage metrics | global scheduling or tenant policy |
| Ingest gateway | authenticate producer, validate schema/hash, return durable receipt | graph queries |
| Durable log | absorb bursts and preserve ordering per producer/scope | evidence interpretation |
| Materializer | correlation, graph edges, risk/signal derivation, objectification | raw sensor control |
| Object store | immutable bodies, manifests, bundles, replay objects | mutable graph indexes |
| Graph/index store | bounded lineage and investigation queries | raw blob retention |
| Query service | timeline, explain, diff/blame, verify, replay, export | workload execution |

## Producer identity and ordering

Every batch should carry:

- `producer_id`, `producer_profile`, and `node_id`;
- monotonic `producer_sequence` and capture time range;
- event count, byte count, source hash, and capability report;
- queue/drop counters at the time the batch was sealed;
- substrate identity such as cluster/node/pod/container, VM ID, or local host.

Ordering is guaranteed only within one producer sequence. Cross-node order is a
query-time approximation using capture timestamps and clock-quality metadata;
the service must not fabricate a total order when clocks disagree.

## Backpressure and failure behavior

- Producers use bounded batch count, batch bytes, and total spool bytes.
- The gateway acknowledges only after durable-log commit.
- Retries are idempotent by batch hash and producer sequence.
- Queue exhaustion follows the configured `reject` or `drop_oldest` policy.
- Every drop is observable as coverage evidence; silence is never reported as
  complete coverage.
- Query/materialization failure cannot block node-side capture until the local
  spool reaches its explicit bound.

## Security and trust boundary

- Transport authentication should be mTLS or a workload-identity equivalent.
- Authorization is scoped by producer, tenant, project, and run.
- Only hashes and explicitly selected evidence bodies cross a trust boundary.
- Off-host anchoring/signing is a separate provider interface; it is not implied
  by central storage.
- A central receipt proves durable acceptance, not that an untrusted producer
  captured every event.

## Capacity model

Capacity is expressed in events/s and bytes/s per producer, not only run count.
The minimum operational report contains:

- accepted, filtered, rejected, and dropped events/batches;
- spool depth in batches and bytes;
- ingest throughput and durable-ack latency;
- correlation coverage and sensor ring-buffer drops;
- query p50/p95/p99 and materialization lag;
- storage growth and retention deletions.

## Explicit non-goals

- no implementation of multi-tenancy, billing, or a fleet scheduler;
- no replacement for Kafka, object storage, Kubernetes, or a SIEM;
- no global exactly-once event semantics;
- no claim of total ordering across hosts;
- no central service in the current release target.

## Graduation criteria

Implementation should start only after per-node operation is proven with:

1. one sensor observing multiple independent workloads;
2. bounded queues and byte budgets under overload;
3. drop and coverage accounting that survives export/import;
4. a reproducible 100k-event ingest/query report;
5. semantic graph parity across local, Kubernetes, and microVM profiles.

