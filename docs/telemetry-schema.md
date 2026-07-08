# Telemetry Event Schema

AgentProvenance correlates application context with runtime telemetry. These
fields must stay separated so eBPF/Falco/Tetragon/LoongCollector-style events
can be ingested without pretending the kernel knows agent-level identifiers.

## Event Layers

| Layer | Examples | Source |
| --- | --- | --- |
| Application context | `run_id`, `trajectory_id`, `execution_scope_id`, `substrate_scope_id`, `tool_call_id`, `process_id`, `artifact_state_id` | AgentProvenance control plane or white-box tool router |
| Runtime identity | `raw_event_id`, `container_id`, `cgroup_id`, `pid`, `tgid`, `ppid`, `timestamp` | Runtime or telemetry substrate |
| Raw payload | syscall arguments, path, destination address, argv, event-specific fields | Runtime or telemetry substrate |
| Correlation result | `correlation.method`, `correlation.confidence`, `correlation.binding_id` | AgentProvenance correlator |
| Launch/correlation provenance | `binding_source`, `self_launched`, `correlation_class` | AgentProvenance correlator / recorder |

## Raw Payload Rules

The `payload` passed to `agentprov telemetry ingest` or `telemetry.IngestFiltered`
must be a JSON object. This is enforced at ingest time.

The raw payload must not contain application context or correlation result
fields:

- `run_id`
- `trajectory_id`
- `execution_scope_id`
- `substrate_scope_id`
- `tool_call_id`
- `process_id`
- `artifact_state_id`
- `correlation`

Those fields belong to structured ingest parameters or to the correlator output.
This keeps zero-SDK and eBPF-style events honest: raw runtime telemetry can be
linked to an execution scope, but it is not required to carry a ToolCallID.

Storage compatibility note: older bundle schemas and SQLite tables still use
`rollout_id`, `attempt_id`, `session_id`, and `snapshot_id`. They map to
`trajectory_id`, `execution_scope_id`, `substrate_scope_id`, and
`artifact_state_id` at API and documentation boundaries; raw telemetry should
prefer the new terms.

`graph verify` also validates stored telemetry-source events after unwrapping
AgentProvenance correlation metadata. This catches malformed data loaded
directly into SQLite or produced by future receivers.

## Event Body Shapes

The current MVP validates these minimum event-specific fields:

| Event type | Required body |
| --- | --- |
| `execve` | `argv` as a non-empty string array, or `command` |
| `process_exit` | numeric `exit_code` |
| `file_open` / `file_write` / `secret_path` | safe relative `path` or `file` |
| `network_connect` / `metadata_ip` / `private_cidr` | `dst`, `dst_ip`, or `host` |
| `abnormal_process_tree` | numeric `pid` or `command` |
| `policy_verdict` | `decision` or `verdict` |
| `resource_pressure` | `resource` or `signal` |
| `setuid` / `setgid` | `uid` / `gid` (privilege change; setuid/setgid to `0` is the escalation case) |
| `ptrace` | `request`, `target_pid` (process injection / inspection) |
| `file_rename` / `file_unlink` | `path` (tamper / cleanup) |
| `dns_query` | `host` (resolved name; egress by name, not just IP) |
| `tls_write` / `tls_read` | privacy-safe `preview_sha256` + short `preview` + allow-listed `http` metadata (never the full body) |

Absolute paths, `..` paths, and `/workspace/../...`-style escapes are rejected
for file-oriented events. The privilege/tamper/DNS/TLS types carry the fields
above but are not subject to a strict required-body check.

`secret_path` now covers a sensitive-path **read**, not only a write: the native
sensor captures filtered read opens of credential/secret paths.

## Example

Valid raw runtime event:

```sh
agentprov telemetry ingest \
  --type execve \
  --source tetragon_jsonl \
  --container-id container-1 \
  --cgroup-id cgroup-1 \
  --pid 424242 \
  --ppid 424200 \
  --payload '{"argv":["sh","-lc","pytest -q"]}'
```

Invalid raw payload:

```json
{
  "tool_call_id": "tool-123",
  "argv": ["pytest", "-q"]
}
```

The correct form is to pass `--tool-call tool-123` as structured application
context when it is known, or omit it and let the correlator resolve the event
through cgroup/container/pid/time evidence.

## Correlation Semantics

Correlation is not a single boolean. AgentProvenance keeps launch provenance and
runtime correlation separate:

| Field | Meaning |
| --- | --- |
| `binding_source` | How the scope binding was created, e.g. `zero_sdk_record`, `ai_asserted`, or receiver-specific context |
| `self_launched` | AgentProvenance directly launched the process scope, so descendants are expected to belong to this run |
| `correlation_class` | `self_observed`, `context_asserted`, `kernel_correlated`, or `uncorrelated` |
| `correlation_method` | The concrete join used, such as `process_id`, `cgroup_time_window`, `container_time_window`, or `pid_time_window` |
| `correlation_confidence` | Numeric confidence for that join |

Current confidence tiers:

| Method | Confidence | Notes |
| --- | --- | --- |
| Direct process / self-observed wrapper evidence | `1.0` | Produced by AgentProvenance itself |
| Real cgroup + time window | `0.98` | Supervised Linux capture; strong subtree join |
| Container + time window | `0.92` | Common runtime/collector join |
| PID + time window | `0.85` | Useful fallback; weaker because of PID reuse and missed short-lived descendants |
| `ai_asserted` application context | `<=0.5` | App-supplied claim, intentionally lower trust |

In record-only mode, a synthetic scope id is sufficient because there is no
kernel telemetry to join. In supervised mode, `record` creates a real cgroup
scope and `sensor stream` observes syscalls from the host; the correlator joins
events back to the run by `cgroup_id` without requiring raw events to carry
agent identifiers.

## JSONL Receivers

The MVP can ingest already-filtered substrate JSONL:

```sh
agentprov telemetry ingest-jsonl --format tetragon --file tetragon-events.jsonl
agentprov telemetry ingest-jsonl --format falco --file falco-events.jsonl
agentprov telemetry ingest-jsonl --format loongcollector --file loong-events.jsonl
agentprov telemetry ingest-jsonl --format auto --file mixed-events.jsonl --json
agentprov telemetry ingest-falco --file falco-events.jsonl --json
falco -o json_output=true -o json_include_output_property=true | agentprov telemetry ingest-falco --file -
agentprov telemetry batches --run <run_id>
agentprov telemetry batches --run <run_id> --json
agentprov telemetry correlations --run <run_id> --json
agentprov telemetry correlations --event <event_id> --json
./scripts/demo_telemetry_jsonl.sh
```

Runnable fixtures live in `examples/telemetry/`.

`telemetry ingest-jsonl --json` returns both batch-level and row-level receiver
evidence. `receiver_summary` aggregates detected formats, normalized event
types, identity keys, resolved/unresolved rows, skipped rows, and failed rows.
`row_results` records the line number, detected format, normalized event type,
source, raw event id, identity keys, correlation method, and any skip/failure
reason. This keeps receiver behavior auditable without requiring raw telemetry
payloads to contain application context such as `tool_call_id`.

By default, `telemetry ingest-jsonl` also runs runtime-policy evaluation for
ingested events. Risky substrate rows such as metadata IP access, private CIDR
access, and secret-path reads create `policy_decisions`, `risk_signals`,
`response_actions`, graph edges, and timeline rows. The ingest result includes
`policy_decisions` and `policy_decision_ids`; pass `--no-policy` to run a pure
normalization-only receiver path.

`telemetry correlations --json` explains the second half of the path: why a
normalized runtime event was attached to a ToolCallScope. The report includes
the raw runtime identity, resolved application context, matched binding,
matched identity keys such as `pid`, `container_id`, `cgroup_id`, and `time`,
confidence, time window, and drill-down refs.

The receiver maps recognized substrate events into the normalized schema:

| Source | Input shape | Normalized event |
| --- | --- | --- |
| Native eBPF sensor (`agentprov_ebpf`) | own-sensor JSONL, auto-detected | `execve`, `network_connect`/`metadata_ip`/`private_cidr`, `file_write`, sensitive read → `secret_path` (else `file_open`), `process_exit`, `setuid`/`setgid`, `ptrace`, `file_rename`, `file_unlink`, `tls_write`/`tls_read`, `dns_query`, `resource_pressure` |
| Tetragon | `process_exec` | `execve` |
| Tetragon | `process_exit` | `process_exit` |
| Falco | `execve`, `execveat`, `spawned_process` | `execve` |
| Falco | `open`, `openat`, `openat2`, `creat` | `file_open`, `file_write`, or `secret_path` |
| Falco | `connect` | `network_connect`, `metadata_ip`, or `private_cidr` |
| LoongCollector | `execve`, `process_exit`, `file_open`, `file_write`, `network_connect` | matching normalized family |

The native sensor (`internal/sensor`, `cmd/agentprov-sensor`; Linux, arm64)
emits this normalized schema directly, so own-kernel telemetry drives the same
correlation → policy → risk path as Falco/Tetragon. It also adds a DAG `llm_call`
edge (TLS request ↔ response) and an `llm_intent_caused` edge (TLS response →
the syscalls it caused).

For local supervised capture, the CLI also exposes:

```sh
agentprov --data-dir <dir> sensor stream
```

This runs the native sensor as a per-node supervisor, ingests its normalized
events into the local store, applies policy/risk evaluation by default, and uses
the same cgroup/container/pid/time correlation path as JSONL receivers. It is
the product path used by the committed `run-snake-supervised` demo bundle.

Unrecognized rows are skipped. Malformed rows or rows that fail schema
validation are counted as failed and reported in the ingest result.

`telemetry ingest-falco` is the dedicated Falco-compatible path. It accepts a
Falco JSON/stdout file or stdin stream, maps process/file/network rows, then
runs runtime-policy evaluation by default. Metadata IP, private CIDR, and
secret-path Falco rows therefore create normalized runtime events plus
`policy_decisions`, `risk_signals`, `response_actions`, graph edges, and
timeline rows. Use `--no-policy` when the receiver should only normalize and
store telemetry.

`graph explain --risk <policy_decision_id> --json` links the resulting risk
back to the normalized runtime event and forward to the recorded response
action, so the receiver path can be audited end to end.

Each JSONL ingest also writes a compact telemetry batch manifest:

- `batch_id`
- source `format`
- input `path`
- input `file_sha256`
- row counters: read / ingested / skipped / failed
- mapped `event_ids_json`
- `event_ids_sha256`

The batch manifest intentionally does not copy the raw telemetry stream into
SQLite. It gives the provenance graph a stable audit handle for the external
evidence source while keeping AgentProvenance out of the long-term log storage
business. `graph verify` checks that batch event IDs still exist for the run
and that the event ID hash has not drifted.

After `graph materialize --run <run_id>`, the batch is also written as a
`telemetry_batch` content-addressed object. Its parent hashes point to the
normalized runtime event objects generated from that input batch. `graph
explain --event <event_id> --json` includes matching `telemetry_batches`, so an
operator can move from a substrate event to the original receiver batch, input
file hash, mapped event IDs, and object refs.

`graph explain --event <event_id> --json` includes a `telemetry` section for
runtime events. It reports the receiver (`tetragon`, `falco`,
`loongcollector`, or local wrapper), source format, normalized event type,
identity keys used for correlation, schema validation status, and correlation
status. This is the main inspection surface for answering how a substrate event
became part of the provenance DAG.
