# Falco-compatible Receiver

Status: **maintained for compatibility, not a featured path.** The primary
kernel-evidence source is AgentProvenance's own eBPF sensor
(`agentprov sensor stream`). This receiver exists for environments where the
native sensor cannot run (non-arm64 hosts today, managed clusters where you
cannot load your own eBPF) or where Falco is already deployed and filtering
kernel/runtime events — its output can be folded into the same DAG,
correlation, policy, and risk path.

```sh
./agentprov telemetry bind --run run-falco-demo --substrate-scope substrate-falco-demo \
  --execution-scope exec-falco-demo --tool-call tool-falco-demo \
  --process process-falco-demo --container-id container-falco-demo --pid 4242 \
  --started-at 2026-01-01T00:00:00Z

./agentprov telemetry ingest-falco \
  --file examples/telemetry/falco-risk-events.jsonl --json

./agentprov telemetry list --run run-falco-demo
./agentprov telemetry list --run run-falco-demo --limit 100 --json
./agentprov telemetry list --run run-falco-demo --limit 100 --cursor <next_cursor> --json
./agentprov timeline --run run-falco-demo
./agentprov security risks --run run-falco-demo --json
./agentprov security responses --run run-falco-demo --json
```

For a live stream, pipe Falco JSON output directly:

```sh
sudo falco -o json_output=true -o json_include_output_property=true | \
  ./agentprov telemetry ingest-falco --file -
```

The receiver maps Falco process, file, and network rows into normalized runtime
events. Metadata IP, private CIDR, and secret-path rows are promoted into
security evidence: `RiskSignal`, `ResponseAction`, policy graph edges, and
timeline entries. `graph explain --risk <policy_decision_id> --json` links the
risk back to the raw runtime event and forward to the response action. Falco
remains the substrate collector; AgentProvenance owns correlation, causality,
provenance, and risk/audit linkage.

The main smoke path is telemetry correlation and graph explanation:

```sh
./scripts/demo_telemetry_jsonl.sh
```

It binds a ToolCallScope, ingests raw Falco/Tetragon/LoongCollector-style
runtime events that do not carry `tool_call_id`, normalizes them into the event
store, correlates them back to application context, and explains the resulting
causal graph.
