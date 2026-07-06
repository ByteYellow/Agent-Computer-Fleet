# Graph Commands

The Git-like provenance surface over content-addressed evidence objects. The
README carries a short summary; this is the complete reference.

```sh
./agentprov graph trace --run run-demo-bugfix
./agentprov graph refs --run run-demo-bugfix
./agentprov graph log --run run-demo-bugfix
./agentprov graph materialize --run run-demo-bugfix
./agentprov graph objects --run run-demo-bugfix
./agentprov graph objects --run run-demo-bugfix --limit 50 --json
./agentprov graph objects --run run-demo-bugfix --limit 50 --cursor <next_cursor> --json
./agentprov graph verify --run run-demo-bugfix
./agentprov graph verify --run run-demo-bugfix --json
./agentprov graph replay --run run-demo-bugfix
./agentprov graph replay --run run-demo-bugfix --json
./agentprov graph trajectories --run run-demo-bugfix --json
./agentprov graph lens --run run-demo-bugfix --lens default --json
./agentprov graph lens --run run-demo-bugfix --lens data-flow-taint --overlay risk --json
./agentprov graph lens --run run-demo-bugfix --lens data-flow-taint --detail expanded --json
./agentprov graph lens --run run-demo-bugfix --lens process --detail raw --focus runtime_event/<event_id> --json
./agentprov graph lens --run run-demo-bugfix --lens process --focus runtime_event/<event_id> --json
./agentprov graph diff --run run-demo-bugfix --file calculator.py
./agentprov graph diff --run run-demo-bugfix --file calculator.py --json
./agentprov graph blame --run run-demo-bugfix --file calculator.py
./agentprov graph blame --run run-demo-bugfix --file calculator.py --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py
./agentprov graph explain --run run-demo-bugfix --file calculator.py --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --cursor <next_cursor> --json
./agentprov graph explain --tool-call <tool_call_id>
./agentprov graph explain --risk <policy_decision_id> --json
```

## Per-command purpose

| Command | Purpose |
|---|---|
| `trace` | Show execution context, runtime causality, provenance edges, risk, and response-gate evidence |
| `refs` | Emit stable Git-like references for attempts, snapshots, artifacts, and decisions |
| `log` | Show chronological execution history |
| `materialize` | Write content-addressed provenance objects |
| `materialize-llm` | Objectify captured LLM request/response bodies and build `llm_call` nodes with `llm_caused` edges for a run |
| `objects` | List content-addressed object refs, hashes, parent hashes, source IDs, paths, and sizes; supports `--limit` and `--cursor` |
| `verify` | Check graph integrity, risk/response evidence chains, taint/response barriers, object hashes, replay generation, drain watermarks, telemetry batch hashes, and orphan lifecycle evidence for outlived zero-SDK child processes |
| `replay` | Emit a plan-only reconstruction of the run |
| `trajectories --json` | Emit per-attempt behavior evidence, risk/deviation context, cost, artifacts, and runtime events for external evaluators or RL reward/penalty pipelines |
| `lens` | Project the canonical graph through a Graph Explorer lens. Emits `agentprovenance.graph_lens/v1` with canonical nodes/edges, derived edges, focus state, overlays, layout hints, raw event count, omitted counts, and `--detail summary\|expanded\|raw` |
| `diff` | Compare file state between base and attempts |
| `blame` | Attribute file state to attempt, tool call, process, strategy, command, and local candidate status |
| `explain` | Explain a target by combining trace, runtime causality, diff/blame, telemetry receiver details, telemetry batch manifests, process observations, policy, object refs, risk signals, baseline deviations, and response evidence; `--json` emits `agentprovenance.explain/v1` with `upstream`, `downstream`, bounded `causality_path`, `query`, `evidence`, `objects`, `risks`, `telemetry_batches`, `process_observations`, and `replay_refs`; runtime events include receiver/source format, normalized event type, identity keys, schema status, and correlation status; use `--depth`, `--limit`, and `--cursor` to bound and page DAG traversal |
