# Security Evidence Commands

The full run-level security evidence surface. Every command has a stable
`--json` contract with result/page integrity hashes. The README carries a
short summary; this is the complete reference.

```sh
./agentprov observe summary --run <run_id>
./agentprov observe summary --run <run_id> --json
./agentprov observe coverage --run <run_id>
./agentprov observe coverage --run <run_id> --json
./agentprov observe scopes --run <run_id>
./agentprov observe scopes --run <run_id> --json
./agentprov observe event --run <run_id> --event <event_id>
./agentprov observe event --run <run_id> --event <event_id> --json
./agentprov observe process --run <run_id> --process <process_id>
./agentprov observe process --run <run_id> --process <process_id> --json
./agentprov observe flow --run <run_id>
./agentprov observe flow --run <run_id> --json
./agentprov evidence manifest --run <run_id>
./agentprov evidence manifest --run <run_id> --json
./agentprov evidence manifest --run <run_id> --materialize --json
./agentprov telemetry correlations --run <run_id>
./agentprov telemetry correlations --run <run_id> --json
./agentprov telemetry correlations --event <event_id> --json
./agentprov timeline --run <run_id>
./agentprov timeline --run <run_id> --view causality
./agentprov timeline --run <run_id> --limit 100 --cursor <next_cursor> --json
./agentprov timeline --run <run_id> --tool-call <tool_call_id> --json
./agentprov timeline --run <run_id> --process <process_id> --json
./agentprov timeline --run <run_id> --type risk_signal --json
./agentprov security risks --run <run_id>
./agentprov security risks --run <run_id> --json
./agentprov security deviations --run <run_id>
./agentprov security deviations --run <run_id> --json
./agentprov security responses --run <run_id>
./agentprov security responses --run <run_id> --json
./agentprov baseline learn --template <template_name> --run <run_id>
./agentprov baseline check --template <template_name> --run <run_id>
./agentprov signal context --run <run_id>
./agentprov signal batch-context --batch <batch_id>
./agentprov signal batch-context --shard <shard_id>
./agentprov signal batch-context --runs runs.jsonl
./agentprov signal run --run <run_id>
./agentprov signal run --run <run_id> --json
./agentprov signal run --run <run_id> \
  --external "PYTHONPATH=python python3 examples/evaluators/python_signal_eval.py" --json
./agentprov signal import --run <run_id> --file external-signals.json --json
./agentprov signal import-batch --file signal-reports.jsonl --engine python-sdk --json
./agentprov compliance frameworks
./agentprov compliance map --framework owasp-asi --run <run_id>
./agentprov compliance explain --framework owasp-asi --run <run_id> --item ASI05
./agentprov compliance gaps --framework owasp-asi --run <run_id>
./agentprov compliance report --framework nist-rfi-2026-00206 --run <run_id>
./agentprov ai tools --provider openai
./agentprov ai tools --provider anthropic
./agentprov ai call evaluate_action --input '{"event_type":"network_connect","dst_ip":"169.254.169.254"}'
./agentprov policy test examples/events/metadata-egress.jsonl
./agentprov policy decisions --run <run_id>
./agentprov forensics export <run_id>
./agentprov forensics export-batch --batch <batch_id>
./agentprov forensics export-batch --latest --include-eval-contexts --json
```

## Per-command purpose

| Command | Purpose |
|---|---|
| `observe summary` | Show run-level observability coverage across application context, runtime telemetry, risks, baselines, responses, and evidence refs |
| `observe coverage` | Show runtime telemetry correlation quality and list events missing session/tool_call/process identity |
| `observe scopes` | Show per-tool-call observability: processes, runtime events, risks, policy decisions, responses, and drill-down links |
| `observe event` | Explain one runtime event with correlated agent context, related risk/policy/response evidence, and drill-down links |
| `observe process` | Explain one process with its tool_call context, runtime events, risk/policy/response evidence, and drill-down links |
| `observe flow` | Show the compact causality flow from runtime events to risk signals, policy decisions, and response actions |
| `evidence manifest` | Emit a run-level evidence index that binds observability summary, timeline hash, content-addressed object refs, risk/response report hashes, and recommended drill-down queries; `--materialize` writes it as an `evidence_manifest` provenance object |
| `telemetry correlations` | Explain why runtime telemetry events were attached to a ToolCallScope, including raw identity, matched binding, matched keys, confidence, time window, and drill-down refs |
| `timeline` | Show a time-ordered execution view across application context, runtime telemetry, evidence, risk, baseline, response, and external effects |
| `security risks` | List normalized `RiskSignal` records derived from policy/runtime evidence; `--json` emits schema/hash metadata and drill-down refs to event/process/timeline/explain views |
| `security deviations` | List `BaselineDeviation` records from behavior feature checks; `--json` emits schema/hash metadata and drill-down refs to timeline and summary views |
| `security responses` | List recorded `ResponseAction` records such as audit, deny, kill, quarantine, taint, export, or notification hooks; `--json` emits schema/hash metadata and drill-down refs back to risk/process/explain views |
| `baseline learn/check` | Learn process/file/network/risk/runtime feature vectors and emit deviation records plus baseline-derived risk signals |
| `signal context/batch-context/run/import/import-batch` | Export one `EvalContext` or JSONL `EvalContext` streams for a batch/shard/run list, run built-in or external evaluators, and validate imported `EvalSignal` records or JSONL `EvalReport` batches for reward shaping, dataset filtering, quality scoring, or external benchmark consumers. AgentProvenance owns the evidence protocol, not the reward policy |
| `compliance frameworks/map/explain/gaps/report` | Map run evidence to OWASP Agentic Security and NIST AI agent security assessment profiles as item-level self-assessment evidence and gap lists |
| `ai tools/call` | Expose the read-only evidence query surface and inline policy pre-flight gate as provider tool schemas plus a local dispatcher. This is not an LLM gateway: models can query evidence and ask for a trusted policy verdict, but they cannot fabricate runtime telemetry, signatures, or provenance objects |
| `policy test/decisions` | Evaluate events, persist policy decisions, and feed the risk/response graph |
| `forensics export` | Export auditable evidence for a run; `--json` emits `agentprovenance.forensics_export/v1` with bundle path, sha256, size, and status |
| `forensics export-batch` | Export a batch-level audit bundle for record batches; `--json` emits `agentprovenance.batch_forensics_export/v1` with batch summary, per-run forensics refs, optional EvalContext records, result/page hashes, and a sha256-verified bundle path |
