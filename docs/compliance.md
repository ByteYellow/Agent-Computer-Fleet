# Compliance Evidence, Not Certification

AgentProvenance can map run evidence to security framework profiles such as
OWASP Agentic Security and NIST AI agent security assessment questions. The
README carries a short summary; this is the complete reference.

```sh
./agentprov compliance frameworks
./agentprov compliance frameworks --ruleset examples/compliance/custom-ruleset.yaml
./agentprov compliance validate --ruleset examples/compliance/custom-ruleset.yaml
./agentprov compliance map --framework owasp-asi --run <run_id>
./agentprov compliance map --framework owasp-asi --run <run_id> --only ASI05,ASI10,TRACE
./agentprov compliance explain --framework owasp-asi --run <run_id> --item ASI05
./agentprov compliance gaps --framework owasp-asi --run <run_id>
./agentprov compliance gaps --framework owasp-asi --run <run_id> --missing-only --json
./agentprov compliance map --framework enterprise-agent-review --ruleset examples/compliance/custom-ruleset.yaml --run <run_id>
./agentprov compliance report --framework nist-rfi-2026-00206 --run <run_id> --json
```

The output is an evidence-backed self-assessment. It does not certify
compliance, provide legal advice, or replace qualified third-party audit. Each
check item is derived from evidence already present in the run: timeline events,
runtime telemetry, ToolCallScope bindings, policy decisions, risk signals,
baseline deviations, response actions, forensics bundles, content-addressed
provenance objects, and graph edges.

Each item reports:

```text
covered | partial | missing | not_applicable
```

with concrete `evidence_refs`, a gap when evidence is incomplete, and a
recommended next step. This makes agent execution evidence usable for security
reviews without turning AgentProvenance into a GRC platform.
`compliance gaps` turns that same mapping into an actionable backlog of missing
or partial evidence items for a run.

## Custom rulesets

Custom rulesets can add local frameworks and rules without replacing built-ins.
The YAML model separates `rules`, `frameworks`, and `mappings`; mappings can
also select built-in items such as `ASI05`, `ASI10`, or `TRACE` and reuse them
inside an enterprise-specific review profile. JSON keeps `control_id` for
compatibility and also emits `item_id` for the current terminology.
