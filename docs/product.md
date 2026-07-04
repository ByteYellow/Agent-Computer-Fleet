# AgentProvenance Product Direction

AgentProvenance is a security-oriented execution observability and Git-like
provenance control plane for sandboxed agent execution.

It correlates application-side agent context with system-side telemetry, then
records how an agent execution context produces state changes, runtime events,
artifacts, risk signals, response decisions, and audit evidence. The project is
not a generic sandbox runtime, generic telemetry collector, generic
observability dashboard, Kubernetes/Ray replacement, or RL trainer.

The core product line is:

```text
Execution Context
  -> Evidence Ingest
  -> Execution Timeline
  -> Runtime Causality Graph
  -> Provenance DAG
  -> State Diff / Blame / Artifact Lineage
  -> Security Analysis / Risk Decision
  -> Taint / Response Action
  -> Replay / Forensics / Audit Manifest
```

## Positioning

AgentProvenance is built for autonomous tool-using agents, especially coding
agents. RL-style rollout and evaluator pipelines are important stress cases, but
they are not the only product target.

Primary scenarios:

- Coding-agent repair, refactor, test, and patch generation.
- Autonomous agent workflows with long chains of tool calls and subprocesses.
- Security analysis of sandboxed agent executions where application context,
  system telemetry, state changes, artifacts, risk, and replay matter.
- Risk discovery and risk judgment for agent behaviors that cross process,
  file, network, and sandbox boundaries.
- Automated response prototypes: audit, deny, kill, quarantine, taint snapshot,
  export forensics, and notify operators through Feishu/DingTalk-style apps.
- Behavior baseline and deviation analysis for repeated agent/task profiles.

Stress scenarios:

- Branch/fanout stress scenarios that exercise diff, blame, taint, and
  response-gate behavior.
- Evaluator or RL pipelines that need trajectory evidence, expectation
  deviation signals, and risk context for reward/penalty shaping.
- High-concurrency sandbox execution where raw traces are not enough.

AgentProvenance does not choose the winner or define the reward function for an
RL pipeline. It emits structured trajectory evidence, behavior deviations,
runtime/security signals, and provenance context so the external evaluator,
trainer, or harness can assign reward, penalty, filtering, or review decisions.

## Two Context Modes

### White-box mode

The agent harness, SDK, tool router, or framework provides explicit context:

```text
run_id / session_id / attempt_id / tool_call_id / tool_name / args_hash
```

This mode gives the highest precision and is suitable for Agentix-style
harnesses, internal coding-agent systems, LangGraph-like execution engines, and
custom tool routers.

### Zero-SDK mode

The user runs:

```sh
agentprov record -- <agent command>
```

The recorder snapshots the working directory before execution, runs the command,
computes file changes after execution, objectifies changed files into
content-addressed artifacts, and records process/file evidence into the graph.
On Linux, when a per-node sensor is enabled, `record` can place the child process
into a real cgroup scope so kernel events from the whole subtree correlate back
to the run by `cgroup_id` instead of by best-effort PID polling.

AgentProvenance infers execution scope from runtime evidence:

```text
root process / process tree / cwd / timestamp / container_id / cgroup_id
  / file diff / artifact refs
```

Zero-SDK mode is broader than white-box tool-router integration, but it has two
precision tiers:

- **record-only:** synthetic scope id + process sampling + file diff. This is
  correct when no kernel sensor is running.
- **supervised capture:** per-node sensor + real cgroup-per-scope join. This
  gives high-fidelity subtree correlation without requiring agent framework
  changes.

Both tiers are useful because raw system-side telemetry cannot be expected to
carry application-level `tool_call_id`.

The long-term direction is SDK-optional, proxy-optional, and vendor-neutral:
white-box context where available, runtime inference where not.

## Product Boundary

AgentProvenance owns agent execution provenance and security evidence
correlation. It does not own generic infrastructure.

It may consume:

- Docker, OpenSandbox, gVisor, Firecracker, Kata, or other sandbox runtimes.
- Kubernetes, Ray, Batch, or cloud orchestrators.
- Falco, Tetragon, LoongCollector, eBPF, auditd, wrapper telemetry, or runtime
  event streams.
- LangSmith-style traces or internal agent harness events.
- system-side low-intrusion system-side observability output.

Its job is to convert those signals into a causality and provenance model:

```text
agent context + system telemetry + state diff + artifacts + risk
  -> queryable, replayable, auditable security evidence DAG
```

## Codebase Boundary

The repository layout follows the product boundary:

```text
core path:
  record / telemetry / correlation / provenance / evidence / security /
  baseline / forensics

substrate path:
  substrate/runtime / substrate/node / substrate/state / control /
  computerapi / ports

non-product paths:
  stressdemo/*       branch-heavy fanout scenarios for load and DAG tests
  experimental/*     resource, scheduler, node metadata, and warm-pool experiments
```

This separation is intentional. Substrate code can be replaced by Docker,
OpenSandbox, Kubernetes, Falco, Tetragon, system-side collectors, or future
native sensors. The core product remains the correlation, provenance, timeline,
risk, response, replay, and audit model above those facts.

## Deployment Modes

AgentProvenance should not require a central platform before it becomes useful.
The product has three deployment shapes:

| Mode | Shape | Primary users |
|---|---|---|
| Library / CLI-only recorder | one Go binary, optional Python helper, local SQLite/object store | RL rollout, evaluator jobs, benchmarks, CI, red-team harnesses |
| Sidecar / local daemon | local daemon owns store, spool, correlation, graph query, risk, and forensics API | sandbox workers, CI workers, local security harnesses |
| Central evidence service | shared ingest/query service, object storage, retention, auth, UI/API | enterprise security, audit, SRE, compliance, incident review |

For RL and evaluator pipelines, the first mode is the most important adoption
path. AgentProvenance should let a pipeline wrap an existing command, emit a
record or batch manifest and `EvalContext`, and leave reward/ranking/dataset
decisions to the pipeline. Heavy telemetry, daemon mode, and central services
are opt-in hardening paths, not prerequisites.

## Relationship To System observability, HIDS, And OpenTelemetry

system-side systems are valuable because they provide low-intrusion,
system-level ground truth for agent behavior: process activity, file access,
network behavior, and cross-process effects. AgentProvenance should learn from
that direction and can ingest that class of telemetry, but it should not present
itself as a clone of a zero-SDK eBPF observer.

The differentiation is the control-plane layer above observation:

```text
system-side telemetry + application-side agent context
  -> runtime causality graph
  -> Git-like provenance DAG
  -> security analysis / risk judgment
  -> response action / forensics / audit trail
```

The HIDS analogy is useful: AI agents in sandboxes still create host-like
monitoring needs around process, file, network, resource, and policy activity.
The difference is that AgentProvenance treats the agent context as first-class:
run, session, attempt, tool call, task, snapshot, artifact, risk signal,
baseline deviation, response action, and quarantine state.

OpenTelemetry and LLM tracing tools remain useful inputs or exports. They are
not the core product surface. AgentProvenance focuses on evidence lineage,
diff/blame, taint propagation, risk decisions, response hooks, replay, and audit
manifests.

## What The Graph Must Answer

- What produced this artifact?
- Which snapshot did this attempt start from?
- Which tool call started this process?
- Which child process produced this runtime event?
- What is the time-ordered execution story across tool calls, processes,
  telemetry, risk, and response?
- Which process changed this file?
- Which behavior deviated from this task or agent baseline?
- Which file state is created, modified, deleted, or unchanged from base?
- Which external effect was attempted, gated, or denied?
- Which branch was tainted or quarantined?
- Why was an execution branch blocked by the response gate?
- Which risk decision and response action are supported by concrete evidence?
- What evidence and deviation signals should an external evaluator or RL
  pipeline score?
- Can this trajectory be replayed or audited later?

## Phase Plan

> Status (as of v0.4.x): Phases 1–5 are substantially delivered — including the
> **native eBPF sensor** (`internal/sensor`, shipped in v0.2.0 and expanded
> since), supervised cgroup capture, correlation, risk/policy/response, taint,
> automatic artifact objectification, and signed forensics export.
> Phase 6 is partial (content-addressed storage and the web dashboard are in;
> retention/GC/scale hardening is ongoing). This is delivered work, not a list of
> unbuilt plans.

The canonical phase table lives in the **[README Roadmap](../README.md#roadmap)**,
and the current, machine-checked acceptance list (Phase 1 / v1 Definition of Done)
is **[docs/v1-definition-of-done.md](v1-definition-of-done.md)**. To avoid drift,
this doc no longer restates them — it keeps only the product framing above; see
those two for the canonical roadmap and DoD.

## Final Effect

The finished system should make a sandboxed agent execution feel like Git for
runtime state and evidence:

```text
branch: attempt
commit-like object: content-addressed evidence object
diff: file state delta from base
blame: state attribution to attempt/tool/process
tag: candidate/promoted/quarantined/tainted
log: execution history
replay: reconstruction plan and audit manifest
```

This is the durable differentiation from generic observability:
AgentProvenance is not only showing that something happened. It explains how an
agent execution state was produced, changed, branched, tainted, judged risky,
responded to, and made eligible or ineligible for further use.
