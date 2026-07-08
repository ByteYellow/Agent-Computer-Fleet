# Changelog

## v0.7.0 - 2026-07-08

Portable Producer Profiles. Evidence collection extends from local/VM to
**Kubernetes pods** with the same guarantees — **without changing the core graph
or the schema**. The core stays substrate-agnostic: it reads the normalized
telemetry schema out of SQLite, and substrate never reaches it. Producers differ
only in *where the sensor runs*, *how scope is attributed*, *how events ship*, and
*which layers they can honestly collect*. One node sensor can now observe multiple
pod cgroups and pin each to its own signed run. The microVM guest profile is
declared as capability data and marked in progress.

### Added

- **Producer Profile abstraction (`internal/producer/profile.go`).** A profile
  declares sensor placement, scope mode, and — as first-class *capability data* —
  the coverage of each of the three collection layers (system telemetry / model
  intent / app context), so a degraded layer is honest data, not a hidden gap.
  Ships `local-record`, `k8s-daemonset`, and `microvm-guest-init` (the last a
  capability declaration; runner/guest-image integration is in progress).
- **k8s-daemonset scope attribution.** `agentprov sandbox bind-cgroup` binds a
  pod's node-observed cgroup to a run as a passive `k8s_cgroup` scope
  (confidence 0.8, vs record's kernel-verified 1.0), with optional pod-metadata
  enrichment (cluster / node / namespace / pod / container / image /
  service-account / pod-ip / labels) recorded as a context event — no schema
  change, no client-go informer required.
- **Substrate lens (dashboard + `graph lens --lens substrate`).** Renders the
  producer topology: profile → node sensor → workload → per-pod cgroup → scope →
  run, plus a `pod_influences_pod` edge when one pod's egress targets another
  pod's IP (a real cross-pod A2A call as kernel ground truth). A run-overview
  producer-profile bar surfaces evidence source / scope source / confidence.
- **Node-side model intent for pods.** The libssl uprobe attaches by inode, so
  pointing it at a pod's own `/proc/<pid>/root/.../libssl.so.3` captures the
  pod's TLS request/response bodies from the node with no image change. Python's
  module-loaded OpenSSL (`_ssl.so`) is auto-detected.
- **Parity acceptance (`scripts/accept_k8s_pod_parity.sh`).** Asserts a
  node-observed pod's telemetry attributes to a run and verifies clean
  (`errors=0`) — the same evidence guarantee as local-record, for an
  externally-scheduled pod never wrapped by `record`.

### Changed

- **File nodes for passive (absolute-path) writes.** Graph file nodes previously
  came only from `record`'s workspace diff (workspace-relative paths). A passive,
  node-side capture has no workspace diff, so its file writes — all absolute —
  produced no file node. Ingest now links substantive absolute paths (filtering
  `/dev/null`, `/proc`, `/sys`, sockets, pipes) to `workspace_file/<abspath>`
  nodes, so passive file activity is first-class in the file, raw, and taint
  lenses, joined to the writing process.

### Demo

- **`demo/k8s-substrate/`** — the k8s-daemonset profile end to end: a real LLM
  agent pod captured node-side (system telemetry + model intent), attributed by
  cgroup. Ships a signed, replayable bundle (`run-claude-demo`).
- **`demo/k8s-cross-pod-a2a/`** — the multi-agent attacker arc across a pod
  boundary: `alice` (pod A) influences `bob` (pod B) over a real A2A network
  call; one node sensor pins `bob`'s secret-read → staged-file → metadata-IP
  exfil to his cgroup while `alice` stays provably clean; both cgroups bind to
  one signed run. Ships a signed, replayable bundle (`run-a2a-demo`).

## v0.6.0 - 2026-07-06

One-command capture and an intent-conformance layer. `agentprov launch -- <agent>`
wraps any agent in a full provenance run with a single command, and the model-
intent layer moves from "which command did the model run" to contract-vs-effect:
what each action DECLARED it would do versus what the runtime ACTUALLY did, with
boundary violations, refusal bypasses, and honest coverage gaps as first-class
verdicts. The agent's real prompt and reasoning are harvested from the session
transcript with zero instrumentation.

### Added

- **`agentprov launch -- <agent>` (`internal/launch`).** One command does the
  whole run: create a run scope, serve the live dashboard, inject a per-run
  Claude Code hooks overlay via `--settings` (the user's `~/.claude` is never
  modified), start the kernel sensor when the host can (else degrade honestly),
  exec the agent in a dedicated cgroup, then seal + sign the evidence graph and
  print a one-line verdict. Evidence level is printed up front on two honest
  axes — application side (hooks / transcript vs record-only) and system side
  (kernel telemetry vs none). A hidden `internal` command group begins the
  git-style porcelain/plumbing split.
- **`agentprov doctor -- <agent>` launch preflight.** The same readiness checks
  launch prints can now run without starting the agent: agent binary, Claude
  hook-injection compatibility, dashboard port availability, cgroup v2 scope
  support, and kernel sensor capability. Warnings are explicit degradation
  reasons rather than hidden failures; `--json` gives install scripts a stable
  machine-readable report.
- **Intent-Runtime Diff conformance engine (`internal/intent`,
  `agentprov intent diff`).** Reconciles each captured IntentContract (a tool
  call, peer message, or refusal, each declaring the effects it should and must
  not produce) against the RuntimeEffects attributed to its scope. Verdicts:
  `declared_vs_effect_mismatch` (a boundary violation, e.g. an install that read
  a foreign secret), `refused_but_runtime_happened`, `decided_and_executed`, and
  the honesty state `intent_coverage_gap` (an effect it could not tie to captured
  intent is a gap, never a fabricated finding). Effects are classified through
  the existing policy engine (a foreign-secret read vs the agent's own creds),
  and the finding is conditional on each action's declared contract — a network
  connect is drift for a read-only tool but permitted for bash. Results feed a
  new `intent_conformance` dimension in the unified signal model and flip the
  launch verdict; `peer_message_intent_mismatch` marks a violation whose intent
  came from another agent's message.
- **Transcript harvest (`internal/provenance.HarvestTranscript`).** The Claude
  Code session transcript (the JSONL a hook's stdin points at) is ingested into
  the same `llm_call` graph model TLS capture feeds — the model's real prompt,
  reasoning, and tool decisions — with zero instrumentation and on any platform.
  Renders through the existing agent-intent flow with no lens change.
- **Conformance ("Intent · declared vs actual") graph lens.** Renders each
  contract's scope → the diff verdict → the observed effects, colored by status,
  alongside the delegation (主从) and peer (对等) agent structure.

### Changed

- **Agent-intent DAG collapses the caused fan-out.** A model response that
  causes hundreds of syscalls now aggregates into a single "caused N syscalls"
  summary node above a threshold, so the prompt→decision→action spine stays
  legible (individual syscalls remain in the process / security lenses).
- **Demos re-captured with `launch`.** The snake supply-chain and multi-agent
  team bundles are freshly captured through the one-command flow; both now carry
  the transcript (cognitive) axis and surface a real conformance mismatch — the
  poisoned install's secret-read + metadata-egress is flagged as an `install`
  operation exceeding its declared contract, attributed to the acting sub-agent.

LLM-intent provenance: the sensor now captures the agent's actual LLM traffic
as full TLS plaintext, reassembles and parses it, and materializes it into the
signed graph — so the DAG can answer "which model call caused this syscall,
and did the command that ran match what the model decided?" The agent-intent
lens is rebuilt as a causal DAG over real evidence nodes, and a new llm-judge
demo has an external LLM render an audited verdict over the full trajectory.

### Added

- **Full TLS body capture (`internal/sensor`).** The SSL_write/SSL_read uprobes
  now emit the complete plaintext as ordered chunks keyed by TLS connection and
  direction (previously hash + bounded metadata only).
- **TLS reassembly + LLM semantics (`internal/tlsintent`).** Userspace
  accumulates the sensor's chunks into COMPLETE HTTP/1.1 messages
  (Content-Length, chunked, and SSE streaming bodies; HTTP/2 is detected via
  the client preface and passed through raw, never mis-parsed) and parses
  minimal LLM semantics tolerant across Anthropic Messages / OpenAI Chat
  Completions shapes: model, message count, system-prompt presence, tools
  offered, tool calls + the shell commands the model decided to run, stop
  reason. Platform-neutral (no eBPF deps), unit-tested off-Linux.
- **LLM calls in the signed graph (`graph materialize-llm`,
  `internal/provenance.MaterializeLLMCalls`).** Each captured body is
  objectified as a content-addressed `llm_message`; each request/response pair
  becomes a first-class `llm_call` node with `llm_request` / `llm_response` /
  `llm_body` edges. Idempotent; covered by `graph verify` and
  `scripts/accept_llm_intent_causality.sh`.
- **`llm_caused` scoped to the decided command.** The causality edge from an
  `llm_call` to a syscall is drawn only when the executed command matches a
  `tool_command` from the model's response — not to everything that happened
  after the call — so "the model told it to" stays narrow and defensible. The
  legacy ingest-time `llm_intent_caused` edge is no longer rendered
  (superseded by the materialized `llm_caused`).
- **Agent-intent lens is now a causal DAG.** The stage-card renderer is
  dropped; the view is a DAG over real evidence nodes — `llm_call` → decided
  command → process → runtime events → risk — with blocked/refused intents
  shown as first-class nodes, grouped by the agent that proposed them.
  Run Overview tool-call / LLM-intent entries drill down into it.
- **Dashboard: LLM lifecycle spine + readability.** `summary` shows only the
  LLM lifecycle route when a captured model call exists (the send-msg step
  tracks orchestrator delegation); readable execve labels; content previews on
  tool_call/event nodes; sticky expand; node labels clipped inside their boxes.
- **llm-judge demo (`demo/llm-judge/judge.py`, Stage 3).** A single-file,
  stdlib-only Python judge reads a captured run's FULL trajectory through the
  generic contract surfaces (EvalContext, ai tools, graph lenses — no event-type
  filter, chunked map-reduce past the context budget, coverage recorded),
  has any Anthropic/OpenAI-protocol LLM produce a structured verdict
  (`agentprovenance.llm_judge/v1`), and imports it back as graph-referenced
  signals. The judge itself runs under `record` and its own LLM
  requests/responses become `llm_call` nodes in the judge's provenance run —
  the judge is itself audited. Degrades to a keyless offline fixture.
- **Real LLM intent in the demo bundles (`demo/shared/llm-intent-curl.sh`).**
  Both capture harnesses fire one real model/tool-intent request via
  curl/OpenSSL (secrets stay in headers, never in the script or body), so the
  recaptured, re-signed Stage 1/2 bundles now carry the model call that
  decided the poisoned install — `llm_call` → `llm_caused` → the exact syscall.

### Changed

- **README narrative: evidence layers, not integration modes.** The
  "White-box mode / Zero-SDK mode" split is gone: one entry point
  (`record -- <cmd>`), kernel/runtime facts as the foundation, application
  context (hooks bridge / MCP context-write, `ai_asserted` ≤0.5) as an
  automatically stacking enrichment layer. "SDK/framework integration"
  phrasing removed throughout; `docs/product.md` aligned.
- **README slimmed into docs/ references.** Full command references moved to
  `docs/security-commands.md`, `docs/graph-commands.md`, and
  `docs/compliance.md`; the Python custom-rules content merged into the
  External Evaluator Protocol section (one topic, told once).
- **Falco receiver demoted to a compatibility path.** The README section moved
  to `docs/falco-receiver.md`; the native eBPF sensor is the featured
  kernel-evidence source, and third-party receivers (Falco/Tetragon) are
  maintained for compatibility, not extended.

### Fixed

- **`graph explain` no longer crashes on large scopes.** Telemetry batches are
  matched against event ids in Go instead of one SQL `LIKE` clause per event,
  which overflowed SQLite's expression-depth limit (~1000 events) and crashed
  `--attempt/--tool-call/--process/--file`.
- **Deterministic DAG rendering.** Every `created_at` ordering feeding the
  causality DAG gained an id tiebreaker, lens summary builders iterate in
  `(created_at, node id)` order, and `/api/graph` node output is sorted — BFS
  order, `page_hash`, evidence_refs, and the 32-item lens truncations are now
  byte-stable across renders and survive re-materialize (verified 3× on both
  demo bundles).
- **Hooks bridge: sub-agent identity.** Sub-agents spawned via the Agent tool
  now resolve their name from the tool's `name` field instead of falling back
  to a generic id.
- perf: graph edges indexed by `(run_id, created_at, id)`; lens metadata cached.

## v0.5.0 - 2026-07-03

Multi-agent orchestration provenance: attribute an attack across a Claude Code
agent team (delegation + peer edges) against real kernel syscalls in one signed
graph — plus policy replay/config and the app-context hardening that gives
record's own scopes a real kernel join key.

### Added

- **Multi-agent orchestration provenance (`agentprov hooks bridge`,
  `internal/hooksbridge`).** Translates a Claude Code (or compatible) agent team's
  harness hooks into the graph: an `agents` table (`PRIMARY KEY (run_id, id)`, so
  each run's `main` orchestrator stays distinct) + a `tool_calls.agent_id` column,
  `agent_spawn` (delegation) and `agent_message` (peer — the `SendMessage` body
  objectified as content-addressed evidence) edges, and a policy-scored tool_call
  per action bound to the acting agent. In-process sub-agents share one cgroup, so
  the exfil syscall is joined to the right sub-agent by **command-match**
  (`agent_syscall` edge), not cgroup. A new `orchestration` graph lens draws the
  topology; the dashboard renders agent, A2A-message, and `refused` nodes and
  labels runtime events with their target (`secret_path .aws/credentials`,
  `metadata_ip 169.254.169.254`). Proven end-to-end on a signed VM capture
  (`demo/multiagent-provenance`).
- **`agentprov security reevaluate --run [--rules]`.** Re-runs the policy engine
  over a captured run's already-stored events, regenerating the
  decision/risk/response/unified-signal layer (and its graph edges) from the
  current or a custom policy. Raw events are untouched, it is idempotent, and
  `graph verify` stays green — so an edited policy can be applied to
  already-captured runs without re-running the agent or the sensor.
- **`agentprov policy rules [--out]`.** Dumps the built-in policy as an editable
  YAML rules file, to tune and load back via `policy test --rules` /
  `security reevaluate --rules`.
- **Default `self_credential_access` policy rule.** An agent reading its OWN
  operational credentials (`.claude/.credentials.json`, its LLM API env) is still
  captured as an event (full observability) but no longer raises a high
  `secret_path` alert — ranked as an allow before the kill rule — so operational
  self-reads stop burying the real target-secret reads. Configurable via the
  dumped rules file.
- **`SelfLaunched` as a dimension orthogonal to `CorrelationClass`.** An event
  can now be both `kernel_correlated` (independently witnessed) **and**
  `self_launched` (the process was started by us). It is derived from the event
  source and the matched binding's `binding_source`, propagated onto sensor
  events through a new `events.binding_source` column, and surfaced in the
  dashboard as a badge next to the correlation class. This preserves the "did we
  start it vs. did the kernel confirm it" distinction that the old string-hack
  classifier collapsed.
- **Real cgroup-per-scope for `record` (Linux).** `record` now places the child
  (and its whole subtree, via `SysProcAttr.UseCgroupFD`) into a dedicated cgroup
  v2 leaf, so independent telemetry auto-joins the entire subtree by `cgroup_id`
  at 0.98 — no pid polling, no pid-reuse window. Non-Linux and any Linux failure
  (no cgroup v2 / not delegated) degrade to the previous synthetic logical id, so
  behavior is unchanged off-Linux. **Validated end-to-end on the lab VM (Ubuntu
  24.04, kernel 6.8, arm64):** the child is placed in `/agentprov/<attempt>`, the
  stored `cgroup_id` equals the cgroup dir inode (== `bpf_get_current_cgroup_id`),
  and a zero-context sensor event carrying that id resolves to the scope via
  `cgroup_time_window` @0.98 as `kernel_correlated` + `self_launched`. The
  synthetic parent leaf is created lazily; per-scope leaves are removed on exit.
- **`agentprov sensor stream` — per-node supervised capture.** One long-running
  command runs the eBPF sensor and streams its events straight into the store,
  correlating each by cgroup — replacing the manual
  `agentprov-sensor | telemetry ingest-jsonl` pipe. It excludes AgentProvenance's
  own I/O (data-dir snapshot + DB writes, which otherwise form a self-feedback
  storm) and drops uncorrelated host noise that belongs to no scope (which would
  fail per-run `graph verify`). Needs `CAP_BPF`+`CAP_PERFMON` (setcap or root).
- **Built-in artifact objectify in `record`.** Each changed file's content is
  objectified as a `workspace_file/<path>` artifact object, so the dashboard
  Side Panel previews what the agent actually produced. Previously this was a
  manual post-capture script that was easy to forget.

### Changed

- **`CorrelationClass` no longer keys `self_observed` off the synthetic
  `agentprov-record-` container-id string.** It keys on the event *source*, so a
  real kernel event that merely matched a record-launched binding stays
  `kernel_correlated` (with the `self_launched` badge) instead of being
  mislabeled self-observed.
- **App-asserted joins read honestly lower.** `ai_asserted` bindings
  (`bind_scope`) are capped at 0.5 confidence instead of defaulting to 1.0, so a
  scope the model merely *claimed* can never resolve as certain as a
  kernel-verified match. Method tiers (cgroup 0.98 / container 0.92 / pid 0.85 /
  process 1.0) are unchanged; the dashboard now colours the confidence number by
  band.

### Fixed

- **Dashboard graph: annotation nodes no longer render disconnected.** The
  visible node set was built from all filtered edges but only a capped subset was
  returned, so `policy_decision` / `response_action` / `risk_signal` / `file` /
  `artifact` nodes came back orphaned (their edges truncated by the
  runtime-event/process bulk). Edges are now prioritized so the rare semantic
  ones survive the cap, and the node set is built from the RETURNED edges only —
  0 orphans across all nine lenses, annotation nodes stay wired to their lineage.
- **Dashboard graph: processes show names, not bare pids.** `comm`/`tgid`
  fallback labels `runtime_process` and thread-group nodes; the process tree
  collapses repeated leaf commands (`base64 -d ×72`) so a real agent's fan-out
  stays readable.
- **Dashboard performance.** `graph verify` is cached by a cheap fingerprint
  (Run Overview ~2s → instant after first load); the Sugiyama layout is cached by
  topology so select/hover/zoom no longer re-lay-out; the edge budget and live
  refresh interval are eased. Scrubber `edgeVisible` now respects the edge's own
  time instead of only its endpoints'.
- Recaptured the snake / supply-chain demo bundle under the new supervised mode,
  signed (`demo/snake-supply-chain/run-snake-supervised.forensics.json.gz`),
  replacing the older pre-cgroup bundle: the agent's product (`snake.py`) is
  objectified and previewable, the supply-chain TTP correlates @0.98 +
  `self_launched`, and `graph verify` is clean.

## v0.4.1 - 2026-07-01

A consolidation-and-fix release on top of `v0.4.0`. No new surfaces — it makes the
compliance mapping defensible, unifies it across CLI and dashboard, and fixes two
display bugs.

### Changed

- Compliance mapping is now **rule-driven with four honest states** instead of
  "any evidence of class X exists":
  - `enforced` (a mapped detection rule fired and blocked),
    `detected` (fired but detect-only), `not_triggered` (rule maps here, did not
    fire), `no_rule` (no detector maps to this control — an honest coverage gap,
    not a fake pass).
  - The dashboard compliance card and the `compliance map` / `gaps` / `explain`
    CLI now share one model (`compliance.MapRunRules`) so they never drift.
  - Expanding a control shows **every individual rule hit** (time, decision,
    reason), each clickable back to its graph node.
- `security.Rule` gained `mode` (enforce | detect) and `controls:` so custom YAML
  detection rules map themselves onto framework controls; detect-mode rules are
  recorded but do not block. See `examples/policies/agentic-security.yaml`.

### Fixed

- Dashboard timeline "detail" and evidence "payload" cells no longer truncate at
  160 chars — the full record is shown, clamped by default and expandable.
- Graph lens no longer renders `tool_call` / `session` / `attempt` / `rollout` /
  `process` id endpoints as generic "unknown" nodes; they are typed by id prefix
  and counted correctly (e.g. the overview "Tool calls" count).

### Removed

- The legacy evidence-class compliance model (`MapRun`, `ResolveEvidence`, and the
  `internal/compliance/evidence.go` loaders) — superseded by the rule-based model.

## v0.4.0 - 2026-06-30

This release turns AgentProvenance from a CLI-first evidence prototype into a
local, replayable provenance dashboard for sandboxed agent execution.

Compared with `v0.3.0`, the main change is the new Graph Explorer and replayable
agent-in-sandbox demo: a signed supply-chain exfiltration capture can now be
imported directly and inspected offline without a Linux/eBPF VM.

### Added

- Added a portable signed demo bundle at `demo/snake-supply-chain/`.
  - Captured a real coding-agent run in a sandbox.
  - Shows a supply-chain install hook reading planted fake secrets and attempting
    metadata-IP egress.
  - Can be replayed with `forensics import` and inspected through the dashboard.
- Added Graph Explorer lenses for query-oriented provenance inspection:
  - Run overview
  - Security
  - Process
  - File/artifact
  - Network egress
  - Data-flow/taint
  - Agent intent
  - Trust/origin
  - Sandbox boundary
- Added bounded graph detail modes:
  - `summary` for grouped, high-signal views
  - `expanded` for selected high-value detail
  - `raw` for drilldown-oriented evidence, not default rendering
- Added focused evidence drilldown from graph nodes and risk signals.
- Added local graph expansion controls for upstream/downstream/children/raw
  evidence exploration.
- Added dashboard artifact preview support for bounded, redacted content preview.
- Added forensics import support for signed portable bundles.
- Added forensics round-trip tests.
- Added compliance rule mapping:
  - `examples/policies/agentic-security.yaml`
  - `internal/compliance` rule-to-control mapping
  - dashboard compliance API and panel
  - policy rule modes for enforcing vs detect-only mappings
- Added dashboard preview tests and graph lens tests.

### Changed

- Reworked the dashboard from a large canonical graph dump into a
  query-oriented evidence surface.
- Reworked README positioning around execution observability, Git-like
  provenance, dashboard replay, and signed evidence.
- Clarified that raw telemetry remains queryable, but the dashboard should not
  render every syscall/event as a graph node by default.
- Narrowed taint derivation so sensitive-data flow is gated by risky egress
  destinations instead of treating every network connection as exfiltration.
- Improved process naming from sampled process data so graph nodes are easier to
  inspect.
- Updated telemetry schema and eBPF sensor documentation to match the shipped
  native sensor surface.
- Updated roadmap/status documentation to reflect the actual implemented
  dashboard, MCP, native sensor, replay, and compliance surfaces.

### Fixed

- Fixed graph summary aggregation counts in dashboard lenses.
- Fixed risk signal clicks to focus the relevant graph path instead of only
  listing raw events.
- Fixed process burst drilldowns so grouped process/event summaries expand to
  the intended evidence set.
- Fixed dashboard labels that made Focused Evidence and Run Timeline look like
  the same surface.
- Fixed clean replay verification and populated Signals panel for the captured
  demo run.

### Demo

The release demo does not require re-running the agent or the eBPF sensor.
Import the signed bundle:

```sh
go build -o /tmp/agentprov ./cmd/agentprov

/tmp/agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub

/tmp/agentprov --data-dir /tmp/snake-replay dashboard serve --addr 127.0.0.1:7396
```

Then open `http://127.0.0.1:7396` and select `run-snake-supervised`.

The capture scripts under `demo/snake-supply-chain/capture/` are only needed to
reproduce the original Linux/eBPF capture on a compatible VM. They are not
required for replaying the shipped demo.

### Verification

- `go test ./...`
- Dashboard JavaScript syntax check
- Signed forensics import/replay path
- Graph lens and dashboard preview tests

### Known Boundaries

- This is a technical preview, not a production HIDS.
- The project provides local integrity verification and signed evidence export.
  It does not yet provide off-host capture-time tamper-evidence against a
  malicious host root.
- Central evidence service, notification hooks, long-running multi-tenant
  deployment, and hardened production eBPF packaging remain future work.
