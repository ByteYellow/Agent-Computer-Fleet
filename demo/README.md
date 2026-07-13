# AgentProvenance demos — a progressive story

Three stages, read simplest → hardest. Each is a **real capture on genuine
kernel events**, exported as a signed, verifiable bundle you can replay locally
(no VM needed). Start with Stage 1.

Each agent's session transcript is harvested into `llm_call` nodes — the model's
real prompt, reasoning, and decided commands. In the **multi-agent stage**
(Stage 2) the **model call that decided the poisoned install** links to the very
command that ran via an `llm_caused` edge — including the call made by a
**sub-agent** (bob), whose decision lives in its own transcript, not the
orchestrator's. The join is robust to eBPF argv truncation: it matches the
decided command against the record process sample (`/proc/cmdline`), so the edge
survives even when the execve argv is clipped. Rendered by the agent-intent DAG
lens.

(Stage 1's committed bundle predates this harvest, so it shows the causal join
only at the tool_call→syscall level; its `llm_caused` regeneration is pending.)

## Stage 1 — [`snake-supply-chain/`](snake-supply-chain/) · one agent

The foundation. A single agent installs a poisoned `setup.py`; the install hook
reads a secret and connects the cloud-metadata IP. The kernel sensor catches the
`secret_path` + `metadata_ip` syscalls, and the **signed causal graph** ties them
to the run — buried supply-chain exfil turned into verifiable, tamper-evident
evidence. Bundle: `run-snake-supervised`.

## Stage 2 — [`multiagent-provenance/`](multiagent-provenance/) · an agent team

Everything in Stage 1, now across a **team of agents**, and with the attacker's
full arc:

- **Delegation + peer edges.** The same buried install is relayed **alice → bob**
  over `SendMessage`; the graph records who *spawned* whom (delegation) and who
  *influenced* whom (peer, with the poisoned message body captured as evidence).
- **Per-agent attribution.** The in-process sub-agents share one cgroup, so the
  kernel can't tell them apart — provenance joins the exfil syscall back to bob's
  install by **command-match**.
- **The failed path.** Prepended **Attempt A**: a `recon` teammate proposes the
  theft openly and is refused at the intent layer (a `refused` node, no egress);
  the attacker then **pivots** to the buried Stage-1-style path (Attempt B) that
  slips past the model and is caught only by the kernel. One signed graph shows
  *try-the-obvious-way → get-flagged → pivot-to-stealth*.

Bundle: `run-double-attempt`.

## Stage 3 — [`llm-judge/`](llm-judge/) · an external LLM as security judge

The evidence graph is not only for humans: **any external LLM can be wired in
as a security judge** over a captured run. `python3 llm-judge/judge.py run`
exports the run's *full* trajectory (every telemetry event, no type filter,
chunk/map-reduced past the context budget), has the model deliver a
structured verdict, and imports the verdict back as graph-referenced
signals. The judge itself runs under `agentprov record`, and its own LLM
requests/responses become `llm_call` nodes in the judge's provenance run —
**the judge is itself audited**. Works with any Anthropic- or
OpenAI-protocol endpoint (Claude, DeepSeek, Qwen, local Ollama/vLLM, ...),
and degrades to a keyless offline fixture so the pipeline always completes.

## Why this order

Stage 1 proves the moat on the simplest case — intent/action → real syscall →
**signed** evidence. Stage 2 adds what the kernel alone can't do (attribute an
action to one of many in-process agents) *and* the security thesis: alignment
catches the obvious attack, but a hidden-intent supply-chain attack needs the
kernel-level provenance backstop. Same primitive, harder problem.

## View either stage

Each folder's `README.md` has the exact commands + the diagrams. The shape is:

```sh
agentprov --data-dir /tmp/view init
agentprov --data-dir /tmp/view forensics import <folder>/<run>.forensics.json.gz \
  --pub-key <folder>/attestation.pub          # verifies the signature BEFORE loading
agentprov --data-dir /tmp/view graph verify --run <run>        # → status=ok
agentprov --data-dir /tmp/view dashboard serve --addr 127.0.0.1:7396
```

Both bundles can be imported into one `--data-dir` and switched via the run
selector. The **Orchestration** lens (Stage 2) draws the agent topology. Capture
harnesses live under each `capture/`; full design notes: memory
`agentprov-multiagent-demo-todo.md`.

Demo replay fixtures are committed as compressed `*.forensics.json.gz` bundles.
Do not commit regenerated raw `*.forensics.json` captures; keep raw exports local
or publish large captures as release assets.
