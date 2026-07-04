# AgentProvenance demos — a progressive story

Two demos, read simplest → hardest. Each is a **real capture on genuine kernel
events**, exported as a signed, verifiable bundle you can replay locally (no VM
needed). Start with Stage 1.

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
agentprov --data-dir /tmp/view forensics import <folder>/<run>.forensics.json \
  --pub-key <folder>/attestation.pub          # verifies the signature BEFORE loading
agentprov --data-dir /tmp/view graph verify --run <run>        # → status=ok
agentprov --data-dir /tmp/view dashboard serve --addr 127.0.0.1:7396
```

Both bundles can be imported into one `--data-dir` and switched via the run
selector. The **Orchestration** lens (Stage 2) draws the agent topology. Capture
harnesses live under each `capture/`; full design notes: memory
`agentprov-multiagent-demo-todo.md`.
