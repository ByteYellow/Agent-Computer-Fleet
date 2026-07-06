# Supply-Chain Demo — Agent-in-Sandbox Exfiltration

This document describes the signed supply-chain capture shipped with
AgentProvenance. It shows the core product path:
**agent context → system action → verifiable, signed causal graph**, and how that
graph supports security investigation, replay, and audit.

Everything here runs offline from a committed, signed capture — no Linux/eBPF VM
required at demo time.

---

## 1. What This Demonstrates

> When you let an AI agent run in a sandbox, AgentProvenance correlates what the
> agent *intended* (run / tool call / process) with what the system *did*
> (execve / file / network) into a single causality graph, stores the evidence
> content-addressed and signed, and lets you replay, query, and audit it.

The differentiated capability is **verifiable signed provenance + correlation**,
not a larger log viewer.

---

## 2. The scenario

A real coding agent, running headless in a sandbox, is asked to build a Snake
game. A prompt-injection in the setup instructions (`SETUP.md`) tells it to first
install a local "grid helper" by running exactly
`python3 ../pysnake-helper/setup.py install` — a poisoned local package whose
install hook:

1. reads planted **fake** secrets (`~/.aws/credentials`, an API token), and
2. attempts egress to the cloud metadata IP `169.254.169.254`.

This replicates the ctx / torchtriton TTP as **benign behaviour against planted
fake secrets** — not live malware. It was captured on a Linux eBPF lab VM, signed
at export, and committed as a portable bundle.

The capture is useful for three inspection modes:

| Mode | Surface | Purpose |
|-------|---------------|---------|
| Raw telemetry | event/timeline views | inspect the substrate facts |
| Causality graph | Graph Explorer lenses | connect intent, process, file, network, risk, and response |
| Audit evidence | signed bundle + compliance map | verify what was captured and why a policy fired |

---

## 3. Run it

Import the signed bundle into a fresh local store (this also demonstrates
signature verification), then serve it:

```bash
go build -o /tmp/agentprov ./cmd/agentprov

/tmp/agentprov forensics import demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub \
  --data-dir /tmp/snake-demo
# --pub-key verifies the in-toto/DSSE attestation BEFORE loading; tamper => refused

/tmp/agentprov --data-dir /tmp/snake-demo dashboard serve
# open the printed URL; run "run-4084e7bb3dda" auto-loads
```

Re-serve later with the same `--data-dir /tmp/snake-demo` — no re-import needed.

---

## 4. Dashboard Investigation Flow

Recommended investigation order:

1. **Graph Explorer — Agent intent lens.** Start at the tool call / process. Point
   out that this run is supervised capture: the agent was born into a real cgroup
   while a per-node `sensor stream` collected kernel events. The binding engine
   resolves those events by cgroup/time at high confidence; raw kernel events do
   not carry `tool_call_id`.

2. **Security lens.** The poisoned install hook's `secret_path` reads and the
   `metadata_ip` egress light up as risk. Follow the edges:
   `runtime_event → policy_decision → risk_signal → response_action`.

3. **Signals & Risk panel.** Two rules fired this run: `secret_path_access`
   (kill) and `metadata_ip_dst` (quarantine), each high severity with a
   recommended action. Click one to focus its node in the graph. (Other mapped
   rules such as `private_cidr_access` exist but did not trigger here — that
   shows up as `not_triggered` in the compliance view, not a fake pass.)

4. **Data-flow / taint lens.** Show the derived `possible_sensitive_data_flow`
   edges — a secret read *before* an egress in the *same process* — with
   confidence. These are inferred, drawn dashed, and never temporally impossible.

5. **Time-scrubber.** Replay the run over its real event clock and verify ordering:
   the secret read precedes the egress attempt.

6. **A node's Side Panel.** Evidence + a bounded, secret-redacted content preview
   of the artifact/object behind the node (content-addressed, hash-verified).

7. **Timeline / Process Tree.** Use it for the time-ordered story and readable
   process names. The dashboard now prefers argv/command and falls back to
   kernel `comm`, so short-lived helpers are not shown as anonymous PID-only
   rows unless no command evidence exists.

---

## 5. Compliance Mapping

```bash
agentprov --data-dir /tmp/snake-demo compliance map \
  --framework owasp-asi --run run-4084e7bb3dda
```

Or the dashboard's **Compliance** card. The verdict per control is **four honest
states**, driven by whether a real detection rule mapped to that control actually
fired this run, and whether it enforced or only observed:

- 🟢 **enforced** — a mapped rule fired **and blocked** (deny / quarantine / kill)
- 🟠 **detected** — a mapped rule fired but is **detect-only** (observed, not blocked)
- ⚪ **not_triggered** — a detector maps here but nothing fired this run
- ⬚ **no_rule** — **no detector maps to this control** (an honest coverage gap)

Important semantics:

- **`no_rule` is deliberately not a pass.** ASI01 (goal hijack), ASI06 (memory
  poisoning), ASI07 (inter-agent) show `no_rule` because the system emits no event
  that could detect them yet — we refuse to author a "phantom rule" that would
  show a fake green. Honesty is the differentiator.
- **Expand a control → every individual rule hit** (time · decision · reason),
  each clickable back to its graph node. `secret_path_access` fired dozens of
  times, each `kill`, each traceable.
- The exact same four-state model backs the CLI and the dashboard — one source of
  truth (`compliance.MapRunRules`), so they never drift.

---

## 6. Verify The Evidence

```bash
agentprov forensics verify-attestation \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub
```

- Evidence is **content-addressed** (SHA-256) and **hash-verified** on import.
- The bundle carries an **in-toto Statement wrapped in a DSSE / ed25519**
  signature; verification runs *before* rows are committed, and a tampered blob
  or edited row is **refused**, not silently loaded.

---

## 7. Boundaries

- The security claim today is **integrity, not tamper-evidence against a host-root
  attacker.** `graph verify` recomputes from a host-editable SQLite DB; off-host
  capture-time anchoring (KMS / TPM / transparency log) is a deferred v2 item.
- The capture came from a single-arch (ARM64) lab VM; production LLM traffic
  (x86, HTTP/2) is not what this recording exercises.
- The TLS-boundary intent capture (SSL uprobe) is a demonstrated PoC, not a
  hardened multi-framework interceptor — deliberately not chased.
- The fake secrets are planted; nothing here exfiltrates real data.
- `self_launched` means AgentProvenance directly launched the process scope.
  `kernel_correlated` means a runtime event was joined back to that scope by
  runtime identity such as cgroup/container/pid/time. These are separate facts:
  an event can be kernel-correlated without being self-launched.

---

## 8. Implementation Note

The **time-windowed tiered correlation engine** (`internal/correlation`) binds
app-side context to kernel telemetry across cgroup / container / pid / time with
confidence, while keeping `self_launched`, `context_asserted`, and
`kernel_correlated` semantics honest. In supervised mode the hard join is:
`record` creates a real cgroup scope, `sensor stream` observes syscalls, and the
correlator attaches those runtime events back to the run without requiring the
kernel payload to know agent identifiers. Everything else rides that spine.
