# AgentProvenance v0.7: Portable Producer Profiles (K8s Pod + microVM)

## Goal

Extend the collection capability that already works on local Linux / VM to
**Kubernetes Pods** and **microVMs (Firecracker/Kata)**, keeping the same level
of evidence completeness — **without changing the core graph or the schema, and
without building a scheduler**. v0.7 is only about evidence *producers*: where
they run, how scope is resolved, how events ship, and honestly declaring what
each environment can and cannot collect.

## Why this is a producer problem, not a core problem

The core (`internal/provenance`, `internal/evidence`, `internal/forensics`,
`internal/signals`) has **zero dependency on any substrate** — it reads the
normalized telemetry schema out of SQLite. Producers write that schema;
substrate never reaches the core. So new environments are reached by adding
producers, not by touching the graph/diff/verify/export code.

Collection happens on three axes, with three *different* universality ceilings.
This framing decides what v0.7 can and cannot promise:

| Layer | Mechanism (code) | Depends on | Universal by one mechanism? |
|---|---|---|---|
| **system telemetry** | eBPF tracepoints — `execve`/`connect`/`openat`/`exit` (`internal/sensor/sensor_linux.go`) | the target **kernel** | ✅ yes — harness- and language-agnostic |
| **model intent** | eBPF uprobes on libssl (`SSL_write`/`SSL_read` and `SSL_write_ex`/`SSL_read_ex`) + `getaddrinfo`; userspace parses HTTP/1.1 and HTTP/2/HPACK (`sensor_linux.go`, `internal/tlsintent`) | the target kernel **and the TLS stack** | ⚠️ no — dynamically-linked OpenSSL only today |
| **app context** | harness hook JSONL (`internal/hooksbridge`, Claude Code format) joined by **command-match** (`agent_syscall` edge) | the **harness format** | ❌ no — inherently one thin adapter per harness |

The unifying property that keeps the system from ever going dark: app-context and
model-intent join to system-telemetry by **command-match**, and every binding
carries a **confidence tier** (`internal/correlation/binding.go`,
`defaultBindingConfidence`: kernel-verified `1.0` > app-asserted `0.5`). So a
missing or degraded layer downgrades fidelity and confidence — it does not lose
observability. The kernel layer is the always-on, harness-agnostic floor.

**Consequence for v0.7:** the *environment* axis is the easy one (deploy the same
sensor by topology + resolve scope passively; core/schema unchanged). The hard
axes — model-intent across TLS stacks, and per-harness app-context — are
deliberately deferred to v0.7.x / v0.8.0 below.

## Producer Profile abstraction

```
Producer Profile = {
  sensor placement    — which kernel the eBPF sensor attaches to
  scope resolution    — how (run/session/tool_call) binds to (cgroup/container/pid)
  event transport     — how normalized events reach the sink
  capability level     — which of the 3 layers are actually collectable here
}
```

**ScopeSource has two modes**, distinguished purely by the existing confidence tier:

- **passive cgroup-attribution** — sensor derives container/pod from the cgroup
  it observes; tool calls join by command-match. Zero-touch, mid confidence.
- **active record-wrap** — the workload entrypoint is wrapped by `agentprov
  record`, which creates a dedicated cgroup leaf (`internal/record/cgroup_linux.go`)
  → kernel-verified scope, confidence `1.0`. Same as the VM path today.

## Profiles

| Profile | Sensor placement | Scope source | Layers reachable | Net-new work |
|---|---|---|---|---|
| **local-record** (baseline, exists) | local host | `record` cgroup leaf | system + app-context full; model-intent partial (dynamic OpenSSL) | — (parity reference) |
| **k8s-daemonset** | node DaemonSet (privileged / hostPID / CAP_BPF) | passive cgroup→container→pod (+ optional record-wrap entrypoint) | system + app-context directly; model-intent only when workload libssl is resolvable from the node/rootfs | DaemonSet manifest; cgroup→pod resolver; K8s informer for pod metadata |
| **microvm-guest-init** | inside the guest (init service) | `record` works natively in-guest | system + app-context full; model-intent partial (dynamic OpenSSL) | guest-image integration; **design + minimal runner**; flush + bundle export on teardown |

The sensor already parses `docker-<id>.scope`, `cri-containerd-<id>.scope`, and
`kubepods/<id>` cgroups (`sensor_linux.go` `cgroupResolver.refresh`), so pod/
container attribution is partly wired at the kernel layer already.

## Reuse (do not build new)

| Need | Reuse |
|---|---|
| scope binding | `correlation.RecordBinding` → `execution_context_bindings` table; `POST /v1/telemetry/bind`. Add a new `binding_source` value (e.g. `k8s_cgroup`) and one confidence tier in `defaultBindingConfidence`. **No schema change.** |
| event transport | existing `POST /v1/telemetry/*` ingest + spool/backpressure/retention (`internal/daemon`) — remote node/guest producers stream to a central or local daemon |
| microVM evidence durability | existing forensics bundle export/import + signed attestation (`internal/forensics`) — flush on VM teardown |
| pod/container attribution | existing cgroup parsing in `internal/sensor/sensor_linux.go` |

## Visibility & verification

- **Per-layer capability report** — declare, per profile, which of the three
  layers is actually collected (esp. model-intent / TLS coverage), plus the
  confidence tier per binding source. This is what keeps the model-intent gap
  honest instead of hidden behind "profile available". (capability-as-data.)
- **Dashboard** surfaces `evidence source` / `scope source` / `confidence` per
  node.
- ⭐ **Parity acceptance test** — run the same workload under `local-record` and
  `k8s-daemonset`; assert the evidence graph is equivalent and `verify` passes
  the same way, differing only in confidence tier. Fits the existing
  `scripts/accept_*.sh` gate culture. This is the proof that "adaptation level
  is preserved".

## Follow-on tracks (explicit non-goals for v0.7)

These are separate, because they are the *hard* universality axes — do not let
them block shipping the environment profiles.

### v0.7.x — harness Intent Adapters (app-context axis)

- LangChain / OpenAI Assistants / custom-harness adapters: each is a thin
  format translator (harness callbacks → hook schema) riding the existing
  command-match seam. Unadapted harnesses still get kernel-layer provenance —
  they never go dark.

### v0.8.0 — model-intent multi-TLS-stack hardening (intent axis)

- Capture LLM intent beyond dynamically-linked OpenSSL: Go `crypto/tls`,
  BoringSSL, and statically-linked TLS. This is the single attack that makes
  model-intent harness-agnostic across the whole ecosystem (many agents are Go
  binaries that evade the libssl uprobes).

## Capability matrix (target state)

| Environment | system telemetry | model intent | app context | scope |
|---|---|---|---|---|
| local-linux / VM (today) | ✅ | ⚠️ dynamic OpenSSL (`SSL_*` + `SSL_*_ex`; h1 + h2/HPACK) | ✅ | record (kernel-verified) |
| microVM (Firecracker/Kata) | ✅ in-guest | ⚠️ in-guest dynamic OpenSSL | ✅ | record in-guest |
| K8s Pod | ✅ node | ⚠️ dynamic OpenSSL when libssl is resolvable from node/rootfs | ✅ | passive cgroup→pod, or record-wrap |
| K8s Job | ✅ node | ⚠️ same | ✅ | + job/owner metadata |
| bare-metal / multi-node | ✅ per-node | ⚠️ dynamic OpenSSL | ✅ | record or cgroup |
| serverless / managed (no kernel access) | ❌ | ❌ (unless platform exposes it) | ✅ | explicit id only |

The only hard break is environments where you cannot get to the kernel
(serverless / fully-managed): there, only app-context survives. Everywhere that
is "a Linux computer you can put an agent on", all three layers are reachable.
