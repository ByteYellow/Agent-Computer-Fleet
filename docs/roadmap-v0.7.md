# AgentProvenance v0.7: Portable Producer Profiles

## Goal

Extend the collection capability that already works on local Linux to
**Kubernetes Pods**, keeping the same evidence model — **without changing the
core graph or the schema, and without building a scheduler**. v0.7 is only
about evidence *producers*: where they run, how scope is resolved, how events
ship, and honestly declaring what each environment can and cannot collect.
Firecracker/Kata guest integration remains a future profile and is not part of
the v0.7 completion gate.

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
| **model intent** | eBPF uprobes on libssl (`SSL_write`/`SSL_read` and `SSL_write_ex`/`SSL_read_ex`), plus a partial Go `crypto/tls.(*Conn).Write` request/write uprobe via `AGENTPROV_GO_TLS_BIN`; userspace parses HTTP/1.1 and HTTP/2/HPACK (`sensor_linux.go`, `internal/tlsintent`) | the target kernel **and the TLS stack** | ⚠️ no — dynamic OpenSSL + partial unstripped Go request path today |
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
| **local-record** (baseline, exists) | local host | `record` cgroup leaf | system + app-context full; model-intent partial (dynamic OpenSSL + Go request/write when configured) | — (parity reference) |
| **k8s-daemonset** | node sensor DaemonSet plus unprivileged attribution-controller companion | passive cgroup→container→pod (+ optional record-wrap entrypoint) | system telemetry validated across multiple pods; app-context joins through existing adapters; model-intent only when workload TLS symbols are resolvable from the node/rootfs | **Validated:** DaemonSet placement, stdout JSONL transport, container/pod metadata→kernel-cgroup attribution, 8-workload graph verification, and client-go informer create/restart/delete lifecycle. **Deferred:** full operator/HA and cluster-wide control plane. |
| **microvm-guest-init** | future in-guest init service | target: active record-wrap | **planned / unvalidated:** all current coverage reports `none` | future guest-image integration and teardown export; not part of the v0.7 completion gate |

The sensor already parses `docker-<id>.scope`, `cri-containerd-<id>.scope`, and
`kubepods/<id>` cgroups (`sensor_linux.go` `cgroupResolver.refresh`), so pod/
container attribution is partly wired at the kernel layer already.

## Reuse (do not build new)

| Need | Reuse |
|---|---|
| scope binding | `correlation.RecordBinding` → `execution_context_bindings` table; `POST /v1/telemetry/bind`. Add a new `binding_source` value (e.g. `k8s_cgroup`) and one confidence tier in `defaultBindingConfidence`. **No schema change.** |
| event transport | existing `POST /v1/telemetry/*` ingest + spool/backpressure/retention (`internal/daemon`) — remote node/guest producers stream to a central or local daemon |
| future microVM evidence durability | existing forensics bundle export/import + signed attestation can be reused after a guest runner exists |
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

The K8s multi-workload half of this gate is repeatable in
`scripts/accept_k8s_node_multiworkload.sh`: it builds and deploys the actual
sensor DaemonSet, launches N pods, resolves pod/container metadata to observed
kernel cgroups, ingests the DaemonSet JSONL stream, and verifies one run. The
2026-08-05 arm64 K3s reference used 8 pods and captured 1,140 events with zero
verify errors/warnings. The cross-profile assertion is implemented separately
in `scripts/accept_k8s_pod_parity.sh`: on 2026-08-05 the same `id + ls /`
workload produced verified local and K8s graphs with the same canonical command,
event, node, and edge semantics. Physical identity and event-count differences
are excluded while each profile's confidence tier is retained. Future KVM work
must add its own environment gate before the profile can move from `planned` to
`validated`.

The node attribution lifecycle is independently repeatable in
`scripts/accept_k8s_informer_controller.sh`. The 2026-08-05 K3s 1.36.2
reference run created an initial binding, closed and rebound it after a real
container restart under the same Pod UID, then closed the replacement on Pod
deletion. Final state: 2 created, 2 closed, 0 active, 0 retry/failure/resolution
failure. `client-go v0.32.0` is pinned to the repository's Go 1.23 baseline.

## Follow-on tracks (explicit non-goals for v0.7)

These are separate, because they are the *hard* universality axes — do not let
them block shipping the environment profiles.

### v0.7.x — harness Intent Adapters (app-context axis)

- LangChain / OpenAI Assistants / custom-harness adapters: each is a thin
  format translator (harness callbacks → hook schema) riding the existing
  command-match seam. Unadapted harnesses still get kernel-layer provenance —
  they never go dark.

### v0.8.0 — model-intent multi-TLS-stack hardening (intent axis)

- Harden LLM intent beyond the current dynamic OpenSSL + partial Go request
  path: Go `crypto/tls` response/read capture, BoringSSL, statically-linked TLS,
  stripped Go binary handling, and x86 live validation. This is the remaining
  attack that makes model-intent harness-agnostic across the whole ecosystem.
- **Read-side capture rate (observed on the k8s-daemonset demo, 2026-07-08).**
  Even for dynamic OpenSSL, node-side pod capture emits `tls_write` reliably but
  `tls_read` only intermittently (write:read ≈ 13:1 per window). The `SSL_read`
  enter+uretprobe attach is fine; the loss is in HTTP-response head reassembly —
  chunked / HTTP-2 responses whose head does not land in the first `SSL_read`
  return get dropped rather than emitted. Effect: request bodies (prompts) and
  the substrate/process/egress lenses are complete, but response bodies and the
  `agent-intent` llm_call DAG are sparse until a read arrives. Note: the
  request↔response pairing itself is NOT the bottleneck — `recentScopedEvent`
  correctly falls back to run scope when `process_id` is empty (passive capture),
  so one captured `tls_read` yields one `llm_call`. Fix belongs here: reassemble
  `SSL_read` segments before HTTP parsing.

## Capability matrix (target state)

| Environment | system telemetry | model intent | app context | scope |
|---|---|---|---|---|
| local-linux / VM (today) | ✅ | ⚠️ dynamic OpenSSL (`SSL_*` + `SSL_*_ex`; h1 + h2/HPACK) + partial Go request/write | ✅ | record (kernel-verified) |
| microVM (Firecracker/Kata) | ⬜ planned | ⬜ planned | ⬜ planned | future record in-guest |
| K8s Pod | ✅ node | ⚠️ dynamic OpenSSL or Go write path when symbols are resolvable from node/rootfs | ✅ | passive cgroup→pod, or record-wrap |
| K8s Job | ✅ node | ⚠️ same | ✅ | + job/owner metadata |
| bare-metal / multi-node | ✅ per-node | ⚠️ dynamic OpenSSL + partial Go request/write | ✅ | record or cgroup |
| serverless / managed (no kernel access) | ❌ | ❌ (unless platform exposes it) | ✅ | explicit id only |

The only hard break is environments where you cannot get to the kernel
(serverless / fully-managed): there, only app-context survives. Everywhere that
is "a Linux computer you can put an agent on", all three layers are reachable.
