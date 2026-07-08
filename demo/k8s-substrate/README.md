# k8s substrate demo — one pod, node-side capture, model intent included

**The k8s-daemonset producer profile end to end: a real LLM agent runs in an
ordinary Kubernetes pod, and a node DaemonSet sensor captures its kernel activity
*and its model intent* — the actual prompt/response bodies — from outside the pod,
without touching the image, attributed to a run by cgroup.**

This is the single-pod baseline for the k8s-daemonset profile (the
[cross-pod A2A demo](../k8s-cross-pod-a2a) builds the multi-agent attacker arc on
top of it). It is the k8s counterpart of the local-record path: the *same*
evidence for an externally-scheduled pod that was never wrapped by `agentprov
record`.

---

## 1. What this demonstrates

> An agent scheduled by Kubernetes — not launched by us — still produces a
> verifiable provenance graph. A privileged node sensor resolves the pod's cgroup,
> attributes its execve/connect/openat syscalls to a run at a declared confidence
> tier, and (when the pod's TLS symbols are reachable from the node) reads the
> LLM request/response bodies too — all with zero cooperation from the workload.

The differentiated capability: **passive, zero-touch capture of an externally
scheduled pod, including model intent**, not just system telemetry.

---

## 2. The scenario

A Python agent pod (`claude-agent`) makes real LLM calls in a loop —
`POST api.anthropic.com/v1/messages` and `POST api.deepseek.com/chat/completions`.
It is a plain pod: no sidecar, no SDK, no `record` wrapper. A node-side sensor run
captures everything and `sandbox bind-cgroup` ties the pod's cgroup to a run.

---

## 3. Architecture — how model intent is captured node-side

```
   ┌──────────────────────────────  ONE k8s node  ──────────────────────────────┐
   │                                                                              │
   │   ┌─ pod: claude-agent ───────────────┐                                      │
   │   │ python3 agent.py (loop)            │      egress → api.deepseek.com      │
   │   │  └ https POST /chat/completions ───┼──────────────────────────────────▶  │
   │   │      via libssl.so.3               │      egress → api.anthropic.com      │
   │   │ cgroup 358639                      │                                      │
   │   └───────────────┬────────────────────┘                                     │
   │                   │  SSL_write / SSL_read uprobe on the POD's libssl,         │
   │                   │  reached from the node via /proc/<pid>/root/.../libssl.so.3 │
   │                   ▼                                                           │
   │        ┌───────────────────────┐                                             │
   │        │  agentprov-sensor      │  execve · openat · connect  (system)       │
   │        │  (node DaemonSet, eBPF)│  SSL_write body            (model intent)   │
   │        └───────────┬───────────┘  SSL_read body  (partial — see caveats)     │
   │                    │  sandbox bind-cgroup: cgroup 358639 → run (k8s_cgroup,   │
   │                    │  confidence 0.8) + pod metadata (ns / name / uid / image)│
   └────────────────────┼─────────────────────────────────────────────────────────┘
                        ▼
       ┌──────────────────────────────────────────────────────────┐
       │  run "claude-demo"  — one verifiable graph                  │
       │  ingest (AGENTPROV_TLS_CAPTURE_BODY=1) + graph materialize-llm │
       │  substrate lens: profile → node sensor → pod → cgroup → run   │
       └──────────────────────────────────────────────────────────┘
```

The trick that makes model intent work node-side: the sensor attaches the libssl
uprobe by **inode**, so pointing `AGENTPROV_SSL_LIB` at the pod's own
`/proc/<pid>/root/usr/lib/.../libssl.so.3` captures the pod's TLS plaintext from
the node — no image change, satisfying the roadmap's "TLS symbols resolvable from
the node/rootfs".

---

## 4. What each lens shows

| Lens | Shows |
|---|---|
| **Substrate** ⭐ | `k8s-daemonset` profile → node sensor → pod (`default/claude-agent`, its cgroup) → scope (`k8s_cgroup`, 0.8) → run |
| **Agent intent** | LLM `llm_call` nodes with the real prompt (and response, when a read is captured) — `model: claude-sonnet-5` / `deepseek-*` |
| **Network-egress** | connects to the LLM API IPs (IP-only — domain resolution is v0.8) |
| **Process** | the `python3 agent.py` process tree |
| **Trust-origin / Sandbox-boundary** | trust tiers (kernel-observed vs k8s-asserted vs correlation), boundary crossings |

---

## 5. View it (no VM needed)

This folder ships the **signed, replayable bundle** of a real capture (with a real
DeepSeek completion captured node-side). Import verifies the DSSE attestation:

```sh
agentprov --data-dir /tmp/sub-view init
agentprov --data-dir /tmp/sub-view forensics import \
  demo/k8s-substrate/run-claude-demo.forensics.json.gz \
  --pub-key demo/k8s-substrate/attestation.pub          # tamper => refused
agentprov --data-dir /tmp/sub-view graph verify --run claude-demo   # → status=ok, errors=0
agentprov --data-dir /tmp/sub-view dashboard serve                  # run "claude-demo"
```

## 6. Re-capture it (needs the VM)

Single-node k3s/k8s + Docker, on the node as root. Real completions need keys in
an `agent-keys` secret (`DEEPSEEK_API_KEY` / `ANTHROPIC_API_KEY`); without them the
calls 401 but the request bodies are still captured.

```sh
AGENTPROV=./agentprov SENSOR=./agentprov-sensor \
DEEPSEEK_API_KEY=... \
  bash scripts/demo_k8s_substrate.sh
# serves the dashboard; open the URL, run "claude-demo", start on the Substrate lens.
```

---

## 7. Honesty notes

- **Model intent is a partial layer node-side.** `SSL_write` (requests/prompts) is
  captured reliably; `SSL_read` (responses) only intermittently — the HTTP
  response head reassembly drops chunked / HTTP-2 reads that don't land in the
  first `SSL_read` return. So prompts are consistently present, completions are
  hit-or-miss. This is a known v0.8 read-side hardening item, not a substrate bug.
  Full bodies are stored only with `AGENTPROV_TLS_CAPTURE_BODY=1` (default keeps a
  sha256 + short preview, since prompt/response text is sensitive).
- **Egress is IP-only.** `connect()` sees the IP; the domain lives in the TLS/HTTP
  `Host` header (HPACK-compressed under HTTP/2), so the egress lens shows IPs, not
  `api.deepseek.com`. Domain resolution is v0.8.
- **Confidence tier, not certainty.** Passive cgroup attribution is `k8s_cgroup`
  confidence 0.8 (vs record's kernel-verified 1.0) — the honest cost of not
  wrapping the workload.
