# Grok exfil demos — two signed captures of a real AI coding CLI

This folder holds **two real, signed, replayable AgentProvenance captures** of
`@xai-official/grok` 0.2.93 (the exact version the public repro
[`cereblab/grok-build-exfil-repro`](https://github.com/cereblab/grok-build-exfil-repro)
pins). Each is a content-addressed graph you can import and verify offline.

| Bundle | What it caught | Reproducible today? |
|---|---|---|
| **`run-grok-exfil`** | Route ②: the CLI bundles the **whole repo + git history** and POSTs it to the vendor session-trace store (`grok-code-session-traces`) — every upload **BLOCKED**. | **No — not reproducible on 07-15** (appears disabled server-side; see Status). Historical capture. |
| **`run-grok-3routes`** | Route ①: grok reads `.env` / `SECRET_DO_NOT_READ.md` / `.claude/` and the **secrets land in the model request** (`/responses`) — 3 canaries proven in-context. Plus telemetry (`/traces`) + product analytics (Mixpanel). | **Yes** — reproducible. |

## Status — codebase upload not reproducible on 2026-07-15 (appears disabled server-side)

The codebase-upload finding (route ②) is **no longer reproducible**, and grok's own
telemetry corroborates that nothing is being uploaded:

- **2026-07-15:** ~10 re-capture attempts with the version the public repro pins
  (0.2.93, build `f00f96316d`), the same backend (`cli-chat-proxy.grok.com`), the
  disclosed `/settings` flag-flip **confirmed applied**, a **brand-new never-uploaded
  workspace**, and even a forced *bundle-absent* (404 on `GET /bundle/archive`) — grok
  **never POSTs `/storage`**, and a full per-request dump audit finds **no git-bundle
  leaving on any endpoint** (largest upload is the 47 KB model `/responses` call).
- grok's **own** `/sessions/<id>/signals` usage telemetry reports its GCS-upload-queue
  counters (GCS = the `grok-code-session-traces` bucket) as **all zero** —
  `gcsQueueEnqueued: 0`, `gcsQueueUploaded: 0`, `gcsQueuePendingBytes: 0` — i.e. the
  client itself confirms it enqueued nothing to the bucket this run.
- **2026-07-14:** the project's capture log recorded `/storage` git-bundle uploads at
  the time, but that wire log is no longer on hand, and **this committed bundle's graph
  preserved only the `/traces` egress** (an ingest limitation then). So the 07-14 →
  07-15 difference cannot be wire-diffed here.

Honest reading: on 07-15 the codebase does not leave the box, and grok's own queue
counters say so. That it *did* on 07-14 rests on the (now-gone) capture log. **"xAI
disabled it server-side" is the most consistent explanation — a reasonable inference,
not a proven, xAI-confirmed fact.** Treat `run-grok-exfil` as a dated capture of a
behavior that is not currently reproducible.

> Note: `/sessions/<id>/signals` and `/sessions/<id>/turn-deltas` are xAI first-party
> **usage analytics** (turn/latency/lines-of-code counters + the GCS-queue health
> fields above), not the codebase. `/signals` is present in the 07-14 bundle too, so
> it is **not** a new endpoint.

---

## Bundle 1 — `run-grok-exfil` (route ②, historical)

```
user:  grok -p "Reply with the single word: ok."     (never asked it to read/send anything)
model turn: "ok"  — NO tool call declared                     ← app-context (axis ③)
runtime, unprompted:
   reads .env / SECRET_DO_NOT_READ.md / .claude/settings.local.json   ← kernel (axis ①)
   bundles the whole repo + git history
   POST /storage, POST /traces  (grok-code-session-traces)            ← endpoint (axis ②)
       └─ AgentProvenance policy: DENY — every codebase upload BLOCKED
```

**Disclosed force:** grok's codebase upload is gated by a server-controlled flag,
which xAI resolved **OFF** for this account (`trace_upload_enabled=false`,
`disable_codebase_upload=true`). To demonstrate the mechanism **and that
AgentProvenance blocks it**, the capture proxy flips those flags in the `/settings`
response — logging the original server values every time. A *mechanism* demonstration
of a real in-binary code path, trigger simulated and disclosed. Third-party finding;
not xAI-confirmed.

## Bundle 2 — `run-grok-3routes` (route ①, reproducible)

grok was asked to **read** the planted secret files, and the tool captured the
result: all three canaries appear inside the `/responses` **model request body** —
i.e. the secrets reached the model's context. The dashboard's *Outbound Data
Surfaces* renders this as `model_inference / secret / critical`.

**Honesty note:** grok read those files **because the prompt told it to** — this is
the tool correctly *observing secrets-in-context*, **not** covert exfiltration. The
covert "one word → codebase out" story is route ② (bundle 1), which xAI has disabled.

## How it's captured (Grok is rustls → no libssl uprobe)

Grok's HTTP stack is rustls, so the zero-touch TLS uprobe used for Claude Code can't
read its plaintext. Model intent + egress are captured at a controlled proxy instead;
the kernel eBPF sensor remains the fully-passive independent witness.

- **axis ①** eBPF sensor in grok's cgroup — reads of the sensitive files, execve.
- **axis ②** capture+BLOCK proxy — records the egress and DENIES proven-sensitive
  uploads; `graph ingest-endpoint` folds them in as `llm_call` + egress nodes. The
  proxy records the real upstream `host`; the ingest is not hardcoded to any demo.
- **axis ③** grok harness adapter — `hooks bridge --harness grok` reads grok's own
  `chat_history.jsonl`; an assistant turn with no tool call is the model
  "declaring" only text.

## View them (no VM needed)

```sh
agentprov --data-dir /tmp/grok-view init
# Bundle 1 (historical route ②)
agentprov --data-dir /tmp/grok-view forensics import \
  demo/grok-codebase-exfil/run-grok-exfil.forensics.json.gz \
  --pub-key demo/grok-codebase-exfil/attestation.pub
# Bundle 2 (reproducible route ①)
agentprov --data-dir /tmp/grok-view forensics import \
  demo/grok-codebase-exfil/run-grok-3routes.forensics.json.gz \
  --pub-key demo/grok-codebase-exfil/run-grok-3routes.attestation.pub
agentprov --data-dir /tmp/grok-view graph verify --run run-grok-exfil     # → status=ok, errors=0
agentprov --data-dir /tmp/grok-view graph verify --run run-grok-3routes    # → status=ok, errors=0
agentprov --data-dir /tmp/grok-view dashboard serve   # open the "Outbound Data Surfaces" view
```

## Re-capture (needs the VM + a Grok login)

`capture/` holds the harness: `make-canary-repo.sh` (synthetic repo, fake secrets,
per-file canaries), `grok-proxy.py` (forward to `cli-chat-proxy.grok.com`, forward
grok's own OAuth bearer, flip the disclosed flags, record the upstream host, BLOCK +
dump `/storage`+`/traces`), `capture-grok-full.sh` (record+sensor + proxy + seal).
Requires a Grok CLI login (`grok login --device-auth`) and CAP_BPF. All secrets are
synthetic; nothing real leaves the box. **Note:** route ② (codebase upload) no longer
fires — xAI disabled it server-side (see Status); route ① reproduces.

## Rigor

- Synthetic repo, clearly-fake secrets, isolated VM, uploads blocked (no real egress).
- Per-file canary strings → proof of which files entered the (blocked) upload / model context.
- The `trace_upload` force is logged with the server's original values, every time.
- Pin: grok 0.2.93 (`f00f96316d`), capture timestamps; third-party finding re-captured.
- Both bundles DSSE-signed; `graph verify` = `status=ok errors=0`.
