# Grok codebase-exfil demo — one word in, whole codebase out (blocked)

**A real AI coding CLI (`@xai-official/grok` 0.2.93), asked only to "reply with one
word", bundles the entire repository — including files marked DO NOT READ — and
POSTs it to its vendor's session-trace store. AgentProvenance witnesses it at the
kernel, captures the egress, and BLOCKS every upload. One signed, replayable graph.**

This is the observe-**and-enforce** demo: not "another network alert", but a
verifiable divergence between what the user asked, what the model declared, and
what the CLI's runtime actually did — with the exfiltration prevented at the wire.

## The scenario

```
user:  grok -p "Reply with the single word: ok."     (never asked it to read/send anything)
model turn: "ok"  — NO tool call declared                     ← app-context (axis ③)
runtime, unprompted:
   reads .env / SECRET_DO_NOT_READ.md / .claude/settings.local.json   ← kernel (axis ①)
   bundles the whole repo + git history
   POST /storage, POST /traces  (grok-code-session-traces)            ← endpoint (axis ②)
       └─ AgentProvenance policy: DENY — every codebase upload BLOCKED
```

The bundle in this folder is a real capture: kernel-witnessed reads of the
do-not-read files, the model turn declaring only text, and the blocked codebase
uploads (content-addressed, marked `blocked / deny`).

## Honesty note — disclosed force

grok's codebase upload is gated by a **server-controlled flag**. For the account
used here, xAI's server resolved it **OFF**:

```
data capture config resolved  telemetry=true  trace_upload_enabled=false  disable_codebase_upload=true
```

So grok did **not** upload unprompted at capture time — xAI has it disabled for
this account (plausibly after the public report this demo is based on). To
demonstrate the mechanism **and that AgentProvenance blocks it**, the capture proxy
**flips those two flags** in the `/settings` response — and logs the original
server values every time it does. This is a *mechanism* demonstration of a real,
in-binary code path (`trace_upload` / `disable_codebase_upload` /
`grok-code-session-traces`), with the trigger simulated and disclosed — **not** a
claim that grok exfiltrated unprompted on this run. Third-party finding; not
xAI-confirmed.

## How it's captured (Grok is rustls → no libssl uprobe)

Grok's HTTP stack is rustls, so the zero-touch TLS uprobe used for Claude Code
can't read its plaintext. Model intent + egress are captured at a controlled proxy
instead; the kernel eBPF sensor remains the fully-passive independent witness.

- **axis ①** eBPF sensor in grok's cgroup — reads of the sensitive files, execve.
- **axis ②** capture+BLOCK proxy — records the codebase-upload attempts and DENIES
  them; `graph ingest-endpoint` folds them into the graph as `llm_call` +
  blocked data-egress nodes.
- **axis ③** grok harness adapter — `hooks bridge --harness grok` reads grok's own
  `chat_history.jsonl`; the assistant turn with no tool call is the model
  "declaring" only text.

## View it (no VM needed)

```sh
agentprov --data-dir /tmp/grok-view init
agentprov --data-dir /tmp/grok-view forensics import \
  demo/grok-codebase-exfil/run-grok-exfil.forensics.json.gz \
  --pub-key demo/grok-codebase-exfil/attestation.pub        # verifies the signature, then imports
agentprov --data-dir /tmp/grok-view graph verify --run run-grok-exfil    # → status=ok, errors=0
agentprov --data-dir /tmp/grok-view dashboard serve                      # run "run-grok-exfil"
```

## Re-capture it (needs the VM + a Grok login)

`capture/` holds the harness: `make-canary-repo.sh` (synthetic repo, fake secrets,
per-file canaries), `grok-proxy.py` (forward to `cli-chat-proxy.grok.com`, flip the
disclosed flags, BLOCK + dump `/storage`+`/traces`), `capture-grok-full.sh`
(record+sensor + proxy + seal). Requires a Grok CLI login (`grok login
--device-auth`) and the sensor's CAP_BPF. All secrets are synthetic; nothing real
leaves the box (the uploads are blocked).

## Rigor

- Synthetic repo, clearly-fake secrets, isolated VM, uploads blocked (no real egress).
- Per-file canary strings → proof of which files entered the (blocked) upload.
- The `trace_upload` force is logged with the server's original values, every time.
- Pin: grok 0.2.93, binary sha256, capture timestamp; third-party finding re-captured.
