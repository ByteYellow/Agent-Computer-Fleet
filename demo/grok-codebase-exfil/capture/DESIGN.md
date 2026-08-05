# Grok codebase-exfil demo — design (base, no key)

## The finding (third-party, to be re-captured by AgentProvenance)
`@xai-official/grok@0.2.93` (official xAI CLI, Rust) is reported to package the whole
repo + git history into `before_/after_codebase` git bundles and upload them to
`api.x.ai/v1/upload/storage` + `/v1/traces` (→ GCS `grok-code-session-traces`),
independent of what the agent was asked or which files it "read". Confirmed present
in the binary strings: `before_codebase`, `after_codebase`, `git bundle`,
`grok-code-session-traces`, `GROK_STORAGE_MODE`, `GROK_CLAUDE_*_ENABLED`.
Strings prove the code paths EXIST; only a live capture proves runtime behavior.

## Capture architecture (rustls-aware)
Grok's HTTP stack is **rustls** (not openssl), so the libssl `SSL_write` uprobe does
NOT see its plaintext. So axis ② is captured at a **controlled endpoint**, not by uprobe.

- **Axis ① — kernel, fully passive (unchanged):** eBPF sensor in the grok cgroup
  witnesses, independently: `openat`/read of `.env` / `.aws/credentials` /
  `.claude/*` (secret_read), `write` of the `*codebase*.tar`/bundle (file_write),
  `connect()` to the endpoint (network_connect). This is the zero-touch witness.
- **Axis ② — model intent + exfil payload — controlled endpoint:** Grok is pointed
  at a local fake xAI via `XAI_API_BASE_URL`. The fake answers `/v1/chat/completions`
  with a one-word, no-tool-call reply (so Grok proceeds), and ACCEPTS + dumps the
  `/v1/upload/storage` + `/v1/traces` bodies (the git bundle). Topology A: chat AND
  upload are on the same api.x.ai base, so one endpoint covers both; nothing leaves
  the VM.
- **Axis ③ — app-context:** Grok's session is backend-synced via `/v1/traces`, so its
  app-context rides out through the same endpoint. Classifying the captured bodies
  (chat = intent, upload/traces = data egress) IS the Grok adapter (phase 2).

## The divergence the graph shows (the whole point)
```
user: "reply with one word"
  model turn (fake): text "ok", NO tool call        ← axis ②
  intent boundary: no file/network effects declared
    runtime (axis ①, kernel-witnessed):
      read .env / .aws/credentials / .claude/settings.local.json   (secret_read)
      write before_codebase / after_codebase bundle                (file_write)
      connect + POST /v1/upload/storage  (git bundle of the repo)  (network_connect)
        └─ declared_vs_effect_mismatch / intent_coverage_gap
```

## Phasing
- **BASE (these scripts, no key, no new code):** canary repo + fake-xai endpoint +
  record/sensor capture + materialize + intent-diff + verify + sign + export. Produces
  the kernel evidence (axis ①) and the endpoint body-dumps (raw axis ②/③ material).
  Without a Grok adapter the undeclared effects surface as `intent_coverage_gap` —
  already a valid "executed_without_intent" story.
- **PHASE 2 (adapter, new code):** ingest the endpoint-captured `/v1/chat` +
  `/v1/upload`/`/v1/traces` bodies into `llm_call` (intent) + a data-egress node, so
  the graph shows the full three-axis three-way divergence, and reuse for any
  rustls/Rust agent (a growing class).
- **BONUS (real xAI key):** makes the chat call + upload actually succeed against real
  xAI — not required; the attempt + payload are captured either way.

## Rigor checklist (public demo)
- Synthetic repo, clearly-fake secrets, isolated VM, no real egress (fake endpoint).
- Pin: grok version (0.2.93) + binary sha256 + fake endpoint responses + timestamps.
- Canary strings in each "do-not-read" file → grep them in the captured upload to prove
  which files were exfiltrated (kernel read + payload content, two independent sources).
- Present as a third-party finding re-captured by AgentProvenance, NOT xAI-confirmed.
- Distinguish default-on vs experiment-toggled (`GROK_STORAGE_MODE`) vs later server-off.
- Facts only; no product motive in the technical conclusion.

## First run is a DISCOVERY run
The fake xAI logs every request (method/path/headers/body). The first capture tells us
Grok's real request paths + schema (chat path, whether http:// base is accepted or it
forces https + a trusted CA, upload path/format) — refine the fake from that, then the
clean capture.
