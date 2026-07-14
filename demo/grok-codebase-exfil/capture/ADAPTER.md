# Phase-2: Grok endpoint adapter (draft, informed by the real discovery run)

## Job
Take the endpoint-captured traffic (fake-xai dump dir, or a mitmproxy flow) + the local
session store, and emit into the SAME graph model the other axes use — so no lens/intent
change is needed. This is the per-agent glue; the capture mechanism ("ingest model traffic
from a controlled endpoint") is general (reusable for any rustls/Rust agent).

## Classify captured requests by path (all confirmed from the real run)
| Path | Meaning | Emit |
|---|---|---|
| `/v1/chat/completions` | the turn — grok's system prompt + `<user_query>`; response streamed SSE | `llm_call` (request+response objects). Response = text, **no tool_calls** → the "declared" intent is *nothing but text* |
| `/responses` | session-title generation (secondary model call) | `llm_call` (secondary) or skip |
| `/v1/upload/storage`, `/v1/traces` | **codebase / session-trace egress** (git bundle) | `data_egress` node: objectify the body (content-addressed), flag if it is a `# v2 git bundle`, canary-match against the repo |
| `api.mixpanel.com/track` | analytics | `data_egress` (analytics), lower severity |

## Emit shape (reuses existing tables/nodes)
- `/chat` + `/responses` → `llm_call` nodes via the existing llm_message/objectify path
  (like MaterializeLLMCalls, but source = endpoint capture not TLS uprobe). The turn
  declares no tool_call → the run has an intent contract that is "text-only, no file/net".
- `/v1/upload|traces` → a new `data_egress` node (objectified payload + dest host + size +
  canary hits). This is the effect with no declared intent.
- App-context (③): read `~/.grok/sessions/<url-encoded-workspace>/` (+ session_search.sqlite)
  for grok's own session view — optional enrichment.

## Then the existing intent layer does the rest
`intent.Materialize`: the model turn declared only text; the kernel (axis ①) witnessed
`secret_read` of `.env`/`.aws`/`.claude` + the egress node carries the git bundle →
`declared_vs_effect_mismatch` (effect violates the text-only contract) and/or
`intent_coverage_gap` (egress with no covering intent). Two independent sources
(kernel read + endpoint payload content) corroborate.

## Where it plugs in
New `internal/endpointbridge` (mirrors `internal/hooksbridge`): `Ingest(db, dumpDir, run)`
walking the dump's `*.meta.json`+`*.body.bin`, classifying by path, objectifying bodies,
writing `llm_call` + `data_egress` nodes. A `graph ingest-endpoint --run --dump <dir>` CLI,
like `graph harvest-transcripts`.

## Build order (honest)
- **Buildable now** (we have real bodies): the `/chat`+`/responses` → `llm_call` half
  (the "model declared only text, no tool call" side), + the kernel-witness side (axis ①,
  once capture-grok.sh runs under sensor).
- **Blocked on the upload firing**: the `data_egress` (git bundle) half needs a real
  `/v1/upload`/`/v1/traces` body — which is ZDR/account-gated (see grok-exfil-demo memory).
  Get it by faking an upload-enabled account config, or a real key + non-ZDR account via
  mitmproxy. Until then the demo shows: read-the-secrets (kernel) + phones-home + the
  upload code path is present-but-gated — a valid, honest partial.
