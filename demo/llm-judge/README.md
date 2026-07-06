# LLM Judge — the judge is itself audited

An external LLM reads a captured run's **full trajectory** and delivers a
structured security verdict; the verdict is written back into the store as
graph-attached signals. The twist: the judge itself runs under
`agentprov record`, and its own LLM requests/responses are attached to the
judge's provenance run as `tls_write`/`tls_read` evidence and materialized
into `llm_call` nodes — so "which LLM call produced this verdict" is itself
verifiable provenance.

```text
target run (e.g. snake-supply-chain)          judge run (recorded)
  EvalContext: ALL runtime events  ──────▶  judge.py
  lens summaries / risks / verify           │  chunks trajectory, calls LLM
                                            │  every request/response retained
  signals (quality dimension)  ◀────────────┘  sha256 + tls evidence
    llm_judge.verdict / llm_judge.finding.*     └─▶ llm_call nodes in the
    evidence: coverage + judge attestation           judge run's own DAG
```

## Run it

One file, stdlib only — `judge.py run` orchestrates everything (builds the
binary if `AGENTPROV_BIN` is unset, imports the bundle, re-executes itself
as `judge.py judge` under `agentprov record`, attaches the LLM evidence,
imports the verdict):

```sh
python3 judge.py run                            # judge the snake bundle end to end
python3 judge.py run --offline                  # keyless: offline fixture verdict
python3 judge.py run --run <id> --data-dir <dir>  # judge any existing run
```

## Bring your own LLM

This demo is a *pattern*, not a product binding: any external LLM can act as
the security judge, because the judge only needs (a) an HTTP chat endpoint
and (b) the evidence contracts below. Two wire protocols cover essentially
every hosted or local model; pick one with environment variables (the shared
demo env file `~/.agentprov-demo/deepseek-claude.env` is auto-loaded):

| protocol | endpoint env | key env | examples |
|---|---|---|---|
| `anthropic` | `ANTHROPIC_BASE_URL` (default api.anthropic.com) | `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_API_KEY` | Claude, Anthropic-compatible proxies |
| `openai` | `OPENAI_BASE_URL` (default api.openai.com) | `OPENAI_API_KEY` | OpenAI, Qwen, Moonshot, vLLM, Ollama (`http://localhost:11434`) |
| `openai` @ deepseek | — | `DEEPSEEK_API_KEY` (shortcut) | DeepSeek native API |

`AGENTPROV_JUDGE_PROVIDER=anthropic|openai` forces the protocol when several
keys are set; `AGENTPROV_JUDGE_MODEL` picks the model. Whichever provider is
used, the judge's requests/responses are sha256-attested in the verdict and
attached to the judge run as tls evidence — swapping the model never weakens
the audit trail. Without any token the demo completes in offline fixture
mode (verdict derived from stored risk signals, clearly labeled).

## Extensibility contract

- **No event-type filter anywhere.** `judge.py` serializes every
  `runtime_event` in the EvalContext verbatim (type-agnostic payload
  compaction only). When the sensor grows new capture dimensions
  (`dns_query`, `setuid`, TLS plaintext, ...), they flow into the judge
  prompt with zero changes here.
- **Full trajectory, budgeted.** If the trajectory exceeds the per-call
  budget it is chunked chronologically and map-reduced (per-chunk
  observations → final verdict). Nothing is silently dropped; the verdict
  records `coverage` (events_total / chunks / mode).
- **Self-audit deepens automatically.** On this macOS path the judge's LLM
  exchange is app-asserted (`telemetry ingest-jsonl --format native`). On a
  Linux host with the eBPF sensor + SSL uprobe, the *same* HTTP call is
  captured at the kernel boundary instead — the demo's trust level upgrades
  with observability depth, no demo changes.

## Contracts used (all pre-existing)

| step | surface |
|---|---|
| read evidence | `signal context --run` (EvalContext), `ai call verify_run/list_risks/get_signals`, `graph lens --json` |
| write verdict | `signal import --run --file` → `signals` table, quality dimension (note: the plural `signal import-batch` only validates, it does not persist) |
| judge self-audit | `record --json -- python3 judge.py judge ...`, `telemetry ingest-jsonl --format native`, `graph materialize-llm` |

Known gap (honest): imported quality signals show up in `signals list`,
`ai call get_signals`, and the dashboard signals panel, but `graph lens
--lens security` currently renders only `risk_signals`-table rows — the
verdict is graph-referenced (`graph_ref_kind=run`) but not yet a lens node.
