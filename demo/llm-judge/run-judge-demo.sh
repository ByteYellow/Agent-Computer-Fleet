#!/usr/bin/env bash
# End-to-end LLM-judge demo: import a captured run, judge it with an LLM
# (or the offline fixture), write the verdict back as graph-attached
# signals, and record the judge itself as a provenance run whose own LLM
# calls become llm_call nodes -- the judge is itself audited.
#
# Usage:
#   ./run-judge-demo.sh                 # judge the snake-supply-chain bundle
#   ./run-judge-demo.sh --run <run-id> --data-dir <dir>   # judge an existing run
#   AGENTPROV_JUDGE_OFFLINE=1 ./run-judge-demo.sh          # force keyless mode
#
# LLM endpoint comes from the same env contract as the other demos:
#   ${AGENTPROV_DEMO_ENV_FILE:-~/.agentprov-demo/deepseek-claude.env}
#   (ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN/ANTHROPIC_API_KEY +
#    AGENTPROV_DEMO_MODEL). Without a token the demo degrades to an offline
#   fixture verdict so the pipeline always completes.
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$DEMO_DIR/../.." && pwd)"

TARGET_RUN=""
DATA_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run) TARGET_RUN="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

ENV_FILE="${AGENTPROV_DEMO_ENV_FILE:-$HOME/.agentprov-demo/deepseek-claude.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_FILE"
fi

AP="${AGENTPROV_BIN:-}"
if [[ -z "$AP" ]]; then
  AP="$DEMO_DIR/.build/agentprov"
  mkdir -p "$DEMO_DIR/.build"
  (cd "$REPO_DIR" && go build -o "$AP" ./cmd/agentprov)
fi

WORK="$DEMO_DIR/.judge-work"
rm -rf "$WORK" && mkdir -p "$WORK/judge-cwd"

if [[ -z "$DATA_DIR" ]]; then
  DATA_DIR="$WORK/state"
  echo "==> importing snake-supply-chain bundle into fresh store"
  "$AP" --data-dir "$DATA_DIR" forensics import --json \
    "$DEMO_DIR/../snake-supply-chain/run-snake-supervised.forensics.json" >/dev/null
  TARGET_RUN="${TARGET_RUN:-run-snake-supervised}"
fi
[[ -n "$TARGET_RUN" ]] || { echo "--run is required with --data-dir" >&2; exit 2; }

OFFLINE_FLAG=()
if [[ -n "${AGENTPROV_JUDGE_OFFLINE:-}" ]]; then OFFLINE_FLAG=(--offline); fi

echo "==> judging $TARGET_RUN (the judge itself runs under 'agentprov record')"
VERDICT="$WORK/verdict.json"; SIGNALS="$WORK/signals.json"; TLS="$WORK/judge-tls.jsonl"
MANIFEST="$WORK/judge-record.json"
(cd "$WORK/judge-cwd" && \
  AGENTPROV_BIN="$AP" AGENTPROV_DATA_DIR="$DATA_DIR" \
  "$AP" --data-dir "$DATA_DIR" record --json -- \
    python3 "$DEMO_DIR/judge.py" --run "$TARGET_RUN" \
      --verdict-out "$VERDICT" --signals-out "$SIGNALS" --tls-out "$TLS" \
      "${OFFLINE_FLAG[@]}" > "$MANIFEST")

# record's --json manifest follows the wrapped command's own stdout; take the JSON tail.
JUDGE_RUN=$(python3 -c "import json,sys; s=open(sys.argv[1]).read(); m=json.loads(s[s.index('{'):]); print(m.get('run_id') or m.get('RunID'))" "$MANIFEST")
JUDGE_PROC=$(python3 -c "import json,sys; s=open(sys.argv[1]).read(); m=json.loads(s[s.index('{'):]); print(m.get('process_id') or m.get('ProcessID') or '')" "$MANIFEST")
echo "    judge run: $JUDGE_RUN"

if [[ -s "$TLS" ]]; then
  echo "==> attaching the judge's own LLM calls to its provenance run"
  AGENTPROV_TLS_CAPTURE_BODY=1 "$AP" --data-dir "$DATA_DIR" telemetry ingest-jsonl \
    --format native --run "$JUDGE_RUN" --process "$JUDGE_PROC" --file "$TLS" --json >/dev/null
  "$AP" --data-dir "$DATA_DIR" graph materialize-llm --run "$JUDGE_RUN" >/dev/null || true
else
  echo "    (offline mode: no LLM exchange to attach)"
fi

echo "==> importing verdict as signals on $TARGET_RUN"
"$AP" --data-dir "$DATA_DIR" signal import --run "$TARGET_RUN" --file "$SIGNALS" --json >/dev/null

echo
echo "================ verdict ================"
python3 -c "
import json, sys
v = json.load(open(sys.argv[1]))
print('run     :', v['run_id'])
print('verdict :', v['verdict']['verdict'], ' confidence:', v['verdict'].get('confidence'))
print('coverage:', v['coverage'])
print('judge   :', v['judge']['mode'], v['judge'].get('model') or '')
print('summary :', v['verdict'].get('summary'))
for f in v['verdict'].get('findings') or []:
    print('  - [%s] %s  evidence=%s' % (f.get('severity'), f.get('claim'), ','.join(f.get('evidence_ids') or [])))
" "$VERDICT"
echo "========================================="
echo
echo "==> verdict signals now attached to the target run:"
"$AP" --data-dir "$DATA_DIR" signals list --run "$TARGET_RUN" --dimension quality || true
echo
echo "==> the judge's own audited run:"
"$AP" --data-dir "$DATA_DIR" graph lens --run "$JUDGE_RUN" --lens agent-intent | head -20 || true
echo
echo "inspect further:"
echo "  $AP --data-dir $DATA_DIR ai call get_signals --input '{\"run\":\"$TARGET_RUN\"}'"
echo "  $AP --data-dir $DATA_DIR graph lens --json --run $JUDGE_RUN --lens agent-intent"
echo "  $AP --data-dir $DATA_DIR dashboard serve   # signals panel + judge run DAG"
