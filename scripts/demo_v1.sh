#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo}"
BIN="./acfctl"
SESSION_ID=""

cleanup() {
  if [[ -n "$SESSION_ID" ]]; then
    "$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN"
}
trap cleanup EXIT

echo "== build acfctl"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build ./cmd/acfctl

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

echo "== create lease/session"
LEASE_ID="$("$BIN" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)"
SESSION_ID="$("$BIN" --data-dir "$DATA_DIR" session create --lease "$LEASE_ID")"
echo "lease=$LEASE_ID"
echo "session=$SESSION_ID"

echo "== inspect session"
"$BIN" --data-dir "$DATA_DIR" session inspect "$SESSION_ID"

echo "== demo_streaming_terminal"
"$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'echo hello > hello.txt && cat hello.txt'

echo "== demo_snapshot_fanout"
"$BIN" --data-dir "$DATA_DIR" snapshot create "$SESSION_ID" --type directory --path /workspace --name ready
"$BIN" --data-dir "$DATA_DIR" snapshot list
"$BIN" --data-dir "$DATA_DIR" snapshot inspect ready
"$BIN" --data-dir "$DATA_DIR" fork ready --count 3

echo "== demo_best_of_forks"
"$BIN" --data-dir "$DATA_DIR" attempt best-of --snapshot ready \
  --strategy "pass::test -f hello.txt" \
  --strategy "fail::test -f missing.txt"

echo "== demo_snapshot_stack"
STACK_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" snapshot stack --task examples/tasks/bugfix.yaml)"
echo "$STACK_OUTPUT"
STACK_READY="$(echo "$STACK_OUTPUT" | awk -F= '/^ready_snapshot=/{print $2}')"
"$BIN" --data-dir "$DATA_DIR" snapshot inspect "$STACK_READY"

echo "== demo_metadata_egress_quarantine"
"$BIN" --data-dir "$DATA_DIR" policy test examples/events/metadata-egress.jsonl
"$BIN" --data-dir "$DATA_DIR" policy decisions --run run-demo-bugfix

echo "== demo_cost_per_run"
"$BIN" --data-dir "$DATA_DIR" cost show run-demo-bugfix

echo "== demo_active_cpu_overcommit"
"$BIN" bench overcommit --sessions 20 --idle-ratio 0.8

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session stop "$SESSION_ID"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
