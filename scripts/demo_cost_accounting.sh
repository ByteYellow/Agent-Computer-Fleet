#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-cost}"
BIN="./acfctl"
SESSION_ID=""

cleanup() {
  if [[ -n "$SESSION_ID" ]]; then
    "$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN"
}
trap cleanup EXIT

GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build ./cmd/acfctl
"$BIN" --data-dir "$DATA_DIR" init
LEASE_ID="$("$BIN" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)"
SESSION_ID="$("$BIN" --data-dir "$DATA_DIR" session create --lease "$LEASE_ID")"
"$BIN" --data-dir "$DATA_DIR" api call "$SESSION_ID" --command 'echo accounting > cost.txt' --tool-call-id tool-cost-demo
"$BIN" --data-dir "$DATA_DIR" cost sample "$SESSION_ID"
"$BIN" --data-dir "$DATA_DIR" cost show run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" bench overcommit --sessions 20 --idle-ratio 0.8
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
