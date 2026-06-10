#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-snapshot}"
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
"$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'echo base > hello.txt'
"$BIN" --data-dir "$DATA_DIR" snapshot create "$SESSION_ID" --type directory --path /workspace --name ready
"$BIN" --data-dir "$DATA_DIR" fork ready --count 3
"$BIN" --data-dir "$DATA_DIR" snapshot inspect ready
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
