#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-policy}"
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

echo "== seed secret-like path"
"$BIN" --data-dir "$DATA_DIR" api write-file "$SESSION_ID" --path .env --content 'TOKEN=demo' --tool-call-id tool-write-secret

echo "== trigger runtime policy"
"$BIN" --data-dir "$DATA_DIR" api read-file "$SESSION_ID" --path .env --tool-call-id tool-read-secret

echo "== session state after enforcement"
"$BIN" --data-dir "$DATA_DIR" session inspect "$SESSION_ID"

echo "== policy decisions"
"$BIN" --data-dir "$DATA_DIR" policy decisions --run run-demo-bugfix
