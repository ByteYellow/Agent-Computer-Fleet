#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-provenance}"
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

echo "== api workflow"
"$BIN" --data-dir "$DATA_DIR" api write-file "$SESSION_ID" --path notes.txt --content 'hello provenance' --tool-call-id tool-write-demo
"$BIN" --data-dir "$DATA_DIR" api export-artifact "$SESSION_ID" --path notes.txt --name notes.txt --tool-call-id tool-artifact-demo
"$BIN" --data-dir "$DATA_DIR" api call "$SESSION_ID" --module shell --function exec --command 'echo second-line >> notes.txt' --tool-call-id tool-call-demo

echo "== telemetry"
"$BIN" --data-dir "$DATA_DIR" telemetry list --session "$SESSION_ID"

echo "== provenance trace"
"$BIN" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix

echo "== forensics bundle"
BUNDLE="$("$BIN" --data-dir "$DATA_DIR" forensics export run-demo-bugfix)"
echo "$BUNDLE"
sed -n '1,80p' "$BUNDLE"

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
