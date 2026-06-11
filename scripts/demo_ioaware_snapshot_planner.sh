#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ACFCTL="${ACFCTL:-./acfctl}"
DATA_DIR="${DATA_DIR:-.acf-demo-ioaware}"

go build -o "$ACFCTL" ./cmd/acfctl
rm -rf "$DATA_DIR"
"$ACFCTL" --data-dir "$DATA_DIR" init >/dev/null

lease_id=$("$ACFCTL" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)
session_id=$("$ACFCTL" --data-dir "$DATA_DIR" session create --lease "$lease_id")
cleanup() {
  "$ACFCTL" --data-dir "$DATA_DIR" session rm "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$ACFCTL" --data-dir "$DATA_DIR" exec "$session_id" --stream -- sh -lc '
  mkdir -p .git/objects/aa node_modules/pkg .venv/lib/site-packages/pkg
  echo object > .git/objects/aa/obj
  echo module > node_modules/pkg/index.js
  echo venv > .venv/lib/site-packages/pkg/mod.py
' >/dev/null

"$ACFCTL" --data-dir "$DATA_DIR" snapshot create "$session_id" --type directory --path /workspace --name ready
"$ACFCTL" --data-dir "$DATA_DIR" snapshot inspect ready
"$ACFCTL" --data-dir "$DATA_DIR" snapshot plan ready

echo "expecting_io_budget_reject=true"
if ACF_IO_MAX_FANOUT_PER_LOWER=1 "$ACFCTL" --data-dir "$DATA_DIR" fork ready --count 2; then
  echo "unexpected_fork_success=true"
  exit 1
else
  echo "io_budget_reject_observed=true"
fi

"$ACFCTL" --data-dir "$DATA_DIR" fork ready --count 1
"$ACFCTL" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix
