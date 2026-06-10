#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-egress}"
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

echo "== init and configure allowlist"
"$BIN" --data-dir "$DATA_DIR" init
"$BIN" --data-dir "$DATA_DIR" egress allow example.com

echo "== create proxied session"
LEASE_ID="$("$BIN" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)"
SESSION_ID="$("$BIN" --data-dir "$DATA_DIR" session create --lease "$LEASE_ID")"
"$BIN" --data-dir "$DATA_DIR" egress status

echo "== verify sandbox proxy environment"
"$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'test -n "$HTTP_PROXY" && echo proxy=$HTTP_PROXY'

echo "== allowed HTTP request through proxy"
"$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'wget -qO- http://example.com >/tmp/example.html && test -s /tmp/example.html && echo allowed_via_proxy'

echo "== direct egress bypass is blocked by internal sandbox network"
if "$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy wget -T 3 -qO- http://example.com >/dev/null'; then
  echo "direct egress unexpectedly succeeded" >&2
  exit 1
fi

echo "== metadata IP denied by proxy policy"
if "$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'wget -qO- http://169.254.169.254/latest/meta-data'; then
  echo "metadata request unexpectedly succeeded" >&2
  exit 1
fi

echo "== credential injection is recorded without raw secret"
"$BIN" --data-dir "$DATA_DIR" credential inject --run run-demo-bugfix --session "$SESSION_ID" --name demo-token --host example.com --value 'Bearer SHOULD_NOT_APPEAR'
if "$BIN" --data-dir "$DATA_DIR" telemetry list --run run-demo-bugfix | grep -q 'SHOULD_NOT_APPEAR'; then
  echo "raw secret leaked into telemetry" >&2
  exit 1
fi
if grep -R 'SHOULD_NOT_APPEAR' "$DATA_DIR/workspaces" "$DATA_DIR/logs" "$DATA_DIR/acf.db" >/dev/null 2>&1; then
  echo "raw secret leaked outside host secret store" >&2
  exit 1
fi

echo "== policy decisions"
"$BIN" --data-dir "$DATA_DIR" policy decisions --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" telemetry list --run run-demo-bugfix

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
