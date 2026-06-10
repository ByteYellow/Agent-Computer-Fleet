#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-preview}"
BIN="./acfctl"
SESSION_ID=""
PORT_ID=""
PREVIEW_URL=""

cleanup() {
  if [[ -n "$PORT_ID" ]]; then
    "$BIN" --data-dir "$DATA_DIR" port close "$PORT_ID" >/dev/null 2>&1 || true
  fi
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

echo "== start sandbox HTTP service"
"$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'nohup sh -c "while true; do printf \"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npreview-ok\" | nc -l -p 8000; done" >/tmp/acf-httpd.log 2>&1 &'

echo "== expose preview URL"
EXPOSE_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" port expose "$SESSION_ID" 8000)"
echo "$EXPOSE_OUTPUT"
PORT_ID="$(echo "$EXPOSE_OUTPUT" | sed -n 's/.*port_id=\([^ ]*\).*/\1/p')"
PREVIEW_URL="$(echo "$EXPOSE_OUTPUT" | sed -n 's/.*preview_url=\([^ ]*\).*/\1/p')"

if [[ -z "$PORT_ID" || -z "$PREVIEW_URL" ]]; then
  echo "failed to parse port expose output" >&2
  exit 1
fi

echo "== fetch preview URL"
BODY=""
for _ in $(seq 1 20); do
  BODY="$(curl -fsS "$PREVIEW_URL" 2>/dev/null || true)"
  if [[ "$BODY" == "preview-ok" ]]; then
    break
  fi
  sleep 0.25
done
if [[ "$BODY" != "preview-ok" ]]; then
  echo "unexpected preview body: $BODY" >&2
  exit 1
fi
echo "body=$BODY"

echo "== list preview proxies"
"$BIN" --data-dir "$DATA_DIR" port list

echo "== close preview proxy"
"$BIN" --data-dir "$DATA_DIR" port close "$PORT_ID"
sleep 0.25
if curl -fsS "$PREVIEW_URL" >/dev/null 2>&1; then
  echo "preview proxy still reachable after close" >&2
  exit 1
fi
PORT_ID=""

echo "== cleanup session"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""

echo "demo_preview_url ok"
