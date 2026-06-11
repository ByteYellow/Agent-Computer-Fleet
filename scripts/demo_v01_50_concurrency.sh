#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ACFCTL="${ACFCTL:-./acfctl}"
DATA_DIR="${DATA_DIR:-.acf-demo-50}"
SESSIONS="${SESSIONS:-50}"
BURST_MAX_INFLIGHT="${BURST_MAX_INFLIGHT:-4}"
LISTEN="${LISTEN:-127.0.0.1:18574}"
DAEMON_URL="http://$LISTEN"

go build -o "$ACFCTL" ./cmd/acfctl
rm -rf "$DATA_DIR"
"$ACFCTL" --data-dir "$DATA_DIR" init >/dev/null
ACF_BURST_MAX_INFLIGHT="$BURST_MAX_INFLIGHT" "$ACFCTL" --data-dir "$DATA_DIR" daemon serve --listen "$LISTEN" --sample-interval 0 >"$DATA_DIR/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 50); do
  if curl -fsS "$DAEMON_URL/v1/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

session_ids=()
cleanup() {
  for session_id in "${session_ids[@]:-}"; do
    "$ACFCTL" --daemon-url "$DAEMON_URL" session rm "$session_id" >/dev/null 2>&1 || true
  done
  kill "$daemon_pid" >/dev/null 2>&1 || true
  wait "$daemon_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "creating_sessions=$SESSIONS"
for i in $(seq 1 "$SESSIONS"); do
  lease_id=$("$ACFCTL" --daemon-url "$DAEMON_URL" lease create --task examples/tasks/bugfix.yaml)
  session_id=$("$ACFCTL" --daemon-url "$DAEMON_URL" session create --lease "$lease_id")
  session_ids+=("$session_id")
  if (( i % 10 == 0 )); then
    echo "created=$i"
  fi
done

echo "running_light_tool_phase"
rm -rf "$DATA_DIR/results"
mkdir -p "$DATA_DIR/results"
for session_id in "${session_ids[@]}"; do
  (
    if "$ACFCTL" --daemon-url "$DAEMON_URL" exec "$session_id" -- sh -lc 'printf ok >/workspace/result.txt; sleep 2' >/dev/null 2>"$DATA_DIR/results/$session_id.err"; then
      echo ok >"$DATA_DIR/results/$session_id.status"
    else
      echo rejected >"$DATA_DIR/results/$session_id.status"
    fi
  ) &
done
wait
admitted=$(grep -l '^ok$' "$DATA_DIR"/results/*.status 2>/dev/null | wc -l | tr -d ' ')
rejected=$(grep -l '^rejected$' "$DATA_DIR"/results/*.status 2>/dev/null | wc -l | tr -d ' ')
echo "burst_max_inflight=$BURST_MAX_INFLIGHT admitted_exec=$admitted rejected_exec=$rejected"

echo "sampling_cost"
for session_id in "${session_ids[@]}"; do
  "$ACFCTL" --data-dir "$DATA_DIR" cost sample "$session_id" >/dev/null || true
done

ACF_BURST_MAX_INFLIGHT="$BURST_MAX_INFLIGHT" "$ACFCTL" --daemon-url "$DAEMON_URL" scheduler status
"$ACFCTL" --data-dir "$DATA_DIR" cost show run-demo-bugfix
"$ACFCTL" --data-dir "$DATA_DIR" telemetry list --run run-demo-bugfix --type burst_reject
if [[ "$rejected" != "0" ]]; then
  burst_guard_enforced=true
else
  burst_guard_enforced=false
fi
echo "sessions=$SESSIONS completed=true burst_guard_enforced=$burst_guard_enforced"
