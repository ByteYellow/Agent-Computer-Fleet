#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_100K_DATA_DIR:-.agentprov-100k-accept}"
BIN="${AGENTPROV_ACCEPT_100K_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-100k-bin.XXXXXX")}"
LISTEN="${AGENTPROV_ACCEPT_100K_LISTEN:-127.0.0.1:18576}"
EVENT_COUNT="${AGENTPROV_ACCEPT_100K_EVENTS:-100000}"
REPORT_PATH="${AGENTPROV_ACCEPT_100K_REPORT:-${TMPDIR:-/tmp}/agentprov-100k-pressure-report.json}"
DAEMON_URL="http://$LISTEN"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN"
}
trap cleanup EXIT

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

post_json() {
  local path="$1"
  local body="$2"
  curl -fsS -X POST "$DAEMON_URL$path" -H 'Content-Type: application/json' -d "$body"
}

get_json() {
  local path="$1"
  curl -fsS "$DAEMON_URL$path"
}

now_ns() {
  python3 -c 'import time; print(time.time_ns())'
}

elapsed_ms() {
  python3 -c 'import sys; print(round((int(sys.argv[2])-int(sys.argv[1]))/1_000_000, 3))' "$1" "$2"
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== generate $EVENT_COUNT Falco events"
generate_started_ns="$(now_ns)"
rm -rf "$DATA_DIR" "$DATA_DIR.daemon.log"
mkdir -p "$DATA_DIR"
python3 - <<'PY' "$DATA_DIR/falco-100k.jsonl" "$EVENT_COUNT"
import json
import sys

path = sys.argv[1]
count = int(sys.argv[2])
with open(path, "w", encoding="utf-8") as f:
    for i in range(count):
        row = {
            "time": "2026-01-01T00:00:00Z",
            "rule": "Terminal shell in container",
            "priority": "Notice",
            "output_fields": {
                "evt.type": "execve",
                "proc.pid": 1000 + i,
                "proc.ppid": 1,
                "container.id": "container-pressure",
                "proc.cmdline": "true",
            },
        }
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
generate_finished_ns="$(now_ns)"

echo "== start daemon"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" \
  --sample-interval 0 \
  --spool-interval 0 \
  --spool-limit 1 \
  --spool-max-queued 2 \
  --spool-drop-policy reject \
  --evidence-interval 0 \
  --gc-interval 0 >"$DATA_DIR.daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 80); do
  if get_json /v1/health >/tmp/agentprov-100k-health.json 2>/dev/null; then
    break
  fi
  sleep 0.1
done
HEALTH="$(cat /tmp/agentprov-100k-health.json 2>/dev/null || true)"
assert_contains "$HEALTH" '"status":"ok"'

echo "== enqueue high-volume telemetry batch"
enqueue_started_ns="$(now_ns)"
ENQUEUE_JSON="$(post_json /v1/telemetry/ingest-falco '{"file":"'"$DATA_DIR"'/falco-100k.jsonl","run_id":"run-100k-pressure","queued":true,"no_policy":true}')"
enqueue_finished_ns="$(now_ns)"
assert_contains "$ENQUEUE_JSON" '"schema_version":"agentprovenance.daemon_falco_spool/v1"'
assert_contains "$ENQUEUE_JSON" '"status":"queued"'

echo "== control API remains responsive while high-volume batch is queued"
HEALTH_QUEUED="$(get_json /v1/health)"
assert_contains "$HEALTH_QUEUED" '"status":"ok"'
assert_contains "$HEALTH_QUEUED" '"queued_spool":1'
PRE_QUERY="$(get_json '/v1/telemetry/events?run=run-100k-pressure&limit=5')"
assert_contains "$PRE_QUERY" '"schema_version":"agentprovenance.telemetry_events/v1"'
assert_contains "$PRE_QUERY" '"event_count":0'
QUEUED_HEALTH="$(get_json '/v1/telemetry/producer-health?run=run-100k-pressure')"
assert_contains "$QUEUED_HEALTH" '"schema_version":"agentprovenance.producer_health/v1"'

echo "== drain high-volume telemetry batch"
health_samples="$(mktemp "${TMPDIR:-/tmp}/agentprov-health-latency.XXXXXX")"
query_samples="$(mktemp "${TMPDIR:-/tmp}/agentprov-query-latency.XXXXXX")"
resource_samples="$(mktemp "${TMPDIR:-/tmp}/agentprov-resource.XXXXXX")"
process_json_file="$(mktemp "${TMPDIR:-/tmp}/agentprov-process-result.XXXXXX")"
drain_started_ns="$(now_ns)"
curl -fsS -X POST "$DAEMON_URL/v1/telemetry/spool/process" -H 'Content-Type: application/json' -d '{"limit":1}' >"$process_json_file" &
process_pid=$!
probe_count=0
while kill -0 "$process_pid" >/dev/null 2>&1; do
  if [[ "$probe_count" -lt 10 ]]; then
    curl -sS -o /dev/null -w '%{time_total}\n' "$DAEMON_URL/v1/health" >>"$health_samples" || true
    curl -sS -o /dev/null -w '%{time_total}\n' "$DAEMON_URL/v1/telemetry/events?run=run-100k-pressure&limit=5" >>"$query_samples" || true
    probe_count=$((probe_count + 1))
  fi
  ps -o rss=,%cpu= -p "$daemon_pid" 2>/dev/null | awk '{$1=$1; print}' >>"$resource_samples" || true
  # One probe per second is enough to prove liveness without making the
  # acceptance client itself dominate SQLite with repeated total-count queries.
  sleep 1
done
wait "$process_pid"
drain_finished_ns="$(now_ns)"
PROCESS_JSON="$(cat "$process_json_file")"
assert_contains "$PROCESS_JSON" '"schema_version":"agentprovenance.telemetry_spool_process/v1"'
assert_contains "$PROCESS_JSON" '"processed":1'
if [[ "$EVENT_COUNT" -gt 1000 ]]; then
  assert_contains "$PROCESS_JSON" '"row_results_truncated":true'
fi

echo "== paged query remains bounded after high-volume ingest"
PAGE_JSON="$(get_json '/v1/telemetry/events?run=run-100k-pressure&limit=5')"
assert_contains "$PAGE_JSON" '"schema_version":"agentprovenance.telemetry_events/v1"'
assert_contains "$PAGE_JSON" '"event_count":5'
assert_contains "$PAGE_JSON" '"has_more":true'
assert_contains "$PAGE_JSON" '"next_cursor":"'
assert_contains "$PAGE_JSON" '"total_count":'"$EVENT_COUNT"
assert_contains "$PAGE_JSON" '"result_set_id":"sha256:'
assert_contains "$PAGE_JSON" '"page_hash":"sha256:'

echo "== health remains responsive after high-volume ingest"
HEALTH_DONE="$(get_json /v1/health)"
assert_contains "$HEALTH_DONE" '"status":"ok"'
PRODUCER_HEALTH="$(get_json '/v1/telemetry/producer-health?run=run-100k-pressure')"
assert_contains "$PRODUCER_HEALTH" '"schema_version":"agentprovenance.producer_health/v1"'

# Ensure the percentile arrays are populated even on unusually fast machines.
for _ in $(seq 1 10); do
  curl -sS -o /dev/null -w '%{time_total}\n' "$DAEMON_URL/v1/health" >>"$health_samples"
  curl -sS -o /dev/null -w '%{time_total}\n' "$DAEMON_URL/v1/telemetry/events?run=run-100k-pressure&limit=5" >>"$query_samples"
done

mkdir -p "$(dirname "$REPORT_PATH")"
python3 - <<'PY' \
  "$REPORT_PATH" "$EVENT_COUNT" \
  "$(elapsed_ms "$generate_started_ns" "$generate_finished_ns")" \
  "$(elapsed_ms "$enqueue_started_ns" "$enqueue_finished_ns")" \
  "$(elapsed_ms "$drain_started_ns" "$drain_finished_ns")" \
  "$health_samples" "$query_samples" "$resource_samples" \
  "$QUEUED_HEALTH" "$PRODUCER_HEALTH"
import json
import math
import pathlib
import sys
from datetime import datetime, timezone

report_path = pathlib.Path(sys.argv[1])
event_count = int(sys.argv[2])
generation_ms = float(sys.argv[3])
enqueue_ms = float(sys.argv[4])
drain_ms = float(sys.argv[5])

def values(path):
    result = []
    for raw in pathlib.Path(path).read_text().splitlines():
        try:
            result.append(float(raw.strip()))
        except ValueError:
            pass
    return sorted(result)

def percentiles(samples):
    if not samples:
        return {"samples": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "max_ms": 0}
    def p(q):
        idx = max(0, min(len(samples) - 1, math.ceil(q * len(samples)) - 1))
        return round(samples[idx] * 1000, 3)
    return {"samples": len(samples), "p50_ms": p(.50), "p95_ms": p(.95), "p99_ms": p(.99), "max_ms": round(samples[-1] * 1000, 3)}

rss = []
cpu = []
for raw in pathlib.Path(sys.argv[8]).read_text().splitlines():
    parts = raw.split()
    if len(parts) >= 2:
        try:
            rss.append(float(parts[0]))
            cpu.append(float(parts[1]))
        except ValueError:
            pass

queued = json.loads(sys.argv[9])
final = json.loads(sys.argv[10])
report = {
    "schema_version": "agentprovenance.telemetry_pressure_report/v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "event_count": event_count,
    "generation_ms": generation_ms,
    "enqueue_ms": enqueue_ms,
    "drain_ms": drain_ms,
    "ingest_events_per_second": round(event_count / (drain_ms / 1000), 2) if drain_ms > 0 else 0,
    "health_latency": percentiles(values(sys.argv[6])),
    "paged_query_latency": percentiles(values(sys.argv[7])),
    "daemon_peak_rss_bytes": int(max(rss) * 1024) if rss else 0,
    "daemon_peak_cpu_percent": round(max(cpu), 2) if cpu else 0,
    "queued_snapshot": queued,
    "producer_health": final,
    "acceptance": {
        "health_responsive": True,
        "bounded_paging": True,
        "reported_total_count": event_count,
        "no_failed_batches": final.get("spool", {}).get("failed_batches", 0) == 0,
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n")
PY

rm -f "$health_samples" "$query_samples" "$resource_samples" "$process_json_file"

echo "100k telemetry pressure acceptance passed; report=$REPORT_PATH"
