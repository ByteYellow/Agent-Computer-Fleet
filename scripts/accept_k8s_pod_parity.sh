#!/usr/bin/env bash
# Environment-gated semantic parity acceptance for Producer Profiles.
#
# The same workload runs twice on one Linux/K8s node:
#   1. local-record: actively launched into a dedicated cgroup;
#   2. k8s-daemonset: externally scheduled Pod, passively attributed by cgroup.
#
# Physical identities are expected to differ. The gate compares canonical
# evidence semantics (workload execs, event classes, graph node/edge kinds),
# requires both graphs to verify, and asserts the honest confidence difference.
set -euo pipefail

AGENTPROV="${AGENTPROV:?set AGENTPROV to the agentprov binary}"
SENSOR="${SENSOR:?set SENSOR to the agentprov-sensor binary}"
KUBECTL="${KUBECTL:-k3s kubectl}"
IMAGE="${IMAGE:-busybox}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-14}"
REPORT_PATH="${AGENTPROV_K8S_PARITY_REPORT:-}"
SUFFIX="$$"
POD="agentprov-parity-$SUFFIX"
LOCAL_RUN="run-parity-local-$SUFFIX"
K8S_RUN="run-parity-k8s-$SUFFIX"
DATA="$(mktemp -d)"
OUT="$(mktemp -d)"

cleanup() {
  $KUBECTL delete pod "$POD" --force --grace-period=0 >/dev/null 2>&1 || true
  if [[ "${AGENTPROV_KEEP_PARITY_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "$DATA" "$OUT"
  else
    echo "  kept data=$DATA artifacts=$OUT" >&2
  fi
}
trap cleanup EXIT

[[ -x "$AGENTPROV" ]] || { echo "FAIL: agentprov is not executable: $AGENTPROV"; exit 1; }
[[ -x "$SENSOR" ]] || { echo "FAIL: sensor is not executable: $SENSOR"; exit 1; }

echo "== schedule the k8s copy of the canonical workload"
$KUBECTL run "$POD" --image="$IMAGE" --image-pull-policy=IfNotPresent --restart=Never \
  --labels "app=agentprov-parity" \
  --command -- sh -c 'while true; do id >/dev/null; ls / >/dev/null; sleep 1; done' >/dev/null
$KUBECTL wait --for=condition=Ready pod/$POD --timeout=90s >/dev/null
POD_UID="$($KUBECTL get pod "$POD" -o jsonpath='{.metadata.uid}')"
CONTAINER_ID="$($KUBECTL get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}')"
CONTAINER_ID="${CONTAINER_ID##*://}"

echo "== start one node sensor for both profile executions"
CAPTURE_START="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$SENSOR":/agentprov-sensor:ro -v "$OUT":/out \
  ubuntu:24.04 bash -c "/agentprov-sensor >/out/sensor.jsonl 2>/out/sensor.err & SP=\$!; sleep '$CAPTURE_SECONDS'; kill \$SP 2>/dev/null || true" \
  >/dev/null 2>&1 &
SENSOR_JOB=$!
sleep 3

echo "== run the local-record copy of the same workload"
mkdir -p /sys/fs/cgroup/agentprov
mkdir -p "$OUT/workspace"
AGENTPROV_CGROUP_PARENT=/sys/fs/cgroup/agentprov \
  "$AGENTPROV" --data-dir "$DATA" record --run "$LOCAL_RUN" --name parity-local --workdir "$OUT/workspace" -- \
  sh -c 'i=0; while [ "$i" -lt 4 ]; do id >/dev/null; ls / >/dev/null; i=$((i+1)); sleep 1; done' \
  >/dev/null

wait "$SENSOR_JOB"
JSONL="$OUT/sensor.jsonl"
[[ -s "$JSONL" ]] || { echo "FAIL: node sensor produced no telemetry"; exit 1; }

LOCAL_BINDINGS="$OUT/local-bindings.json"
"$AGENTPROV" --data-dir "$DATA" telemetry bindings --run "$LOCAL_RUN" --json >"$LOCAL_BINDINGS"
read -r LOCAL_CGROUP LOCAL_STARTED_AT LOCAL_ENDED_AT <<<"$(python3 - "$LOCAL_BINDINGS" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))["bindings"]
real = [r for r in rows if str(r.get("cgroup_id", "")).isdigit()]
if not real:
    raise SystemExit("local record did not create a real cgroup binding")
row = real[-1]
print(row["cgroup_id"], row["started_at"], row["ended_at"])
PY
)"

K8S_CGROUP="$(python3 - "$JSONL" "$CONTAINER_ID" <<'PY'
import json, sys
path, container = sys.argv[1:]
for line in open(path, errors="replace"):
    try: row = json.loads(line)
    except Exception: continue
    if row.get("container_id") == container and row.get("comm") in {"id", "ls"}:
        value = str(row.get("cgroup_id", ""))
        if value.isdigit():
            print(value)
            break
else:
    raise SystemExit("k8s workload cgroup was not observed")
PY
)"

echo "  local cgroup=$LOCAL_CGROUP  k8s cgroup=$K8S_CGROUP"
[[ "$LOCAL_CGROUP" != "$K8S_CGROUP" ]] || { echo "FAIL: profiles unexpectedly share one cgroup"; exit 1; }

echo "== bind the externally scheduled pod and ingest each cgroup into its run"
POD_NS="$($KUBECTL get pod "$POD" -o jsonpath='{.metadata.namespace}')"
NODE="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.nodeName}')"
SA="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.serviceAccountName}')"
CONTAINER="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.containers[0].name}')"
POD_IMAGE="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.containers[0].image}')"
"$AGENTPROV" --data-dir "$DATA" sandbox bind-cgroup --run "$K8S_RUN" \
  --cgroup-id "$K8S_CGROUP" --session "$POD_UID" --started-at "$CAPTURE_START" \
  --namespace "$POD_NS" --pod-name "$POD" --node "$NODE" \
  --container "$CONTAINER" --image "$POD_IMAGE" --service-account "$SA" \
  --labels "app=agentprov-parity" >/dev/null

python3 - "$JSONL" "$LOCAL_CGROUP" "$K8S_CGROUP" "$LOCAL_STARTED_AT" "$LOCAL_ENDED_AT" "$OUT/local.jsonl" "$OUT/k8s.jsonl" <<'PY'
import json, sys
from datetime import datetime
src, local_cg, k8s_cg, local_start, local_end, local_out, k8s_out = sys.argv[1:]
files = {local_cg: open(local_out, "w"), k8s_cg: open(k8s_out, "w")}
def stamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
start, end = stamp(local_start), stamp(local_end)
try:
    for line in open(src, errors="replace"):
        try: row = json.loads(line)
        except Exception: continue
        cgroup = str(row.get("cgroup_id", ""))
        if cgroup == local_cg:
            when = row.get("timestamp") or row.get("created_at")
            if not when or not (start <= stamp(when) <= end):
                continue
        out = files.get(cgroup)
        if out: out.write(json.dumps(row, separators=(",", ":")) + "\n")
finally:
    for out in files.values(): out.close()
PY

for spec in "$LOCAL_RUN:$OUT/local.jsonl" "$K8S_RUN:$OUT/k8s.jsonl"; do
  run="${spec%%:*}"; file="${spec#*:}"
  [[ -s "$file" ]] || { echo "FAIL: no scoped telemetry for $run"; exit 1; }
  "$AGENTPROV" --data-dir "$DATA" telemetry ingest-jsonl --run "$run" --file "$file" --format native >/dev/null
  "$AGENTPROV" --data-dir "$DATA" graph materialize --run "$run" >/dev/null
done

set +e
"$AGENTPROV" --data-dir "$DATA" graph verify --run "$LOCAL_RUN" --json >"$OUT/local.verify.json" 2>"$OUT/local.verify.err"
LOCAL_VERIFY_RC=$?
"$AGENTPROV" --data-dir "$DATA" graph verify --run "$K8S_RUN" --json >"$OUT/k8s.verify.json" 2>"$OUT/k8s.verify.err"
K8S_VERIFY_RC=$?
set -e
if [[ "$LOCAL_VERIFY_RC" -ne 0 || "$K8S_VERIFY_RC" -ne 0 ]]; then
  echo "FAIL: graph verification failed (local=$LOCAL_VERIFY_RC k8s=$K8S_VERIFY_RC)" >&2
  cat "$OUT/local.verify.json" "$OUT/k8s.verify.json" >&2
  exit 1
fi
LOCAL_VERIFY="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("graph verify: errors=%s warnings=%s" % (d.get("errors", d.get("error_count", 0)), d.get("warnings", d.get("warning_count", 0))))' "$OUT/local.verify.json")"
K8S_VERIFY="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("graph verify: errors=%s warnings=%s" % (d.get("errors", d.get("error_count", 0)), d.get("warnings", d.get("warning_count", 0))))' "$OUT/k8s.verify.json")"

for run in "$LOCAL_RUN" "$K8S_RUN"; do
  "$AGENTPROV" --data-dir "$DATA" telemetry list --run "$run" --limit 10000 --json >"$OUT/$run.events.json"
  "$AGENTPROV" --data-dir "$DATA" graph lens --run "$run" --lens process --detail raw --limit 5000 --json >"$OUT/$run.graph.json"
  "$AGENTPROV" --data-dir "$DATA" telemetry bindings --run "$run" --json >"$OUT/$run.bindings.json"
done

python3 - "$OUT" "$LOCAL_RUN" "$K8S_RUN" "$REPORT_PATH" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone

root, local_run, k8s_run, report_path = sys.argv[1:]
root = pathlib.Path(root)
workload_commands = {"id", "ls"}

def canonical(run):
    page = json.load(open(root / f"{run}.events.json"))
    graph = json.load(open(root / f"{run}.graph.json"))
    bindings = json.load(open(root / f"{run}.bindings.json"))["bindings"]
    event_types, commands = set(), set()
    def command_names(value):
        names = set()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"comm", "command", "cmdline"} and isinstance(item, str):
                    token = item.strip().split()[0] if item.strip() else ""
                    if token: names.add(pathlib.PurePath(token).name)
                elif key == "argv" and isinstance(item, list) and item and isinstance(item[0], str):
                    names.add(pathlib.PurePath(item[0]).name)
                names.update(command_names(item))
        elif isinstance(value, list):
            for item in value: names.update(command_names(item))
        return names

    for event in page["events"]:
        event_types.add(event["event_type"])
        try: payload = json.loads(event.get("payload") or "{}")
        except Exception: payload = {}
        commands.update(command_names(payload) & workload_commands)
    nodes = graph.get("nodes", graph.get("graph", {}).get("nodes", []))
    edges = graph.get("edges", graph.get("graph", {}).get("edges", []))
    node_kinds = sorted({str(n.get("kind", "")) for n in nodes if n.get("kind")})
    edge_types = sorted({str(e.get("edge_type", e.get("type", ""))) for e in edges if e.get("edge_type") or e.get("type")})
    return {
        "event_types": sorted(event_types),
        "workload_commands": sorted(commands),
        "node_kinds": node_kinds,
        "edge_types": edge_types,
        "binding_sources": sorted({b.get("binding_source", "") for b in bindings}),
        "binding_confidence": sorted({float(b.get("confidence", 0)) for b in bindings}),
    }

local = canonical(local_run)
k8s = canonical(k8s_run)
required_types = {"execve"}
required_nodes = {"runtime_event"}
required_edges = {"runtime_process_event"}
failures = []
for name, value in (("local", local), ("k8s", k8s)):
    if set(value["workload_commands"]) != workload_commands:
        failures.append(f"{name}: commands={value['workload_commands']}")
    if not required_types.issubset(value["event_types"]):
        failures.append(f"{name}: missing execve semantics")
    if not required_nodes.issubset(value["node_kinds"]):
        failures.append(f"{name}: missing runtime_event graph node")
    if not required_edges.issubset(value["edge_types"]):
        failures.append(f"{name}: missing runtime_process_event graph edge")

# Compare the semantic projection, not substrate-specific noise. Additional
# lifecycle events may differ because a Pod and a local wrapper have different
# supervisors; the canonical workload commands and runtime graph contract must
# be equal.
equivalent = (
    local["workload_commands"] == k8s["workload_commands"]
    and required_types.issubset(set(local["event_types"]) & set(k8s["event_types"]))
    and required_nodes.issubset(set(local["node_kinds"]) & set(k8s["node_kinds"]))
    and required_edges.issubset(set(local["edge_types"]) & set(k8s["edge_types"]))
)
if not equivalent: failures.append("canonical semantic projection differs")
if "k8s_cgroup" not in k8s["binding_sources"] or 0.8 not in k8s["binding_confidence"]:
    failures.append("k8s passive binding confidence is not 0.8")
if not any(v >= 0.98 for v in local["binding_confidence"]):
    failures.append("local record binding is not kernel-verified")

report = {
    "schema_version": "agentprovenance.profile_semantic_parity/v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "workload": "sh loop: id + ls /",
    "equivalent": equivalent and not failures,
    "ignored_physical_fields": ["pid", "ppid", "tgid", "cgroup_id", "container_id", "timestamps", "event_count"],
    "local_record": local,
    "k8s_daemonset": k8s,
    "failures": failures,
}
text = json.dumps(report, indent=2) + "\n"
print(text, end="")
if report_path:
    pathlib.Path(report_path).write_text(text)
if failures:
    raise SystemExit(1)
PY

echo "  $LOCAL_VERIFY"
echo "  $K8S_VERIFY"
echo "PASS: local-record and k8s-daemonset are semantically equivalent for the canonical workload"
