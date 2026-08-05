#!/usr/bin/env bash
# Environment-gated acceptance: deploy the real k8s-daemonset Producer Profile,
# then prove ONE node sensor observes N independently scheduled workloads. The
# controller resolves container/cgroup -> pod metadata without workload changes,
# ingests the DaemonSet's stdout JSONL, and verifies one evidence graph.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENTPROV="${AGENTPROV:?set AGENTPROV to the linux agentprov binary}"
SENSOR="${SENSOR:?set SENSOR to the linux agentprov-sensor binary}"
KUBECTL="${KUBECTL:-k3s kubectl}"
IMAGE="${IMAGE:-busybox}"
SENSOR_IMAGE="${AGENTPROV_SENSOR_IMAGE:-agentprov-sensor:accept}"
SENSOR_DOCKERFILE="${AGENTPROV_SENSOR_DOCKERFILE:-$ROOT_DIR/deploy/k8s/Dockerfile.sensor}"
DAEMONSET_MANIFEST="${AGENTPROV_DAEMONSET_MANIFEST:-$ROOT_DIR/deploy/k8s/agentprov-sensor-daemonset.yaml}"
WORKLOAD_COUNT="${AGENTPROV_MULTIWORKLOAD_COUNT:-8}"
CAPTURE_SECONDS="${AGENTPROV_MULTIWORKLOAD_CAPTURE_SECONDS:-10}"
RUN_ID="${AGENTPROV_MULTIWORKLOAD_RUN_ID:-run-k8s-multiworkload}"
REPORT_PATH="${AGENTPROV_MULTIWORKLOAD_REPORT:-}"
KEEP_ARTIFACTS="${AGENTPROV_MULTIWORKLOAD_KEEP:-0}"
PREFIX="agentprov-multi-$$"
SENSOR_NAMESPACE="agentprov-accept-$$"
DATA="$(mktemp -d)"
OUT="$(mktemp -d)"

cleanup() {
  if [[ "$KEEP_ARTIFACTS" == "1" ]]; then
    echo "  kept data=$DATA output=$OUT namespace=$SENSOR_NAMESPACE" >&2
    return
  fi
  for i in $(seq 1 "$WORKLOAD_COUNT"); do
    $KUBECTL delete pod "$PREFIX-$i" --force --grace-period=0 >/dev/null 2>&1 || true
  done
  # Namespace finalization is owned by the cluster controller. Do not block the
  # acceptance result on unrelated discovery failures (for example a stale
  # metrics.k8s.io APIService); all namespaced test content is already deleted.
  $KUBECTL delete namespace "$SENSOR_NAMESPACE" --wait=false >/dev/null 2>&1 || true
  rm -rf "$DATA" "$OUT"
}
trap cleanup EXIT

[[ -x "$SENSOR" ]] || { echo "FAIL: sensor binary is not executable: $SENSOR"; exit 1; }
[[ -f "$SENSOR_DOCKERFILE" ]] || { echo "FAIL: sensor Dockerfile not found: $SENSOR_DOCKERFILE"; exit 1; }
[[ -f "$DAEMONSET_MANIFEST" ]] || { echo "FAIL: DaemonSet manifest not found: $DAEMONSET_MANIFEST"; exit 1; }

echo "== build and import DaemonSet sensor image"
mkdir -p "$OUT/image"
cp "$SENSOR" "$OUT/image/agentprov-sensor"
cp "$SENSOR_DOCKERFILE" "$OUT/image/Dockerfile"
docker build -q -t "$SENSOR_IMAGE" "$OUT/image" >/dev/null
docker save "$SENSOR_IMAGE" | k3s ctr images import - >/dev/null

sed \
  -e "s/name: agentprov$/name: $SENSOR_NAMESPACE/" \
  -e "s/namespace: agentprov/namespace: $SENSOR_NAMESPACE/" \
  -e "s#image: agentprov-sensor:latest#image: $SENSOR_IMAGE#" \
  "$DAEMONSET_MANIFEST" >"$OUT/daemonset.yaml"
$KUBECTL apply -f "$OUT/daemonset.yaml" >/dev/null
$KUBECTL rollout status daemonset/agentprov-sensor -n "$SENSOR_NAMESPACE" --timeout=90s >/dev/null
sensor_pod="$($KUBECTL get pod -n "$SENSOR_NAMESPACE" -l app=agentprov-sensor -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$sensor_pod" ]] || { echo "FAIL: DaemonSet sensor pod was not scheduled"; exit 1; }
echo "  daemonset=agentprov-sensor pod=$SENSOR_NAMESPACE/$sensor_pod transport=stdout-jsonl"
# Pod readiness only proves the sensor process is alive. Leave a short attach
# window before scheduling workloads so their first exec is not in the probe
# setup boundary.
sleep 2

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CLUSTER="$($KUBECTL config current-context 2>/dev/null || echo k8s)"
echo "== deploy $WORKLOAD_COUNT workloads"
for i in $(seq 1 "$WORKLOAD_COUNT"); do
  $KUBECTL run "$PREFIX-$i" --image="$IMAGE" --image-pull-policy=IfNotPresent --restart=Never \
    --labels "app=agentprov-multi,agentprov-index=$i" \
    --command -- sh -c "while true; do /bin/busybox id >/dev/null; /bin/busybox ls / >/dev/null; sleep 1; done" >/dev/null
done

for _ in $(seq 1 60); do
  running="$($KUBECTL get pods -l app=agentprov-multi --field-selector=status.phase=Running -o name 2>/dev/null | grep -c "$PREFIX" || true)"
  [[ "$running" -ge "$WORKLOAD_COUNT" ]] && break
  sleep 1
done
[[ "${running:-0}" -ge "$WORKLOAD_COUNT" ]] || { echo "FAIL: only ${running:-0}/$WORKLOAD_COUNT workloads reached Running"; exit 1; }

echo "== stimulate one observable exec in every workload cgroup"
for i in $(seq 1 "$WORKLOAD_COUNT"); do
  $KUBECTL exec "$PREFIX-$i" -- /bin/busybox id >/dev/null
done

echo "== collect ${CAPTURE_SECONDS}s from the DaemonSet stdout transport"
sleep "$CAPTURE_SECONDS"
J="$OUT/sensor.jsonl"
$KUBECTL logs -n "$SENSOR_NAMESPACE" "$sensor_pod" -c sensor >"$J"
[[ -s "$J" ]] || { echo "FAIL: sensor produced no telemetry"; exit 1; }
: >"$OUT/cgroups.txt"
: >"$OUT/nodes.txt"
host_cgroup_fallbacks=0

echo "== resolve and bind N pod identities"
for i in $(seq 1 "$WORKLOAD_COUNT"); do
  pod="$PREFIX-$i"
  cid="$($KUBECTL get pod "$pod" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's#^[^:]*://##')"
  cgroup="$(python3 - "$J" "$cid" <<'PY'
import json, sys
path, cid = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    for line in f:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("container_id") == cid and row.get("cgroup_id"):
            print(row["cgroup_id"])
            break
PY
)"
  if [[ -z "$cgroup" ]]; then
    cgroup_path="$(find /sys/fs/cgroup -type d -name "*$cid*" -print -quit 2>/dev/null || true)"
    if [[ -n "$cgroup_path" ]]; then
      cgroup="$(stat -c %i "$cgroup_path")"
      host_cgroup_fallbacks=$((host_cgroup_fallbacks + 1))
    fi
  fi
  [[ -n "$cgroup" ]] || { echo "FAIL: no sensor cgroup for pod=$pod container=$cid"; exit 1; }
  python3 - "$J" "$cgroup" <<'PY'
import json, sys
path, cgroup = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    if not any(str(json.loads(line).get("cgroup_id", "")) == cgroup for line in f if line.lstrip().startswith("{")):
        raise SystemExit(f"cgroup {cgroup} did not appear in the DaemonSet event stream")
PY
  echo "$cgroup" >>"$OUT/cgroups.txt"
  uid="$($KUBECTL get pod "$pod" -o jsonpath='{.metadata.uid}')"
  node="$($KUBECTL get pod "$pod" -o jsonpath='{.spec.nodeName}')"
  echo "$node" >>"$OUT/nodes.txt"
  ns="$($KUBECTL get pod "$pod" -o jsonpath='{.metadata.namespace}')"
  "$AGENTPROV" --data-dir "$DATA" sandbox bind-cgroup --run "$RUN_ID" --cgroup-id "$cgroup" \
    --session "$uid" --started-at "$STARTED_AT" \
    --cluster "$CLUSTER" \
    --namespace "$ns" --pod-name "$pod" --node "$node" --container "$pod" --image "$IMAGE" \
    --labels "app=agentprov-multi,agentprov-index=$i" >/dev/null
done

unique_cgroups="$(sort -u "$OUT/cgroups.txt" | wc -l | tr -d ' ')"
[[ "$unique_cgroups" -eq "$WORKLOAD_COUNT" ]] || { echo "FAIL: observed $unique_cgroups unique cgroups, want $WORKLOAD_COUNT"; exit 1; }
unique_nodes="$(sort -u "$OUT/nodes.txt" | wc -l | tr -d ' ')"
[[ "$unique_nodes" -eq 1 ]] || { echo "FAIL: workloads landed on $unique_nodes nodes; this gate validates one node"; exit 1; }
node_name="$(head -1 "$OUT/nodes.txt")"

python3 - "$J" "$OUT/cgroups.txt" "$OUT/workloads.jsonl" <<'PY'
import json, sys
source, ids_path, target = sys.argv[1:]
ids = set(open(ids_path, encoding="utf-8").read().split())
with open(source, encoding="utf-8") as src, open(target, "w", encoding="utf-8") as dst:
    for line in src:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(row.get("cgroup_id", "")) in ids:
            dst.write(json.dumps(row, separators=(",", ":")) + "\n")
PY

"$AGENTPROV" --data-dir "$DATA" telemetry ingest-jsonl --run "$RUN_ID" --file "$OUT/workloads.jsonl" --format native >/dev/null
event_count="$(wc -l <"$OUT/workloads.jsonl" | tr -d ' ')"
verify_rc=0
verify_output="$($AGENTPROV --data-dir "$DATA" graph verify --run "$RUN_ID" 2>&1)" || verify_rc=$?
verify="${verify_output%%$'\n'*}"
echo "  workloads=$WORKLOAD_COUNT unique_cgroups=$unique_cgroups events=$event_count"
echo "  $verify"
[[ "$verify_rc" -eq 0 && "$verify" == *"errors=0"* ]] || { echo "FAIL: multi-workload evidence graph did not verify"; exit 1; }
if [[ -n "$REPORT_PATH" ]]; then
  mkdir -p "$(dirname "$REPORT_PATH")"
  python3 - "$REPORT_PATH" "$RUN_ID" "$CLUSTER" "$node_name" "$WORKLOAD_COUNT" "$unique_cgroups" "$event_count" "$host_cgroup_fallbacks" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone

path, run_id, cluster, node, workloads, cgroups, events, fallbacks = sys.argv[1:]
report = {
    "schema_version": "agentprovenance.k8s_node_multiworkload_acceptance/v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "producer_profile": "k8s-daemonset",
    "sensor_placement": "kubernetes_daemonset",
    "event_transport": "kubernetes_pod_stdout_jsonl",
    "scope_resolution": "k8s_api_container_to_kernel_cgroup",
    "host_cgroup_fallback_count": int(fallbacks),
    "cluster": cluster,
    "node": node,
    "sensor_count": 1,
    "workload_count": int(workloads),
    "unique_cgroup_count": int(cgroups),
    "captured_event_count": int(events),
    "graph_verify": {"status": "ok", "errors": 0, "warnings": 0},
}
pathlib.Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY
  echo "  report=$REPORT_PATH"
fi
echo "PASS: one node sensor observed $WORKLOAD_COUNT workloads and produced one verified graph"
