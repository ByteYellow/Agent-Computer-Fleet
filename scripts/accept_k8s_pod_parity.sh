#!/usr/bin/env bash
# Acceptance: the k8s-daemonset Producer Profile captures a real Kubernetes pod's
# kernel telemetry from the node, attributes it to the pod's container/cgroup,
# and produces a forensics bundle that imports and verifies clean centrally -
# the same evidence guarantee the local-record path gives, for an externally-
# scheduled pod that was never wrapped by `record`.
#
# Flow: deploy pod -> node sensor captures -> `sandbox bind-cgroup` ties the
# pod's cgroup to a run (k8s_cgroup, confidence 0.8) -> ingest the pod-scoped
# telemetry -> forensics export -> graph verify (must be errors=0).
#
# Run on the node. Requires a running single-node k3s/k8s + Docker.
# Env:
#   AGENTPROV   path to linux agentprov binary (required)
#   SENSOR      path to linux agentprov-sensor binary (required)
#   KUBECTL     kubectl command (default "k3s kubectl"; needs cluster access)
#   IMAGE       pod image, present in the cluster containerd (default busybox)
set -uo pipefail

AGENTPROV="${AGENTPROV:?set AGENTPROV to the agentprov binary}"
SENSOR="${SENSOR:?set SENSOR to the agentprov-sensor binary}"
KUBECTL="${KUBECTL:-k3s kubectl}"
IMAGE="${IMAGE:-busybox}"
POD="accept-parity-$$"
DATA="$(mktemp -d)"; OUT="$(mktemp -d)"
cleanup() { $KUBECTL delete pod "$POD" --force --grace-period=0 >/dev/null 2>&1 || true; rm -rf "$DATA" "$OUT"; }
trap cleanup EXIT

echo "== deploy a workload pod that execs in a loop"
$KUBECTL run "$POD" --image="$IMAGE" --image-pull-policy=IfNotPresent --restart=Never \
  --labels app=agentprov-accept,agentprov-run=POD1 \
  --command -- sh -c 'while true; do id; ls / >/dev/null; sleep 1; done' >/dev/null
for i in $(seq 1 30); do
  [ "$($KUBECTL get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] && break
  sleep 2
done
[ "$($KUBECTL get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] || {
  echo "FAIL: pod did not reach Running (image present in cluster containerd?)"; exit 1; }

echo "== node sensor captures node-wide telemetry"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$SENSOR":/agentprov-sensor:ro -v "$OUT":/out \
  ubuntu:24.04 bash -c '/agentprov-sensor >/out/sensor.jsonl 2>/dev/null & SP=$!; sleep 6; kill $SP 2>/dev/null' >/dev/null 2>&1

J="$OUT/sensor.jsonl"
podExec=$(grep -E '"comm":"(id|ls)"' "$J" | grep -c execve)
CG=$(grep -E '"comm":"(id|ls)"' "$J" | grep execve | grep -oE '"cgroup_id":"[0-9]+"' | head -1 | grep -oE '[0-9]+')
withContainer=$(grep -E '"comm":"(id|ls)"' "$J" | grep execve | grep -cE '"container_id":"[0-9a-f]{64}"')
CGPATH=$(find /sys/fs/cgroup -inum "${CG:-0}" 2>/dev/null | head -1)
PODUID=$(echo "$CGPATH" | grep -oE 'pod[0-9a-f_]+' | head -1 | sed 's/^pod//;s/_/-/g')
echo "  pod execve captured: $podExec ; container_id resolved: $withContainer ; pod cgroup: $CG"
[ "$podExec" -ge 1 ] && [ "$withContainer" -ge 1 ] && [ -n "$CG" ] && echo "$CGPATH" | grep -q kubepods || {
  echo "FAIL: pod telemetry not captured/attributed from the node"; exit 1; }

echo "== bind the pod cgroup -> run, ingest, export, verify"
PODNS="$($KUBECTL get pod "$POD" -o jsonpath='{.metadata.namespace}')"
NODE="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.nodeName}')"
SA="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.serviceAccountName}')"
CONTAINER="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.containers[0].name}')"
PODIMAGE="$($KUBECTL get pod "$POD" -o jsonpath='{.spec.containers[0].image}')"
CLUSTER="$($KUBECTL config current-context 2>/dev/null || echo k8s)"
LABELS="app=agentprov-accept,agentprov-run=POD1"
"$AGENTPROV" --data-dir "$DATA" sandbox bind-cgroup --run POD1 --cgroup-id "$CG" --session "$PODUID" --started-at "$START" \
  --cluster "$CLUSTER" --namespace "$PODNS" --pod-name "$POD" --node "$NODE" --container "$CONTAINER" --image "$PODIMAGE" --service-account "$SA" --labels "$LABELS" >/dev/null
grep -F "\"cgroup_id\":\"$CG\"" "$J" > "$OUT/pod.jsonl"
"$AGENTPROV" --data-dir "$DATA" telemetry ingest-jsonl --run POD1 --file "$OUT/pod.jsonl" --format native >/dev/null 2>&1
"$AGENTPROV" --data-dir "$DATA" forensics export POD1 >/dev/null 2>&1
verify=$("$AGENTPROV" --data-dir "$DATA" graph verify --run POD1 2>&1 | head -1)
echo "  $verify"

if echo "$verify" | grep -q "errors=0"; then
  echo "PASS: node-observed pod telemetry attributed to a run and verifies clean (errors=0)"
  exit 0
fi
echo "FAIL: pod evidence did not verify clean"
exit 1
