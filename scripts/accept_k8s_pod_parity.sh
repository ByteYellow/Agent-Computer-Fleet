#!/usr/bin/env bash
# Acceptance: the k8s-daemonset Producer Profile captures a real Kubernetes pod's
# kernel telemetry from the node and attributes it to the pod's container/cgroup.
#
# This is the real-cluster counterpart to the local-record path: instead of
# `record` creating a cgroup, a node-level sensor observes an externally-scheduled
# pod and the cgroup->container->pod resolution ties its events to the pod. It
# proves the k8s-daemonset system-telemetry + attribution mechanism on a real
# k3s node (the cgroup format the node sensor sees is what internal/producer
# ParseCgroupScope parses).
#
# Requires: a running single-node k3s (or k8s) + Docker, run on the node itself.
# eBPF needs a privileged container (no host sudo required for the sensor).
#
# Env:
#   SENSOR      path to the linux/arm64 agentprov-sensor binary (required)
#   KUBECTL     kubectl command (default: "k3s kubectl"; needs cluster access)
#   IMAGE       pod image, must be importable/present in the cluster containerd
set -uo pipefail

SENSOR="${SENSOR:?set SENSOR to the agentprov-sensor binary path}"
KUBECTL="${KUBECTL:-k3s kubectl}"
IMAGE="${IMAGE:-busybox}"
POD="accept-parity-$$"

cleanup() { $KUBECTL delete pod "$POD" --force --grace-period=0 >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== deploy a workload pod that execs in a loop"
$KUBECTL run "$POD" --image="$IMAGE" --image-pull-policy=IfNotPresent --restart=Never \
  --command -- sh -c 'while true; do id; ls / >/dev/null; sleep 1; done' >/dev/null
for i in $(seq 1 30); do
  [ "$($KUBECTL get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] && break
  sleep 2
done
[ "$($KUBECTL get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] || {
  echo "FAIL: pod did not reach Running (image present in cluster containerd?)"; exit 1; }

echo "== run the node sensor (privileged, hostPID, host cgroup/BTF/tracefs)"
OUT=$(mktemp)
docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$SENSOR":/agentprov-sensor:ro \
  ubuntu:24.04 bash -c '/agentprov-sensor >/tmp/s.jsonl 2>/dev/null & SP=$!; sleep 5; kill $SP 2>/dev/null; cat /tmp/s.jsonl' >"$OUT" 2>/dev/null

echo "== assert the pod's execve was captured and attributed"
podExec=$(grep -E '"comm":"(id|ls)"' "$OUT" | grep -c execve)
withContainer=$(grep -E '"comm":"(id|ls)"' "$OUT" | grep execve | grep -cE '"container_id":"[0-9a-f]{64}"')
cgroupID=$(grep -E '"comm":"(id|ls)"' "$OUT" | grep execve | grep -oE '"cgroup_id":"[0-9]+"' | head -1 | grep -oE '[0-9]+')
kubepodsPath=""
[ -n "$cgroupID" ] && kubepodsPath=$(find /sys/fs/cgroup -inum "$cgroupID" 2>/dev/null | grep -c kubepods)
rm -f "$OUT"

echo "  pod execve captured: $podExec"
echo "  events with resolved 64-hex container_id: $withContainer"
echo "  event cgroup ($cgroupID) is a kubepods cgroup: ${kubepodsPath:-0}"

if [ "$podExec" -ge 1 ] && [ "$withContainer" -ge 1 ] && [ "${kubepodsPath:-0}" -ge 1 ]; then
  echo "PASS: node sensor captured the pod's kernel telemetry and resolved it to the pod's container/cgroup"
  exit 0
fi
echo "FAIL: pod telemetry not captured/attributed"
exit 1
