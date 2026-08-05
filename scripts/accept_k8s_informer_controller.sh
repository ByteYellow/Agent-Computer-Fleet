#!/usr/bin/env bash
# Environment-gated lifecycle test for the lightweight client-go informer:
# initial pod attribution -> container restart rebinding -> pod deletion close.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENTPROV="${AGENTPROV:?set AGENTPROV to the linux agentprov binary}"
KUBECTL="${KUBECTL:-k3s kubectl}"
IMAGE="${IMAGE:-busybox}"
CONTROLLER_IMAGE="${AGENTPROV_CONTROLLER_IMAGE:-agentprov-controller:accept}"
DOCKERFILE="${AGENTPROV_CONTROLLER_DOCKERFILE:-$ROOT_DIR/deploy/k8s/Dockerfile.controller}"
MANIFEST="${AGENTPROV_CONTROLLER_MANIFEST:-$ROOT_DIR/deploy/k8s/agentprov-attribution-controller.yaml}"
REPORT_PATH="${AGENTPROV_K8S_INFORMER_REPORT:-}"
SUFFIX="$$"
NAME="agentprov-informer-accept-$SUFFIX"
POD="agentprov-informer-workload-$SUFFIX"
RUN_ID="run-k8s-informer-$SUFFIX"
DATA_PATH="/tmp/agentprov-informer-$SUFFIX"
CONTROLLER_NAMESPACE="${AGENTPROV_CONTROLLER_NAMESPACE:-default}"
OUT="$(mktemp -d)"

cleanup() {
  $KUBECTL delete pod "$POD" --force --grace-period=0 >/dev/null 2>&1 || true
  $KUBECTL delete daemonset "$NAME" -n "$CONTROLLER_NAMESPACE" --wait=true --timeout=60s >/dev/null 2>&1 || true
  $KUBECTL delete clusterrolebinding "$NAME" >/dev/null 2>&1 || true
  $KUBECTL delete clusterrole "$NAME" >/dev/null 2>&1 || true
  $KUBECTL delete serviceaccount "$NAME" -n "$CONTROLLER_NAMESPACE" >/dev/null 2>&1 || true
  rm -rf "$DATA_PATH" "$OUT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ -x "$AGENTPROV" ]] || { echo "FAIL: agentprov binary is not executable: $AGENTPROV"; exit 1; }
[[ -f "$DOCKERFILE" && -f "$MANIFEST" ]] || { echo "FAIL: controller Dockerfile/manifest missing"; exit 1; }

echo "== build and deploy attribution controller"
mkdir -p "$OUT/image"
cp "$AGENTPROV" "$OUT/image/agentprov"
cp "$DOCKERFILE" "$OUT/image/Dockerfile"
docker build -q -t "$CONTROLLER_IMAGE" "$OUT/image" >/dev/null
docker save "$CONTROLLER_IMAGE" | k3s ctr images import - >/dev/null

# The checked production manifest owns the `agentprov` namespace. Acceptance
# deliberately drops that first Namespace document and deploys unique resource
# names into an existing namespace, so a test can never replace a real install.
sed -n '/^---$/,$p' "$MANIFEST" | tail -n +2 | sed \
  -e "s/agentprov-attribution-controller/$NAME/g" \
  -e "s/namespace: agentprov/namespace: $CONTROLLER_NAMESPACE/g" \
  -e "s#image: agentprov-controller:latest#image: $CONTROLLER_IMAGE#" \
  -e "s#path: /var/lib/agentprov, type:#path: $DATA_PATH, type:#" \
  -e "s#- 30s#- 2s#" \
	-e "/- 2s/a\\            - --selector\\n            - agentprov.io/acceptance=$SUFFIX" \
  >"$OUT/controller.yaml"
$KUBECTL apply -f "$OUT/controller.yaml" >/dev/null
$KUBECTL rollout status daemonset/$NAME -n "$CONTROLLER_NAMESPACE" --timeout=90s >/dev/null
controller_pod="$($KUBECTL get pod -n "$CONTROLLER_NAMESPACE" -l "app=$NAME" -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "$controller_pod" ]]; then
  controller_pod="$($KUBECTL get pod -n "$CONTROLLER_NAMESPACE" -l "app=$NAME" -o name | tail -1 | cut -d/ -f2)"
fi
[[ -n "$controller_pod" ]] || { echo "FAIL: controller pod not found"; exit 1; }

echo "== create annotated workload and wait for initial binding"
$KUBECTL run "$POD" --image="$IMAGE" --image-pull-policy=IfNotPresent --restart=Always \
  --annotations "agentprov.io/run=$RUN_ID" --labels "app=agentprov-informer-accept,agentprov.io/acceptance=$SUFFIX" \
  --command -- sh -c 'while [ ! -f /tmp/agentprov-restart ]; do id >/dev/null; sleep 1; done; exit 42' >/dev/null
$KUBECTL wait --for=condition=Ready pod/$POD --timeout=90s >/dev/null
initial_container="$($KUBECTL get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}')"

wait_log() {
  local pattern="$1"
  for _ in $(seq 1 60); do
    logs="$($KUBECTL logs -n "$CONTROLLER_NAMESPACE" "$controller_pod" 2>/dev/null || true)"
    if grep -q "$pattern" <<<"$logs"; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: controller log never matched: $pattern" >&2
  $KUBECTL logs -n "$CONTROLLER_NAMESPACE" "$controller_pod" >&2 || true
  return 1
}
wait_log 'bindings=1 active=1'

echo "== force container restart and require close+rebind"
# Let the container's own PID 1 exit. This deterministically exercises the
# kubelet restart path while preserving the Pod UID; killing PID 1 from a
# kubectl-exec process is runtime-dependent and can be ignored.
$KUBECTL exec "$POD" -- touch /tmp/agentprov-restart >/dev/null
for _ in $(seq 1 90); do
  restarts="$($KUBECTL get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
  current_container="$($KUBECTL get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}' 2>/dev/null || true)"
  if [[ "${restarts:-0}" -ge 1 && -n "$current_container" && "$current_container" != "$initial_container" ]]; then
    break
  fi
  sleep 1
done
[[ "${restarts:-0}" -ge 1 && "$current_container" != "$initial_container" ]] || { echo "FAIL: container did not restart"; exit 1; }
wait_log 'bindings=2 active=1 closed=1 restarts=1'

echo "== delete pod and require binding closure"
$KUBECTL delete pod "$POD" --wait=true --timeout=60s >/dev/null
wait_log 'bindings=2 active=0 closed=2 restarts=1'

bindings="$($KUBECTL exec -n "$CONTROLLER_NAMESPACE" "$controller_pod" -- /usr/local/bin/agentprov --data-dir /var/lib/agentprov telemetry bindings --run "$RUN_ID" --json)"
read -r rows open_rows <<<"$(python3 -c 'import json,sys; rows=json.load(sys.stdin)["bindings"]; print(len(rows), sum(not row["ended_at"] for row in rows))' <<<"$bindings")"
[[ "$rows" -eq 2 ]] || { echo "FAIL: binding rows=$rows, want 2"; echo "$bindings"; exit 1; }
[[ "$open_rows" -eq 0 ]] || { echo "FAIL: open bindings remain=$open_rows"; echo "$bindings"; exit 1; }

logs="$($KUBECTL logs -n "$CONTROLLER_NAMESPACE" "$controller_pod")"
final_line="$(grep 'k8s informer node=' <<<"$logs" | tail -1)"
echo "  $final_line"
echo "  bindings=2 restart_rebound=1 delete_closed=1"

if [[ -n "$REPORT_PATH" ]]; then
  mkdir -p "$(dirname "$REPORT_PATH")"
  python3 - "$REPORT_PATH" "$RUN_ID" "$initial_container" "$current_container" "$final_line" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone
path, run_id, initial, restarted, status = sys.argv[1:]
report = {
    "schema_version": "agentprovenance.k8s_informer_acceptance/v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "producer_profile": "k8s-daemonset",
    "controller": "client-go-informer",
    "client_go_version": "v0.32.0",
    "initial_container_id": initial,
    "restarted_container_id": restarted,
    "bindings_created": 2,
    "bindings_closed": 2,
    "restart_rebound": True,
    "delete_closed": True,
    "status_line": status,
}
pathlib.Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY
  echo "  report=$REPORT_PATH"
fi
echo "PASS: K8s informer lifecycle attribution"
