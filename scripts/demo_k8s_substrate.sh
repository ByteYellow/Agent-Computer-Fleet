#!/usr/bin/env bash
# Demo: the k8s-daemonset Producer Profile, end to end, over a real LLM workload.
#
# Deploys a Python agent Pod that makes real DeepSeek/Anthropic API calls in a
# loop, captures its kernel telemetry AND its model-intent (TLS request/response
# bodies) from the NODE side without touching the image, attributes it to a run
# via the pod cgroup + pod metadata, and serves it on the substrate lens.
#
# This is the k8s counterpart of the local-record demo: same evidence, an
# externally-scheduled pod that was never wrapped by `record`. The model-intent
# capture points the libssl uprobe at the pod's own libssl through /proc/<pid>/
# root, satisfying the roadmap's "TLS symbols resolvable from the node/rootfs".
#
# Run on the node. Requires single-node k3s/k8s + Docker, run as root (the
# sensor needs privileged BPF and the k3s kubeconfig is root-only).
#
# Env:
#   AGENTPROV         path to the linux agentprov binary (required)
#   SENSOR            path to the linux agentprov-sensor binary (required)
#   KUBECTL           kubectl command (default "k3s kubectl")
#   IMAGE             python image present in the cluster containerd
#                     (default docker.io/library/python:3-slim)
#   DEEPSEEK_API_KEY  real key -> real completions; unset/placeholder -> 401s
#   ANTHROPIC_API_KEY real key -> real completions; unset/placeholder -> 401s
#   DNS_SERVER        pod upstream DNS, bypassing broken in-cluster CoreDNS
#                     (default 10.211.55.1; set to your node's resolver)
#   DATA              agentprov data dir (default /home/agentprov/agentprov-demo)
#   CAPTURE_SECONDS   sensor capture window (default 50)
#   SERVE             1 = leave the dashboard running at the end (default 1)
#   ADDR              dashboard listen address (default 127.0.0.1:7396)
set -uo pipefail

AGENTPROV="${AGENTPROV:?set AGENTPROV to the agentprov binary}"
SENSOR="${SENSOR:?set SENSOR to the agentprov-sensor binary}"
KUBECTL="${KUBECTL:-k3s kubectl}"
IMAGE="${IMAGE:-docker.io/library/python:3-slim}"
DNS_SERVER="${DNS_SERVER:-10.211.55.1}"
DATA="${DATA:-/home/agentprov/agentprov-demo}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-50}"
SERVE="${SERVE:-1}"
ADDR="${ADDR:-127.0.0.1:7396}"
RUN="claude-demo"
POD="claude-agent"
NS="default"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== render the agent workload + pod manifest"
cat > "$WORK/agent_demo.py" <<'PY'
import json
import os
import time
import urllib.request


def call(name, url, headers, body):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print(name, r.status, r.read()[:160], flush=True)
    except Exception as e:  # noqa: BLE001 - demo loop must survive 401/network errors
        print(name, "ERR", getattr(e, "code", e), flush=True)


ak = os.environ.get("ANTHROPIC_API_KEY", "")
dk = os.environ.get("DEEPSEEK_API_KEY", "")
i = 0
while True:
    i += 1
    call(
        "anthropic",
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": ak, "anthropic-version": "2023-06-01"},
        {
            "model": "claude-sonnet-5",
            "max_tokens": 48,
            "messages": [
                {"role": "user", "content": f"k8s substrate demo ping {i}: reply with one short sentence"}
            ],
        },
    )
    call(
        "deepseek",
        "https://api.deepseek.com/chat/completions",
        {"Authorization": "Bearer " + dk},
        {
            "model": "deepseek-chat",
            "max_tokens": 48,
            "messages": [{"role": "user", "content": f"k8s substrate demo ping {i}"}],
        },
    )
    time.sleep(5)
PY

cat > "$WORK/pod.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  namespace: ${NS}
  labels:
    app: ${POD}
    demo: substrate
spec:
  restartPolicy: Never
  dnsPolicy: "None"
  dnsConfig:
    nameservers:
      - ${DNS_SERVER}
  containers:
    - name: agent
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["python3", "-u", "/demo/agent_demo.py"]
      envFrom:
        - secretRef:
            name: agent-keys
            optional: true
      volumeMounts:
        - name: script
          mountPath: /demo
  volumes:
    - name: script
      configMap:
        name: ${POD}-script
YAML

echo "== (re)create the API-key secret from env (skipped if no keys set)"
if [ -n "${DEEPSEEK_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]; then
  $KUBECTL delete secret agent-keys -n "$NS" >/dev/null 2>&1
  $KUBECTL create secret generic agent-keys -n "$NS" \
    --from-literal=DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-placeholder}" \
    --from-literal=ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-placeholder}" >/dev/null
  dsstate=$([ -n "${DEEPSEEK_API_KEY:-}" ] && echo "real key" || echo placeholder)
  anstate=$([ -n "${ANTHROPIC_API_KEY:-}" ] && echo "real key" || echo placeholder)
  echo "  secret agent-keys set (deepseek=$dsstate, anthropic=$anstate)"
else
  echo "  no keys in env; reusing existing agent-keys secret if present (calls 401 otherwise)"
fi

echo "== deploy the agent pod"
$KUBECTL delete pod "$POD" -n "$NS" --force --grace-period=0 >/dev/null 2>&1
$KUBECTL create configmap "${POD}-script" -n "$NS" --from-file="$WORK/agent_demo.py" \
  --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
$KUBECTL apply -f "$WORK/pod.yaml" >/dev/null
for _ in $(seq 1 40); do
  [ "$($KUBECTL get pod "$POD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] && break
  sleep 2
done
[ "$($KUBECTL get pod "$POD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] || {
  echo "FAIL: pod did not reach Running (image '$IMAGE' present in cluster containerd?)"
  echo "  hint: docker pull '$IMAGE' && docker save '$IMAGE' | k3s ctr images import -"
  exit 1; }
echo "  pod Running; giving it a few call cycles"
sleep 12
$KUBECTL logs "$POD" -n "$NS" --tail=4 | sed 's/^/  log: /'

echo "== resolve the pod's pid / cgroup / libssl, capture ${CAPTURE_SECONDS}s from the node"
PID="$(pgrep -f agent_demo.py | head -1)"
[ -n "$PID" ] || { echo "FAIL: agent process not found on the node"; exit 1; }
LIBSSL="/proc/$PID/root/usr/lib/aarch64-linux-gnu/libssl.so.3"
[ -e "$LIBSSL" ] || LIBSSL="/proc/$PID/root/usr/lib/x86_64-linux-gnu/libssl.so.3"
CGREL="$(awk -F:: '{print $2}' "/proc/$PID/cgroup")"
CGID="$(stat -c %i "/sys/fs/cgroup$CGREL")"
PODUID="$($KUBECTL get pod "$POD" -n "$NS" -o jsonpath='{.metadata.uid}')"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  pid=$PID cgroup=$CGID pod_uid=$PODUID libssl=$LIBSSL"

docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /sys/kernel/debug:/sys/kernel/debug -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$SENSOR":/agentprov-sensor:ro -v "$WORK":/out \
  -e AGENTPROV_SSL_LIB="$LIBSSL" \
  ubuntu:24.04 bash -c \
  "/agentprov-sensor >/out/sensor.jsonl 2>/out/sensor.err & SP=\$!; sleep $CAPTURE_SECONDS; kill \$SP 2>/dev/null" \
  >/dev/null 2>&1

J="$WORK/sensor.jsonl"
execveN=$(grep -c execve "$J")
tlsN=$(grep -cE '"event_type":"tls_' "$J")
cgN=$(grep -cF "\"cgroup_id\":\"$CGID\"" "$J")
echo "  captured: execve=$execveN tls=$tlsN pod-cgroup-events=$cgN"
[ "$cgN" -ge 1 ] || { echo "FAIL: no telemetry attributed to the pod cgroup"; exit 1; }

echo "== bind pod cgroup + metadata -> run, ingest, export, verify"
rm -rf "$DATA" && "$AGENTPROV" --data-dir "$DATA" init >/dev/null
"$AGENTPROV" --data-dir "$DATA" sandbox bind-cgroup --run "$RUN" \
  --cgroup-id "$CGID" --session "$PODUID" --started-at "$START" \
  --pod-name "$POD" --namespace "$NS" --labels app="$POD",demo=substrate | sed 's/^/  /'
grep -F "\"cgroup_id\":\"$CGID\"" "$J" > "$WORK/pod.jsonl"
# AGENTPROV_TLS_CAPTURE_BODY=1 keeps the full request/response bodies (the actual
# prompt + completion) so the dashboard can show them, matching what the `launch`
# integrated path does. Without it only a sha256 + 80-char preview is stored.
AGENTPROV_TLS_CAPTURE_BODY=1 "$AGENTPROV" --data-dir "$DATA" telemetry ingest-jsonl --run "$RUN" \
  --file "$WORK/pod.jsonl" --format native 2>&1 | grep -o 'read=[0-9]* ingested=[0-9]* skipped=[0-9]* failed=[0-9]*' | sed 's/^/  /'
# Objectify the captured LLM traffic into verifiable llm_message objects + llm_call
# nodes (agent-intent lens). NOTE: request<->response pairing currently keys on the
# logical process_id, which passive node-side capture does not populate, so this
# reports 0 calls until that pairing falls back to pid/cgroup scope.
llmN="$("$AGENTPROV" --data-dir "$DATA" graph materialize-llm --run "$RUN" 2>/dev/null | grep -o '"llm_calls":[0-9]*' | grep -o '[0-9]*')"
echo "  materialized llm_calls=${llmN:-0}"
"$AGENTPROV" --data-dir "$DATA" forensics export "$RUN" >/dev/null 2>&1
verify="$("$AGENTPROV" --data-dir "$DATA" graph verify --run "$RUN" 2>&1 | head -1)"
echo "  $verify"
echo "$verify" | grep -q "errors=0" || { echo "FAIL: demo run did not verify clean"; exit 1; }

tlsRead=$(grep -c '"event_type":"tls_read"' "$WORK/pod.jsonl")
echo "PASS: k8s pod observed from the node -> run '$RUN' (verify errors=0; tls_read bodies=$tlsRead)"

if [ "$SERVE" = "1" ]; then
  pkill -f "dashboard serve" 2>/dev/null
  setsid nohup "$AGENTPROV" --data-dir "$DATA" dashboard serve --addr "$ADDR" \
    >/tmp/agentprov-demo-dashboard.log 2>&1 < /dev/null &
  sleep 2
  echo "== dashboard: http://$ADDR/  (run '$RUN', substrate lens)"
  echo "   from a workstation: ssh -f -N -L ${ADDR##*:}:$ADDR <node> then open http://localhost:${ADDR##*:}/"
fi
