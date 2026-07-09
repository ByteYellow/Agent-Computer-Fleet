# Design: zero-touch K8s pod attribution (auto pod-scope binding)

Status: proposal for sign-off. Turns the k8s-daemonset profile from a manual
node-side script into `kubectl apply` + it-just-works.

## Problem

Today the sensor deploys as a DaemonSet (`deploy/k8s/agentprov-sensor-daemonset.yaml`)
and streams events, but attributing a pod's telemetry to a run is manual: resolve
`pid → cgroup`, read pod metadata from the K8s API, call `sandbox bind-cgroup`
per pod, then ingest. That is the ~12-step flow in `scripts/demo_k8s_a2a.sh`.
Nobody deploys that. The barrier is the gap between "sensor sees the cgroup" and
"scope is bound to it."

The pieces already exist and are reused, not rebuilt:
- `cgroupResolver` (`internal/sensor/sensor_linux.go`) already parses
  `kubepods/<uid>/…<container-id>` → container id from the cgroup dir name.
- `producer.BindCgroupScope` / `correlation.RecordBinding` write the binding row
  (`k8s_cgroup`, confidence 0.8). **No schema change.**
- The daemon ingest API (`POST /v1/telemetry/*`) already accepts streamed events.
- `bind-cgroup` already records pod metadata as a context event.

The only missing thing is the **glue that watches pods and binds automatically**.

## Two phases

### Phase 1 — `agentprov sandbox capture` (one-shot, manual trigger) ← build first

A single node-side command that collapses the manual flow for one running pod:

```
agentprov sandbox capture --pod <name> --namespace <ns> \
  [--run <id>] [--seconds 45] [--kubectl "k3s kubectl"]
```

It does, in-process, exactly what the demo script does by hand:
1. Resolve the pod's `pid` (scan `/proc/*/cgroup` for the pod's cgroup, or take
   `--pid`), its cgroup id (`stat -c %i`), and pull pod metadata from the K8s API
   (namespace/uid/node/container/image/service-account/labels/pod-ip) via kubectl.
2. Run the sensor for `--seconds` (or attach to an already-running DaemonSet
   sensor's spool), filtered to the pod's cgroup.
3. `bind-cgroup` (all metadata auto-filled) + ingest the pod-scoped events into
   the run.
4. Print the one-line attribution result (run id, cgroup, confidence).

Value: the 12-step script becomes one command. Pure Go + kubectl exec; no eBPF
change; testable on the lab VM immediately. This is the near-term face of #1 and
de-risks phase 2.

### Phase 2 — informer/controller (auto, zero-touch) ← the product shape

A control loop (runs in the DaemonSet pod, or as a small sidecar) that:
1. Watches the K8s API for pods scheduled on this node (a client-go informer, or
   — to avoid the client-go dep — polls `kubelet /pods` or `crictl`).
2. For each new pod, resolves its cgroup (the informer gives the pod UID; the
   cgroup path is `kubepods…/pod<uid>` — already the format `cgroupResolver`
   knows), and calls the same `BindCgroupScope` + metadata enrichment as phase 1,
   automatically, at pod start.
3. The DaemonSet sensor already streams events tagged with `cgroup_id`; the
   binding makes them attribute to the pod's run with no per-pod action.

Result: `kubectl apply -f agentprov-sensor-daemonset.yaml` and every pod on the
node is attributed automatically. A pod annotation (e.g.
`agentprov.io/run: <id>`) lets a workload opt its telemetry into a named run;
absent that, each pod gets an auto-run keyed by its UID.

Open choice for phase 2: **client-go informer** (accurate, adds a large dep +
RBAC) vs **kubelet/crictl poll** (no dep, works with the existing node mounts,
slightly less immediate). Recommendation: start with the kubelet/crictl poll (no
new dep, matches the "node sensor is self-contained" posture); add the informer
only if sub-second pod-start attribution is needed.

## Scope / non-goals

- No core/graph/schema change (consistent with v0.7's whole premise).
- Not a scheduler; not prevention; detect-mode only.
- Model-intent (TLS) capture is orthogonal and unchanged here (#2/#3 track it).

## Acceptance

- `agentprov sandbox capture --pod X` on the lab VM: a pod never touched by
  `record` gets attributed + `graph verify errors=0` — same as the manual demo,
  one command.
- Phase 2: deploy the DaemonSet, start a pod, and its telemetry shows up
  attributed to a run with no manual step, within N seconds of pod start.
