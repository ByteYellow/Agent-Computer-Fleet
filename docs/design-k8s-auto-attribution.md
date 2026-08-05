# Design: zero-touch K8s pod attribution (auto pod-scope binding)

Status: one-shot capture, the real sensor DaemonSet, and a lightweight
`client-go` Pod informer controller are implemented. The controller's
create/restart/delete binding lifecycle is validated on single-node K3s. A
full operator, HA/leader election, and cluster-wide evidence service remain
deferred.

## Problem

The sensor deploys as a DaemonSet
(`deploy/k8s/agentprov-sensor-daemonset.yaml`) and streams normalized JSONL.
`sandbox capture` collapses one-pod capture/bind/ingest into one command, while
`sandbox watch` List/Watches pod metadata and maintains passive bindings for
running containers. The environment gate in `scripts/accept_k8s_node_multiworkload.sh`
independently proves the production-shaped seam: one actual DaemonSet observes
N pods, Kubernetes pod/container identity resolves to cgroup ids present in the
kernel stream, and all scoped evidence verifies in one run.

The pieces already exist and are reused, not rebuilt:
- `cgroupResolver` (`internal/sensor/sensor_linux.go`) already parses
  `kubepods/<uid>/…<container-id>` → container id from the cgroup dir name.
- `producer.BindCgroupScope` / `correlation.RecordBinding` write the binding row
  (`k8s_cgroup`, confidence 0.8). **No schema change.**
- The daemon ingest API (`POST /v1/telemetry/*`) already accepts streamed events.
- `bind-cgroup` already records pod metadata as a context event.

The remaining product gap is production operator hardening rather than basic
attribution: HA/leader election, upgrade orchestration, and multi-node shared
state are intentionally outside this local-first controller.

## Two phases

### Phase 1 — `agentprov sandbox capture` (one-shot, manual trigger) — implemented

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

### Phase 2 — controller (auto, zero-touch) — lightweight informer implemented

A control loop runs as a small node-local DaemonSet companion to the sensor:
1. A filtered `client-go` informer List/Watches pods scheduled on this node,
   with an optional label selector and Pod-only `get/list/watch` RBAC.
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

`agentprov sandbox watch` is now the informer controller. It resolves a
container id against the host cgroup tree, records the cgroup inode as the
kernel join key, keeps PID as supplementary evidence, closes the exact prior
binding when a container restarts, and closes all remaining bindings when the
Pod is deleted. The previous kubectl polling implementation remains hidden as
`sandbox watch-poll` only for diagnostics and compatibility.

The repository uses `client-go v0.32.0` because its current Go baseline is
1.23. The Pod core/v1 List/Watch path was live-validated against K3s 1.36.2;
this is a tested compatibility point, not a claim that every Kubernetes minor
is covered.

## Scope / non-goals

- No core/graph/schema change (consistent with v0.7's whole premise).
- Not a scheduler; not prevention; detect-mode only.
- Model-intent (TLS) capture is orthogonal and unchanged here (#2/#3 track it).

## Acceptance

- `agentprov sandbox capture --pod X` on the lab VM: a pod never touched by
  `record` gets attributed + `graph verify errors=0` — same as the manual demo,
  one command.
- DaemonSet node gate: `accept_k8s_node_multiworkload.sh` deploys the actual
  DaemonSet, starts 8 pods by default, maps pod/container identity to observed
  kernel cgroups, ingests the JSONL stream, and requires `graph verify` with
  zero errors/warnings. Reference result: 8 cgroups, 1,140 events.
- Informer lifecycle gate: `accept_k8s_informer_controller.sh` deploys the
  checked controller manifest, creates an annotated Pod, forces a container
  restart under the same Pod UID, and deletes the Pod. The reference K3s run
  created two bindings, closed both, observed one restart, retained zero active
  bindings, and reported zero retries/failures/resolution failures.
