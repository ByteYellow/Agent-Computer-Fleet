# agent-computer-fleet MVP

`agent-computer-fleet` is a CLI-first single-node Agent Computer Control Plane.

The first binary is `acfctl`. It manages local leases, Docker-backed sandbox
sessions, preview URL proxies, runtime/template registries, directory
snapshots, prepared workspace forks, structured Agent Computer API calls,
telemetry, MVP policy decisions, provenance traces, forensics bundles, and
run/session/node-level cost counters.

## Quick path

```sh
acfctl init
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl session list
acfctl session inspect <session_id>
acfctl exec <session_id> --stream -- sh -lc 'echo hello > hello.txt'
acfctl runtime list
acfctl template build --task examples/tasks/bugfix.yaml --name bugfix
acfctl snapshot stack --template bugfix
acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl snapshot list
acfctl snapshot inspect ready
acfctl fork ready --count 2
acfctl snapshot resume ready --lease <lease_id>
acfctl attempt best-of --snapshot ready --strategy "pass::test -f hello.txt" --strategy "fail::test -f missing.txt"
acfctl policy test examples/events/metadata-egress.jsonl
acfctl policy decisions --run run-demo-bugfix
acfctl api write-file <session_id> --path notes.txt --content hello
acfctl telemetry list --session <session_id>
acfctl graph trace --run run-demo-bugfix
acfctl forensics export run-demo-bugfix
acfctl cost sample <session_id>
acfctl cost show run-demo-bugfix
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

## Demos

### demo_streaming_terminal

```sh
lease_id=$(acfctl lease create --task examples/tasks/bugfix.yaml)
session_id=$(acfctl session create --lease "$lease_id")
acfctl exec "$session_id" --stream -- sh -lc 'echo hello'
```

### demo_preview_url

```sh
./scripts/demo_preview_url.sh
```

This starts a tiny HTTP service inside the sandbox and exposes it through a
host-local preview URL. `port list` shows the proxy and `port close` shuts it
down without leaving a residual proxy process.

### demo_snapshot_fanout

```sh
./scripts/demo_snapshot_fanout.sh
```

Equivalent manual flow:

```sh
acfctl exec "$session_id" --stream -- sh -lc 'echo base > hello.txt'
acfctl snapshot create "$session_id" --type directory --path /workspace --name ready
acfctl snapshot list
acfctl snapshot inspect ready
acfctl fork ready --count 3
resume_lease_id=$(acfctl lease create --task examples/tasks/bugfix.yaml)
acfctl snapshot resume ready --lease "$resume_lease_id"
```

Each forked attempt prints an `attempt_id`, workspace path, and `fork_ms`.
Modify files under one attempt workspace and verify the other attempt workspaces
do not change. `snapshot resume` copies the directory snapshot back into a new
workspace and starts a new running Docker session with parent snapshot lineage.

### demo_runtime_capabilities

```sh
acfctl runtime list
acfctl runtime inspect docker
acfctl runtime inspect firecracker
```

The Docker backend reports `exec`, `stop`, `snapshot`, `fork`, and `resume` as
available, with `memory_snapshot=false`. Firecracker, gVisor, and bubblewrap are
registered as capability-gated stubs and do not report unavailable features as
usable.

### demo_snapshot_stack

```sh
acfctl template build --task examples/tasks/bugfix.yaml --name bugfix
acfctl snapshot stack --template bugfix
acfctl snapshot list
acfctl snapshot inspect <ready_snapshot_id>
```

This records `template -> ready snapshot -> attempt workspace` lineage. Use
`snapshot inspect <snapshot_id>` to see kind, parent, manifest hash, status, and
storage bytes.

### demo_best_of_forks

```sh
./scripts/demo_best_of_forks.sh
```

Equivalent manual flow:

```sh
acfctl attempt best-of --snapshot ready \
  --strategy "pass::test -f hello.txt" \
  --strategy "fail::test -f missing.txt"
```

The command forks one workspace per strategy, executes each command in its own
attempt workspace, records exit code, wall time, output summary, score, and
marks the winning attempt.

### demo_metadata_egress_quarantine

```sh
./scripts/demo_policy_quarantine.sh
./scripts/demo_egress_proxy.sh
```

Equivalent manual flow:

```sh
acfctl egress check --run run-demo-bugfix --session <session_id> --dst-ip 169.254.169.254 --host metadata.local
acfctl policy decisions --run run-demo-bugfix
```

The metadata IP event produces a `quarantine` decision and marks the local
session as quarantined.

### demo_egress_proxy

```sh
./scripts/demo_egress_proxy.sh
```

This starts a Docker session on a session-scoped internal bridge network with an
acf egress proxy sidecar, adds `example.com` to the allowlist, verifies an
allowed HTTP request through the sidecar, verifies direct egress bypass failure,
verifies metadata IP denial, and records a redacted credential injection event.

### demo_cost_per_run

```sh
./scripts/demo_cost_accounting.sh
```

Equivalent manual flow:

```sh
acfctl cost sample <session_id>
acfctl cost show run-demo-bugfix
```

The output includes run-level `active_cpu_seconds`, `idle_seconds`,
`wall_seconds`, `snapshot_bytes`, `policy_block_count`, `quarantine_count`,
`overcommit_ratio`, `active_cpu_debt`, `queue_pressure`, and `cost_per_run`,
plus session-level and node-level cost rows.

### demo_provenance_trace

```sh
./scripts/demo_provenance_trace.sh
```

This records file, artifact, process, tool call, policy decision, and forensics
bundle data, then prints `telemetry list` and `graph trace` output.

### demo_baseline_pool_node

```sh
acfctl baseline learn --template bugfix --run run-demo-bugfix
acfctl baseline check --template bugfix --run run-demo-bugfix
acfctl pool create --template bugfix --size 2
acfctl pool status
acfctl node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
acfctl node list
```

### demo_active_cpu_overcommit

```sh
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

This simulation uses the same single-node scheduler admission function as
`session create`. It shows how idle-heavy sessions are admitted using
`active_cpu_request + idle_cpu_request * idle_discount`, while memory is not
overcommitted.

## MVP limits

- Docker must be running for `session`, `exec`, and `process` commands.
- Directory snapshot/fork/resume is supported; memory snapshots are
  intentionally not.
- Runtime backends are capability-gated. Docker is active; Firecracker, gVisor,
  and bubblewrap are stubs.
- Scheduler/admission is single-node and conservative. Multi-node placement is
  still a follow-up.
- `port expose` is an HTTP preview proxy, not a raw TCP tunnel.
- Egress control currently covers HTTP/HTTPS proxy workflows and blocks direct
  outbound traffic from the Docker sandbox bridge. Raw TCP protocol policy is
  still a follow-up.
- The node registry is local metadata. Multi-node scheduling is still a
  follow-up.
