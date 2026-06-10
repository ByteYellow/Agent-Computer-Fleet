# agent-computer-fleet MVP

`agent-computer-fleet` is a CLI-first single-node Agent Computer Control Plane.

The first binary is `acfctl`. It manages local leases, Docker-backed sandbox
sessions, directory snapshots, prepared workspace forks, MVP policy decisions,
and run-level cost counters.

## Quick path

```sh
acfctl init
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl session list
acfctl session inspect <session_id>
acfctl exec <session_id> --stream -- go version
acfctl exec <session_id> --stream -- sh -lc 'echo hello > hello.txt'
acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl fork ready --count 2
acfctl policy test examples/events/metadata-egress.jsonl
acfctl policy decisions --run run-demo-bugfix
acfctl cost show run-demo-bugfix
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

## Demos

### demo_streaming_terminal

```sh
lease_id=$(acfctl lease create --task examples/tasks/bugfix.yaml)
session_id=$(acfctl session create --lease "$lease_id")
acfctl exec "$session_id" --stream -- go version
```

### demo_snapshot_fanout

```sh
acfctl exec "$session_id" --stream -- sh -lc 'echo base > hello.txt'
acfctl snapshot create "$session_id" --type directory --path /workspace --name ready
acfctl fork ready --count 3
```

Each forked attempt prints an `attempt_id`, workspace path, and `fork_ms`.
Modify files under one attempt workspace and verify the other attempt workspaces
do not change.

### demo_metadata_egress_quarantine

```sh
acfctl policy test examples/events/metadata-egress.jsonl
acfctl policy decisions --run run-demo-bugfix
```

The metadata IP event produces a `quarantine` decision. If the referenced
session exists locally, it is marked `quarantined` and its snapshots are tainted.

### demo_cost_per_run

```sh
acfctl cost show run-demo-bugfix
```

The output includes `active_cpu_seconds`, `idle_seconds`, `wall_seconds`,
`snapshot_bytes`, `policy_block_count`, `quarantine_count`, and `cost_per_run`.

### demo_active_cpu_overcommit

```sh
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

This is a simulation for v1. It shows how idle-heavy sessions are admitted using
`active_cpu_request + idle_cpu_request * idle_discount`.

## MVP limits

- Docker must be running for `session`, `exec`, and `process` commands.
- Directory snapshots are supported; memory snapshots are intentionally not.
- `port expose` records a preview URL event. Real dynamic port proxying is a
  follow-up because Docker cannot add host port bindings after container create.
