# agent-computer-fleet

`agent-computer-fleet` is a CLI-first Agent Computer Control Plane for local AI
agent sandboxes.

It treats a sandbox as a leaseable, executable, snapshotable, forkable, auditable
computer instead of a one-shot container.

## What v1 proves

- Docker-backed sandbox sessions can be created and executed through `acfctl`.
- `/workspace` can be snapshotted and forked into independent attempt workspaces.
- Policy events can be correlated with `run_id` and `session_id`, then persisted.
- Risky events can quarantine sessions and taint snapshots.
- Run-level cost output includes active CPU, wall time, snapshot bytes, policy
  blocks, quarantines, and an estimated `cost_per_run`.

## Quick start

Prerequisites:

- Go 1.23+
- Docker Desktop or a compatible Docker daemon

```sh
go build ./cmd/acfctl

./acfctl init
lease_id=$(./acfctl lease create --task examples/tasks/bugfix.yaml)
session_id=$(./acfctl session create --lease "$lease_id")

./acfctl session inspect "$session_id"
./acfctl exec "$session_id" --stream -- go version
./acfctl exec "$session_id" --stream -- sh -lc 'echo hello > hello.txt'

./acfctl snapshot create "$session_id" --type directory --path /workspace --name ready
./acfctl snapshot list
./acfctl snapshot inspect ready
./acfctl fork ready --count 3
./acfctl attempt best-of --snapshot ready \
  --strategy "pass::test -f hello.txt" \
  --strategy "fail::test -f missing.txt"

./acfctl policy test examples/events/metadata-egress.jsonl
./acfctl policy decisions --run run-demo-bugfix
./acfctl cost show run-demo-bugfix
./acfctl session rm "$session_id"
```

Or run the full v1 demo:

```sh
./scripts/demo_v1.sh
```

## V1 commands

```sh
acfctl init
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl session list
acfctl session inspect <session_id>
acfctl session stop <session_id>
acfctl session rm <session_id>
acfctl exec <session_id> --stream -- <command...>
acfctl process interrupt <process_id>
acfctl port expose <session_id> <port>
acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl snapshot stack --task examples/tasks/bugfix.yaml
acfctl snapshot list
acfctl snapshot inspect <snapshot_name_or_id>
acfctl fork ready --count 3
acfctl attempt best-of --snapshot ready --strategy "name::command"
acfctl policy test examples/events/metadata-egress.jsonl
acfctl policy decisions --run <run_id>
acfctl cost show <run_id>
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

## V1 boundaries

V1 is intentionally single-node and Docker-first. It does not implement
multi-node scheduling, Raft, Firecracker memory snapshots, live migration,
deep-learning anomaly detection, or custom eBPF LSM enforcement.
