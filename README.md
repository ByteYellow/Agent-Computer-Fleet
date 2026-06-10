# agent-computer-fleet

`agent-computer-fleet` is a CLI-first Agent Computer Control Plane for local AI
agent sandboxes.

It treats a sandbox as a leaseable, executable, snapshotable, forkable, auditable
computer instead of a one-shot container.

## What v1 proves

- Docker-backed sandbox sessions can be created and executed through `acfctl`.
- Sandbox HTTP services can be exposed through a local preview URL proxy.
- Runtime backends are registered behind a common interface, with Docker active
  and gVisor/Firecracker/bubblewrap represented as extension targets.
- Environment templates can be built from task YAML and used to derive
  `template -> ready snapshot -> attempt workspace` lineage.
- `/workspace` can be snapshotted and forked into independent attempt workspaces.
- Structured Agent Computer API calls can read/write/search/export/call inside a
  sandbox and record `run_id`, `session_id`, `tool_call_id`, and `result_ref`.
- Runtime telemetry, policy decisions, provenance traces, and forensics bundles
  are persisted in SQLite.
- Risky runtime/API/egress events can kill or quarantine sessions and taint
  snapshots where applicable.
- Run-level cost output includes active CPU, wall time, snapshot bytes, policy
  blocks, quarantines, Docker stats samples, overcommit ratio, active CPU debt,
  and an estimated `cost_per_run`.

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
./acfctl exec "$session_id" --stream -- sh -lc 'echo hello > hello.txt'
./acfctl port expose "$session_id" 8000

./acfctl runtime list
./acfctl template build --task examples/tasks/bugfix.yaml --name bugfix
./acfctl snapshot stack --template bugfix
./acfctl snapshot create "$session_id" --type directory --path /workspace --name ready
./acfctl snapshot list
./acfctl snapshot inspect ready
./acfctl fork ready --count 3
./acfctl attempt best-of --snapshot ready \
  --strategy "pass::test -f hello.txt" \
  --strategy "fail::test -f missing.txt"

./acfctl policy test examples/events/metadata-egress.jsonl
./acfctl policy decisions --run run-demo-bugfix
./acfctl api write-file "$session_id" --path notes.txt --content 'hello'
./acfctl telemetry list --session "$session_id"
./acfctl graph trace --run run-demo-bugfix
./acfctl forensics export run-demo-bugfix
./acfctl cost sample "$session_id"
./acfctl cost show run-demo-bugfix
./acfctl session rm "$session_id"
```

Run the main v1 demo or one focused demo:

```sh
./scripts/demo_v1.sh
./scripts/demo_preview_url.sh
./scripts/demo_snapshot_fanout.sh
./scripts/demo_best_of_forks.sh
./scripts/demo_policy_quarantine.sh
./scripts/demo_cost_accounting.sh
./scripts/demo_provenance_trace.sh
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
acfctl port list
acfctl port close <port_id>
acfctl runtime list
acfctl runtime inspect docker
acfctl template build --task examples/tasks/bugfix.yaml --name bugfix
acfctl template list
acfctl template inspect bugfix
acfctl api read-file <session_id> --path notes.txt
acfctl api write-file <session_id> --path notes.txt --content hello
acfctl api search <session_id> --pattern hello
acfctl api export-artifact <session_id> --path notes.txt
acfctl api call <session_id> --module shell --function exec --command 'echo ok'
acfctl telemetry list --run <run_id>
acfctl graph trace --run <run_id>
acfctl forensics export <run_id>
acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl snapshot stack --template bugfix
acfctl snapshot list
acfctl snapshot inspect <snapshot_name_or_id>
acfctl fork ready --count 3
acfctl attempt best-of --snapshot ready --strategy "name::command"
acfctl policy test examples/events/metadata-egress.jsonl
acfctl policy decisions --run <run_id>
acfctl egress check --run <run_id> --session <session_id> --dst-ip 169.254.169.254
acfctl credential inject --run <run_id> --session <session_id> --name github-token --host api.github.com
acfctl cost sample <session_id>
acfctl cost show <run_id>
acfctl baseline learn --template bugfix --run <run_id>
acfctl baseline check --template bugfix --run <run_id>
acfctl pool create --template bugfix --size 2
acfctl pool status
acfctl node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
acfctl node list
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

## V1 boundaries

V1 is still Docker-first and local-first. It has a node registry and placement
signals, but not a real distributed scheduler. It does not implement Raft,
Firecracker memory snapshots, live migration, deep-learning anomaly detection,
or custom eBPF LSM enforcement.
