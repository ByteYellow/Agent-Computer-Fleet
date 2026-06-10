# Agent Computer Fleet

Agent Computer Fleet is a local-first control plane for AI agent sandboxes.

It treats a sandbox as an **agent computer**: leaseable, executable,
snapshotable, forkable, auditable, policy-controlled, and cost-accounted. The
first implementation is CLI-first through `acfctl` and uses Docker as the
active runtime backend.

## Status

This repository is an early MVP. It is useful for demos, local experiments, and
architecture validation. It is not yet a production sandbox fleet.

Current focus:

- Docker-backed sandbox sessions and streaming exec
- Preview URL proxy for sandbox HTTP services
- Directory snapshot, fork, template lineage, and best-of-forks
- Runtime telemetry, policy decisions, provenance trace, and forensics bundle
- Active CPU cost sampling, conservative admission model, and warm pool signals
- Extension points for gVisor, Firecracker, bubblewrap, egress proxy, and
  multi-node scheduling

## Why

Most agent sandboxes are treated as short-lived containers. This project is
exploring a stronger abstraction: an agent computer that can be rented, paused
conceptually, snapshotted, forked into attempts, inspected, quarantined, and
priced per run.

The long-term goal is to prove four capabilities:

- **Agent runtime observability**: correlate process, file, network, resource,
  artifact, and policy events with `run_id`, `session_id`, and `tool_call_id`.
- **Behavior baseline and response**: detect risky behavior and trigger
  `deny`, `kill`, `quarantine`, `taint_snapshot`, or forensics export.
- **Lightweight isolation and reproducibility**: start with Docker namespaces,
  cgroups, seccomp, and local snapshots, then extend to gVisor, Firecracker, and
  eBPF-based telemetry/enforcement.
- **Fleet economics**: account for active CPU, idle time, warm pools,
  overcommit, snapshot bytes, and cost per run.

## Architecture

Agent Computer Fleet is organized around six planes:

```text
Ingress Plane    CLI/API, lease, streaming exec, preview URL
Control Plane    session allocation, state machine, admission, quota
Node Plane       runtime adapters, process manager, node heartbeat
State Plane      template, workspace, snapshot, fork, lineage, taint
Security Plane   policy, telemetry correlation, response, forensics
Economics Plane  active CPU, warm pool, overcommit, cost accounting
```

The current binary is `acfctl`. A daemon/API server is a planned next step.

## Quick Start

Prerequisites:

- Go 1.23+
- Docker Desktop or a compatible Docker daemon

```sh
go build ./cmd/acfctl

./acfctl init
lease_id=$(./acfctl lease create --task examples/tasks/bugfix.yaml)
session_id=$(./acfctl session create --lease "$lease_id")

./acfctl exec "$session_id" --stream -- sh -lc 'echo hello > hello.txt'
./acfctl snapshot create "$session_id" --type directory --path /workspace --name ready
./acfctl fork ready --count 3
./acfctl attempt best-of --snapshot ready \
  --strategy "pass::test -f hello.txt" \
  --strategy "fail::test -f missing.txt"

./acfctl cost sample "$session_id"
./acfctl cost show run-demo-bugfix
./acfctl session rm "$session_id"
```

## Demos

Run the full MVP walkthrough:

```sh
./scripts/demo_v1.sh
```

Run focused demos:

```sh
./scripts/demo_preview_url.sh
./scripts/demo_snapshot_fanout.sh
./scripts/demo_best_of_forks.sh
./scripts/demo_policy_quarantine.sh
./scripts/demo_cost_accounting.sh
./scripts/demo_provenance_trace.sh
```

See [docs/mvp.md](docs/mvp.md) for the detailed command-by-command demo guide.

## Command Surface

Core workflow:

```sh
acfctl init
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl exec <session_id> --stream -- <command...>
acfctl port expose <session_id> <port>
acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl fork ready --count 3
acfctl attempt best-of --snapshot ready --strategy "name::command"
acfctl cost show <run_id>
```

Control and state:

```sh
acfctl session list
acfctl session inspect <session_id>
acfctl session stop <session_id>
acfctl session rm <session_id>
acfctl process interrupt <process_id>
acfctl template build --task examples/tasks/bugfix.yaml --name bugfix
acfctl template list
acfctl template inspect bugfix
acfctl snapshot stack --template bugfix
acfctl snapshot list
acfctl snapshot inspect <snapshot_name_or_id>
```

Security, telemetry, and provenance:

```sh
acfctl api write-file <session_id> --path notes.txt --content hello
acfctl api read-file <session_id> --path notes.txt
acfctl api search <session_id> --pattern hello
acfctl api export-artifact <session_id> --path notes.txt
acfctl api call <session_id> --module shell --function exec --command 'echo ok'
acfctl telemetry list --run <run_id>
acfctl policy test examples/events/metadata-egress.jsonl
acfctl policy decisions --run <run_id>
acfctl graph trace --run <run_id>
acfctl forensics export <run_id>
```

Economics and fleet signals:

```sh
acfctl cost sample <session_id>
acfctl baseline learn --template bugfix --run <run_id>
acfctl baseline check --template bugfix --run <run_id>
acfctl pool create --template bugfix --size 2
acfctl pool status
acfctl node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
acfctl node list
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

Runtime and egress extension points:

```sh
acfctl runtime list
acfctl runtime inspect docker
acfctl egress check --run <run_id> --session <session_id> --dst-ip 169.254.169.254
acfctl credential inject --run <run_id> --session <session_id> --name github-token --host api.github.com
```

## What Works Now

- `docker` runtime adapter can create sessions and run commands.
- `port expose` provides a local HTTP preview proxy.
- Directory snapshots can be created and forked into independent attempt
  workspaces.
- Templates can derive `template -> ready snapshot -> attempt workspace`
  lineage.
- Best-of-forks can run multiple strategies and select a winner.
- Structured API calls produce telemetry and policy decisions.
- Metadata IP and secret-path events can trigger quarantine or kill decisions in
  the MVP enforcement path.
- Forensics bundles can export run evidence.
- Docker stats can be sampled into run cost metrics.

## Current Boundaries

- Docker is the only fully active runtime backend today.
- gVisor, Firecracker, and bubblewrap are registered extension targets, not
  complete adapters.
- Snapshot support is directory-level only; memory snapshot/resume is not
  implemented.
- The egress proxy is currently a policy/telemetry path, not a mandatory network
  chokepoint for all sandbox traffic.
- The node registry captures scheduling signals, but there is no distributed
  scheduler yet.
- Baseline detection is MVP-level event/cost counting, not syscall ML or eBPF
  feature modeling.

## Roadmap

Near term:

- Mandatory egress proxy and real credential injection
- Daemon/API server behind `acfctl`
- Continuous Docker stats/cgroup sampler
- YAML policy rule engine
- Snapshot resume and taint propagation
- Stronger process manager and process tree enforcement

Later:

- gVisor and bubblewrap adapters
- Firecracker disk/memory snapshot path
- Multi-node node agent and placement scheduler
- Falco/Tetragon/eBPF telemetry integration
- Rich provenance graph queries and JSON output mode

## Development

```sh
go test ./...
```

The repository intentionally ignores local `.acf*` state and internal research
notes. Public docs live under `docs/`; runnable examples live under
`examples/` and `scripts/`.
