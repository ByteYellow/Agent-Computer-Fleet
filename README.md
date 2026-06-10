# Agent Computer Fleet

`agent-computer-fleet` is a CLI-first Agent Computer Control Plane for AI agent
sandbox workloads.

Agent Computer Control Plane for AI agents: pluggable sandbox runtimes with
streaming exec, workspace snapshot/fork, runtime policy response, telemetry
correlation, and active-CPU-aware cost accounting for secure, reproducible,
high-density sandbox fleets.

It treats a sandbox as a controllable computer with identity, lifecycle,
filesystem, process execution, snapshots, forks, telemetry, policy response, and
cost accounting.

## V1 status

The v1 MVP lives in:

```text
agent-computer-fleet/
```

It can run a local Docker-backed flow:

```sh
cd agent-computer-fleet
./scripts/demo_v1.sh
```

The demo covers:

- streaming terminal execution
- workspace snapshot
- snapshot fanout into multiple attempt workspaces
- metadata egress quarantine policy
- run-level cost output
- active-CPU-aware overcommit simulation
- session cleanup

## Architecture

Agent Computer Control Plane:

- Ingress Plane: CLI/API, lease, stream, preview
- Control Plane: scheduling, quota, state, policy, GC
- Node Plane: session, runtime, pool, cgroup, telemetry
- State Plane: template, snapshot, fork, resume, taint
- Security Plane: egress, secret, telemetry, policy, quarantine
- Economics Plane: prewarm, sleep/wake, active CPU, overcommit

## Documents

- `01-atomized-design-online-CN.MD`: v2 atomized design based on online product research.
- `02-paper-algorithm-map-CN.MD`: mapping papers and algorithms to implementable project mechanisms.
- `agent-computer-fleet/README.md`: engineering quick start and v1 command reference.

## V1 boundaries

V1 is single-node and Docker-first. It intentionally does not implement
multi-node Fleet Manager, Raft, Firecracker memory snapshots, live migration,
deep-learning anomaly detection, or custom eBPF LSM enforcement.
