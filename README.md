<div align="center">

<h1>Agent Computer Fleet</h1>

### A local-first control plane for agent sandboxes.

<p>
Lease sandbox computers, run commands, snapshot workspaces, fork attempts,
enforce egress policy, and account for cost, from one CLI-first control plane.
</p>

[![Go](https://img.shields.io/badge/go-1.23+-00ADD8.svg?style=flat-square)](https://go.dev/)
[![Runtime](https://img.shields.io/badge/runtime-Docker-2496ED.svg?style=flat-square)](https://www.docker.com/)
[![SQLite](https://img.shields.io/badge/state-SQLite-003B57.svg?style=flat-square)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg?style=flat-square)](LICENSE)

**[Quickstart](#quickstart)** | **[Demos](#demos)** | **[Architecture](#architecture)** | **[Roadmap](#roadmap)**

</div>

---

<table>
<tr>
<td width="50%" valign="top">

#### Agent computer

A sandbox is not just a disposable container. It has a lease, session,
workspace, process history, telemetry, snapshots, and cost.

</td>
<td width="50%" valign="top">

#### Fleet control plane

The first backend is local Docker. The interfaces are shaped so Docker can
later be swapped for gVisor, bubblewrap, Firecracker, or a remote node agent.

</td>
</tr>
<tr>
<td colspan="2" align="center">

v &nbsp; **controlled by** &nbsp; v

```sh
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl exec <session_id> --stream -- <command...>
```

</td>
</tr>
</table>

## Two ideas

Agent Computer Fleet is small on purpose. The MVP is built around two
operations:

| | You do | You get |
|---|---|---|
| **Control** | `acfctl session create`, `acfctl exec`, `acfctl port expose` | A running sandbox session with process records, telemetry, and preview URLs |
| **Branch** | `acfctl snapshot create`, `acfctl fork`, `acfctl attempt best-of` | Reproducible attempt workspaces with lineage, taint status, and fanout cost |

The project treats every run as a traceable object. A command, file event,
network decision, snapshot, artifact, and cost sample can all be tied back to
`run_id`, `session_id`, and, where available, `tool_call_id`.

```sh
./acfctl exec "$SESSION_ID" --stream -- sh -lc 'pytest -q'
./acfctl snapshot create "$SESSION_ID" --type directory --path /workspace --name ready
./acfctl fork ready --count 3
```

## Why this exists

Modern agent workloads are turning sandboxes into a scheduling and observability
problem, not just an execution problem. Evaluation, RL rollouts, best-of-N
sampling, self-repair loops, and tool-using agents can create thousands of
short-lived computers that spend most of their wall time waiting on I/O, model
latency, package installs, tests, or external services. Treating each attempt as
a full-price container leaves a large resource gap: CPU is reserved but idle,
state is rebuilt instead of reused, and security evidence is scattered across
logs, containers, filesystems, and model/tool context.

Agent Computer Fleet is an attempt to make that substrate explicit. It models
an agent sandbox as a leaseable, resumable, forkable, observable, and
cost-accounted computer. The control plane should know which run owns a process,
which snapshot produced an artifact, which tool call caused a network edge, how
much active CPU was actually consumed, and whether a branch came from tainted
state.

The current repository is a local-first MVP. It proves the control-plane shape
with Docker, SQLite, directory snapshots, scheduler admission, and egress
sidecars. The longer-term target is a high-density sandbox fleet that can pair
runtime-level snapshot/resume with scheduler-level time sharing and kernel-level
telemetry.

## Industrial pain points

| Pain point | Why it matters | Control-plane direction |
|---|---|---|
| **High-concurrency RL rollout resource sink** | Rollout fleets multiply sandbox count by task count, sample count, retry count, and evaluator count. Without snapshot reuse and per-run accounting, evaluation infrastructure becomes a CPU, disk, and cold-start sink. | Model every rollout as lease/session/snapshot/attempt/cost; reuse ready state; fan out from snapshots; report cost per run/session/node. |
| **CPU time-sharing and conservative overcommit** | Agent sandboxes are often idle-heavy. Static CPU reservation wastes capacity, while blind overcommit causes throttling and noisy failures. | Track active CPU debt, idle discount, memory pressure, warm-pool signals, and queue pressure before admitting new sessions. Memory is not overcommitted; CPU is overcommitted conservatively. |
| **Fast stop/resume/fork instead of rebuild loops** | Rebuilding workspaces and containers for every attempt destroys iteration speed. Real fleets need a path from ready snapshot to attempt workspace or resumed session. | Keep runtime drivers capability-gated; Docker implements directory snapshot/fork/resume now; VM-capable backends can later expose disk and memory snapshot capabilities. |
| **eBPF dual-axis monitoring** | Security and debugging need both system-side facts and application-side intent. Syscalls alone do not say which agent tool call caused an action; tool logs alone do not prove what happened in the kernel. | Correlate kernel/runtime telemetry such as process, file, network, syscall, cgroup events with `run_id`, `session_id`, `process_id`, `snapshot_id`, and `tool_call_id`. eBPF/Falco/Tetragon integration is a planned telemetry provider, not yet active in this MVP. |

## Quickstart

Prerequisites:

- Go 1.23+
- Docker Desktop or a compatible Docker daemon

```sh
git clone https://github.com/ByteYellow/Agent-Computer-Fleet
cd Agent-Computer-Fleet

go build ./cmd/acfctl

./acfctl init
LEASE_ID=$(./acfctl lease create --task examples/tasks/bugfix.yaml)
SESSION_ID=$(./acfctl session create --lease "$LEASE_ID")

./acfctl exec "$SESSION_ID" --stream -- sh -lc 'echo hello > hello.txt'
./acfctl snapshot create "$SESSION_ID" --type directory --path /workspace --name ready
./acfctl fork ready --count 3
RESUME_LEASE_ID=$(./acfctl lease create --task examples/tasks/bugfix.yaml)
./acfctl snapshot resume ready --lease "$RESUME_LEASE_ID"
./acfctl cost show run-demo-bugfix

./acfctl session rm "$SESSION_ID"
```

Run the full MVP walkthrough:

```sh
./scripts/demo_v1.sh
```

## What you can control

The point of the CLI surface is to make sandbox state explicit enough for
security analysis, fanout execution, and cost accounting:

| You have | You run | You inspect |
|---|---|---|
| A task YAML | `acfctl lease create --task ...` | lease status, run id, resource request |
| A sandbox session | `acfctl session create --lease ...` | container id, workspace path, runtime metadata |
| A process | `acfctl exec <session> --stream -- ...` | process id, exit code, wall time |
| A workspace state | `acfctl snapshot create ...` | manifest hash, file count, bytes, taint |
| A branch point | `acfctl fork <snapshot> --count 3` | attempt workspaces and lineage |
| A stopped state | `acfctl snapshot resume <snapshot> --lease ...` | a new running session with parent snapshot lineage |
| A network event | `acfctl egress check ...` or runtime proxy traffic | policy decisions and quarantine signals |
| A run | `acfctl cost show <run_id>` | CPU seconds, wall time, storage bytes, policy blocks |

## Demos

Focused demos are kept as shell scripts so they can double as smoke tests:

```sh
./scripts/demo_preview_url.sh
./scripts/demo_snapshot_fanout.sh
./scripts/demo_best_of_forks.sh
./scripts/demo_policy_quarantine.sh
./scripts/demo_egress_proxy.sh
./scripts/demo_cost_accounting.sh
./scripts/demo_provenance_trace.sh
```

See [docs/mvp.md](docs/mvp.md) for command-by-command walkthroughs.

## How it compares

**vs. sandbox runners.** A runner gives you a box and a way to execute inside
it, usually shell or a fixed SDK. Agent Computer Fleet adds the control-plane
objects around that box: leases, sessions, snapshots, forks, policy decisions,
forensics, and cost.

| | Simple sandbox runner | Agent Computer Fleet |
|---|---|---|
| **Execution** | Run a command in a sandbox | Lease/session/process state machine |
| **State** | Container filesystem | Workspace snapshots, fork lineage, taint |
| **Security** | Runtime defaults | Policy decisions, egress sidecar, quarantine path |
| **Cost** | Bring your own metrics | Run/session cost samples and active CPU model |
| **Extensibility** | Usually backend-specific | Runtime adapter boundary for Docker, gVisor, bubblewrap, Firecracker |

**vs. full cloud sandbox platforms.** This project is not trying to be a hosted
multi-tenant platform yet. The current goal is a local, inspectable, hackable
MVP that proves the agent-computer abstraction before adding a daemon, API
server, and real multi-node scheduler.

## Architecture

The long-term shape is six planes:

```mermaid
flowchart LR
    CLI["acfctl CLI / API client"] --> Control["Control Plane\nlease, session, admission"]
    Control <--> Economics["Economics Plane\nactive CPU, quota, warm pool"]
    Control --> State["State Plane\nsnapshot metadata, lineage, topology"]
    State --> Control
    Control --> Node["Node Plane\nruntime adapter, process manager"]
    Control -->|"snapshot topology / mount plan"| Node
    Node --> Docker["Docker sandbox\ninternal network"]
    Docker --> Egress["Egress proxy sidecar\nallowlist, deny, credential injection"]
    State -.->|"read-only snapshot store / COW base"| Node
    Docker --> Kernel["Host Kernel\neBPF / cgroup / runtime events"]
    Kernel --> Telemetry["Telemetry Plane\nprocess, file, network, resource"]
    Telemetry -->|"context lookup"| Control
    Telemetry -->|"lineage / taint lookup"| State
    Telemetry --> Security["Security Plane\npolicy, response, forensics"]
    State --> Security
    Security --> Control
```

Control owns placement and state transitions; State owns snapshot metadata and
physical topology; Node executes the mount/restore/fork plan selected by
Control. Telemetry is modeled as an independent host-kernel/runtime event path,
then correlated back to Control and State context.

| Plane | Responsibility |
|---|---|
| **Ingress** | CLI/API, lease, streaming exec, preview URL |
| **Control** | Session allocation, state machine, admission, quota |
| **Node** | Runtime adapters, process manager, node heartbeat |
| **State** | Template, workspace, snapshot, fork, lineage, taint |
| **Security** | Policy, telemetry correlation, response, forensics |
| **Economics** | Active CPU, warm pool, overcommit, cost accounting |

The current binary is `acfctl`. A daemon/API server is planned, but the CLI is
the stable first interface.

## What works now

- Docker-backed sessions can be created, executed, stopped, and removed.
- `exec --stream` records process rows and streams stdout/stderr.
- `port expose` provides a local HTTP preview proxy.
- Directory snapshots can be created and forked into independent workspaces.
- Directory snapshots can be resumed into new running Docker sessions.
- Templates can derive `template -> ready snapshot -> attempt workspace`
  lineage.
- Best-of-forks can run multiple strategies and select a winner.
- Telemetry, policy decisions, provenance trace, and forensics export have MVP
  implementations.
- Policy rules can be loaded from YAML for offline event tests.
- Docker sessions get a session-scoped internal bridge network and an egress
  proxy sidecar. Proxy-aware HTTP/HTTPS clients route through the sidecar;
  direct egress from the sandbox network is blocked.
- Credential injection is proxy-side and redacted: raw secret values are not
  written into workspace files, container environment, SQLite event payloads, or
  normal logs.
- Cost output includes run-level CPU, wall time, snapshot bytes, policy block
  count, quarantine count, session-level cost, node-level cost, and a simple
  cost estimate.
- Session creation goes through a single-node scheduler/admission path that
  reads node capacity, active sessions, memory pressure, warm pool signals, and
  snapshot locality.

## Runtime driver capabilities

Runtime backends are capability-gated. `acfctl runtime list` and
`acfctl runtime inspect <backend>` report what each backend can actually do
instead of presenting planned adapters as usable.

| Backend | Exec | Stop | Snapshot | Fork | Resume | Memory snapshot | Status |
|---|---:|---:|---:|---:|---:|---:|---|
| Docker | yes | yes | directory | directory | directory | no | active |
| gVisor | no | no | no | no | no | no | planned stub |
| Firecracker | no | no | no | no | no | no | planned stub |
| bubblewrap | no | no | no | no | no | no | planned stub |

The Docker driver implements directory-level snapshot, fork, and resume by
copying workspace state and then creating a new running session. Memory-level
snapshot/restore is intentionally left false until a VM-capable backend exists.

## Current boundaries

- Docker is the only fully active runtime backend today.
- gVisor, Firecracker, and bubblewrap are extension targets, not complete
  adapters.
- Snapshot support is directory-level only; memory snapshot/resume is not
  implemented.
- Scheduler/admission is single-node and conservative. It is not a distributed
  placement service yet.
- Egress enforcement covers HTTP/HTTPS proxy workflows and blocks direct
  outbound traffic from the Docker sandbox bridge. It is not a general raw TCP
  policy engine yet.
- Node registry and placement signals exist, but there is no real distributed
  scheduler.
- Baseline detection is MVP-level event/cost counting, not syscall ML or eBPF
  feature modeling.

## Command surface

Core workflow:

```sh
acfctl init
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl exec <session_id> --stream -- <command...>
acfctl port expose <session_id> <port>
acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl fork ready --count 3
acfctl snapshot resume ready --lease <lease_id>
acfctl attempt best-of --snapshot ready --strategy "name::command"
acfctl cost show <run_id>
```

Security, telemetry, and provenance:

```sh
acfctl egress allow example.com
acfctl credential inject --run <run_id> --session <session_id> --name github-token --host api.github.com --value <secret>
acfctl process list --session <session_id>
acfctl process inspect <process_id>
acfctl telemetry list --run <run_id> --type network_deny --tool-call <tool_call_id>
acfctl policy test examples/events/metadata-egress.jsonl --rules examples/policies/default.yaml
acfctl policy decisions --run <run_id>
acfctl graph trace --run <run_id>
acfctl forensics export <run_id>
```

Runtime and fleet signals:

```sh
acfctl runtime list
acfctl runtime inspect docker
acfctl node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
acfctl node list
acfctl pool create --template bugfix --size 2
acfctl bench overcommit --sessions 20 --idle-ratio 0.8 --physical-cpu 8
```

## Roadmap

Near term:

- Daemon/API server behind `acfctl`
- JSON output mode for automation
- Snapshot taint propagation and memory resume capability gates
- Stronger process manager and process tree enforcement
- Raw TCP policy enforcement for non-HTTP protocols

Later:

- gVisor and bubblewrap adapters
- Firecracker disk/memory snapshot path
- Multi-node node agent and placement scheduler
- Falco/Tetragon/eBPF telemetry integration
- Rich provenance graph queries and forensics bundles

## Testing

```sh
go test ./...
```

Local runtime state lives under `.acf/` by default and is intentionally ignored.
Public docs live under [docs/](docs/); runnable examples live under
[examples/](examples/) and [scripts/](scripts/).

<div align="center">
<sub>Apache-2.0 licensed | local-first MVP | built around Go, Docker, and SQLite</sub>
</div>
