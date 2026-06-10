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
- Templates can derive `template -> ready snapshot -> attempt workspace`
  lineage.
- Best-of-forks can run multiple strategies and select a winner.
- Telemetry, policy decisions, provenance trace, and forensics export have MVP
  implementations.
- Docker sessions get a session-scoped internal bridge network and an egress
  proxy sidecar. Proxy-aware HTTP/HTTPS clients route through the sidecar;
  direct egress from the sandbox network is blocked.
- Credential injection is proxy-side and redacted: raw secret values are not
  written into workspace files, container environment, SQLite event payloads, or
  normal logs.
- Cost output includes run-level CPU, wall time, snapshot bytes, policy block
  count, quarantine count, and a simple cost estimate.

## Current boundaries

- Docker is the only fully active runtime backend today.
- gVisor, Firecracker, and bubblewrap are extension targets, not complete
  adapters.
- Snapshot support is directory-level only; memory snapshot/resume is not
  implemented.
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
acfctl attempt best-of --snapshot ready --strategy "name::command"
acfctl cost show <run_id>
```

Security, telemetry, and provenance:

```sh
acfctl egress allow example.com
acfctl credential inject --run <run_id> --session <session_id> --name github-token --host api.github.com --value <secret>
acfctl telemetry list --run <run_id>
acfctl policy test examples/events/metadata-egress.jsonl
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
acfctl bench overcommit --sessions 20 --idle-ratio 0.8
```

## Roadmap

Near term:

- Daemon/API server behind `acfctl`
- JSON output mode for automation
- YAML policy rule engine
- Snapshot resume and taint propagation
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
