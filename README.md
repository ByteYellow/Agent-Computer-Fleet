<div align="center">

<h1>Agent Computer Fleet</h1>

### The runtime bridge between AI agent rollouts and sandbox infrastructure.

<p>
Fork attempts from reusable snapshots, gate synchronized tool bursts,
promote winners through a risk barrier, and preserve cost/evidence lineage.
</p>

[![Go](https://img.shields.io/badge/go-1.23+-00ADD8.svg?style=flat-square)](https://go.dev/)
[![Runtime](https://img.shields.io/badge/runtime-Docker-2496ED.svg?style=flat-square)](https://www.docker.com/)
[![SQLite](https://img.shields.io/badge/state-SQLite-003B57.svg?style=flat-square)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg?style=flat-square)](LICENSE)

**[Quickstart](#quickstart)** | **[Demos](#demos)** | **[Architecture](#architecture)** | **[Roadmap](#roadmap)**

</div>

---

Agent Computer Fleet, or ACF, is a local-first control plane for high-concurrency AI agent rollouts.

It does not try to be a generic sandbox runtime, telemetry collector, or Kubernetes/Ray replacement. Instead, it sits above runtime and telemetry substrates and owns the agent-side rollout semantics that generic infrastructure does not model:

- `run`, `rollout`, `attempt`, and `tool_call`
- snapshot lineage and fork fanout
- best-of-forks selection and winner promotion
- active CPU accounting and burst admission
- telemetry-to-agent-context correlation
- policy decisions, quarantine, taint, and response
- async evidence, provenance, and reproducible replay metadata

ACF uses Docker today and is designed to plug into Docker, OpenSandbox, Kubernetes, Ray, Firecracker, gVisor, Kata, LoongCollector, Falco, Tetragon, and other runtime or telemetry substrates through capability-gated drivers.

## Why this exists

Modern AI agent workloads are no longer just “run one command in one container.”

Evaluation, RL training, best-of-N sampling, coding-agent repair loops, and tool-using agents can create hundreds or thousands of short-lived sandbox computers. Most of those attempts spend much of their wall time waiting on model calls, package installs, tests, I/O, or external services. Meanwhile, their useful state, runtime behavior, cost, and security evidence are scattered across containers, filesystems, logs, telemetry streams, and agent traces.

ACF makes the rollout layer explicit.

It answers questions such as:

- Which `tool_call` created this process, file diff, network edge, or artifact?
- Which snapshot did this attempt fork from?
- Is this branch cheap enough to continue?
- Is this winner safe to promote?
- Did runtime telemetry arrive before promotion?
- Which snapshots or descendants are tainted?
- How much active CPU did this run actually consume?
- What evidence is needed to replay or audit this result?

## The core loop

```text
ready snapshot
  -> fork N attempts
  -> reserve burst budget before tool execution
  -> run each strategy in an isolated workspace
  -> collect cost, telemetry, artifacts, and compact evidence
  -> score attempts by result, cost, and risk
  -> wait at the promotion barrier
  -> promote the safe winner or quarantine the tainted branch
```

In CLI form:

```sh
acfctl snapshot create "$SESSION_ID" --type directory --path /workspace --name ready

acfctl rollout start \
  --task examples/tasks/bugfix.yaml \
  --snapshot ready \
  --fanout 3 \
  --strategy 'probe::test -f hello.txt && echo passed::score=contains:passed' \
  --strategy 'fast::printf 42::score=number' \
  --strategy 'slow::sleep 1; echo passed::score=contains:passed'

acfctl rollout winner run-demo-bugfix
acfctl cost show run-demo-bugfix
acfctl graph trace --run run-demo-bugfix
```

## What ACF owns vs. what it plugs into

| Layer | ACF owns | External substrate |
|---|---|---|
| Agent rollout | `run`, `rollout`, `attempt`, `tool_call`, best-of-forks, promotion | Agentix, trainers, evaluators, coding agents |
| State | snapshot DAG, fork lineage, taint, artifact lineage, replay metadata | Docker workspace copy today; future OverlayFS, reflink, block COW, VM snapshots |
| Economics | active CPU windows, idle discount, BurstGuard, warm reuse, cost per run/attempt/tool call | OS, cgroups, Docker stats, Kubernetes/Ray resource envelopes |
| Risk | telemetry-context correlation, policy decision, response, quarantine, forensics trigger | Falco, Tetragon, LoongCollector, eBPF, runtime events |
| Runtime | capability-gated execution intent | Docker now; future OpenSandbox, gVisor, Firecracker, Kata, Kubernetes, Ray |
| Evidence | compact events, provenance graph, async bundles, replay metadata | local SQLite/filesystem today; future external stores |

## What works now

The current repository is a local-first MVP. It currently supports:

- Docker-backed sandbox sessions
- streaming exec and process records
- local preview URL proxy
- directory snapshot, fork, and resume
- template → ready snapshot → attempt workspace lineage
- rollout fanout and best-of-forks
- BurstGuard admission before synchronized tool phases
- Docker CPU profile switching between `think` and `tool`
- active CPU / idle / wall-time cost accounting
- async evidence and cleanup pipeline
- I/O-aware snapshot planning
- MVP policy decisions, quarantine, provenance trace, and forensics export
- capability-gated runtime drivers with Docker active and gVisor/Firecracker/bubblewrap as explicit stubs

## Current boundaries

ACF is intentionally narrow at this stage:

- Docker is the only fully active runtime backend.
- Directory snapshot/fork/resume is supported; memory snapshots are not.
- Scheduler/admission is single-node and conservative, not a distributed placement service.
- eBPF/Falco/Tetragon/LoongCollector integration is planned; current telemetry is wrapper/runtime-level MVP telemetry.
- Egress policy currently covers HTTP/HTTPS proxy workflows and direct-egress blocking from the Docker sandbox bridge; it is not yet a general raw TCP policy engine.
- Baseline detection is MVP-level event and cost counting, not syscall ML or full eBPF feature modeling.

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

./acfctl rollout start --task examples/tasks/bugfix.yaml --snapshot ready --fanout 3 \
  --strategy 'probe::test -f hello.txt && echo passed::score=contains:passed' \
  --strategy 'fast::printf 42::score=number' \
  --strategy 'slow::sleep 1; echo passed::score=contains:passed'

./acfctl rollout winner run-demo-bugfix
./acfctl cost show run-demo-bugfix
./acfctl graph trace --run run-demo-bugfix

./acfctl session rm "$SESSION_ID"
```

Run the full MVP walkthrough:

```sh
./scripts/demo_v1.sh
```

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
./scripts/demo_cpu_weight_control.sh
./scripts/demo_ioaware_snapshot_planner.sh
SESSIONS=50 ./scripts/demo_v01_50_concurrency.sh
```

See [docs/mvp.md](docs/mvp.md) for command-by-command walkthroughs.

## Command surface

### Daemon mode

```sh
acfctl daemon serve --listen 127.0.0.1:8574
export ACF_DAEMON_URL=http://127.0.0.1:8574
```

Daemon sampling is bounded and windowed:

```sh
acfctl daemon serve \
  --sample-interval 5s \
  --sample-limit 64 \
  --sample-timeout 2s \
  --raw-retention 10m \
  --max-raw-samples 512
```

Raw Docker stats are treated as short-term input. Scheduler and cost views read 10s/60s resource windows instead of scanning unbounded raw samples.

### Core workflow

```sh
acfctl init
acfctl lease create --task examples/tasks/bugfix.yaml
acfctl session create --lease <lease_id>
acfctl session cpu-profile <session_id> --profile think
acfctl exec <session_id> --stream -- <command...>
acfctl port expose <session_id> <port>

acfctl snapshot create <session_id> --type directory --path /workspace --name ready
acfctl snapshot plan ready
acfctl fork ready --count 3
acfctl snapshot resume ready --lease <lease_id>

acfctl attempt best-of --snapshot ready \
  --max-fanout 2 --max-cost 1 --early-stop \
  --strategy "probe::printf 42::budget=2::score=number::artifact=probe.txt" \
  --strategy "full::pytest -q::budget=30::score=contains:passed::artifact=pytest.log"

acfctl cost show <run_id>
```

### Security, telemetry, and provenance

```sh
acfctl egress allow example.com
acfctl credential inject --run <run_id> --session <session_id> \
  --name github-token --host api.github.com --value <secret>

acfctl process list --session <session_id>
acfctl process inspect <process_id>

acfctl telemetry list --run <run_id> --type network_deny --tool-call <tool_call_id>
acfctl policy test examples/events/metadata-egress.jsonl --rules examples/policies/default.yaml
acfctl policy decisions --run <run_id>

acfctl graph trace --run <run_id>
acfctl forensics export <run_id>
```

### Runtime and fleet signals

```sh
acfctl runtime list
acfctl runtime inspect docker

acfctl node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
acfctl node list
acfctl scheduler status

acfctl pool create --template bugfix --size 2 --seed-workspace ./seed --max-size 2
acfctl pool status

acfctl cost sample <session_id>
acfctl bench overcommit --sessions 20 --idle-ratio 0.8 --bursty --physical-cpu 8
```

## Architecture

The long-term shape is an Agent Rollout Control Plane with six ACF-owned planes and pluggable substrates underneath:

```mermaid
flowchart TB
    Client["Agentix / trainer / evaluator / acfctl"] --> Ingress["Fleet Ingress Gateway"]
    Ingress --> ACF["ACF Control Plane"]

    subgraph ACF["ACF Control Plane"]
        Rollout["Rollout Plane\nrun, rollout, attempt, tool_call\nfanout, best-of, budget"]
        State["State Plane\nsnapshot DAG, resume intent\ntaint and artifact lineage"]
        Economics["Economics Plane\nactive CPU, burst admission\nwarm reuse, cost windows"]
        Risk["Risk Plane\ntelemetry-context correlation\nbaseline, decision, response"]
        Evidence["Evidence Plane\nprovenance graph, forensics\nasync GC and replay metadata"]
        Driver["Driver Plane\nruntime, orchestrator\ntelemetry, snapshot drivers"]
    end

    Rollout <--> Economics
    Rollout --> State
    State --> Rollout
    Risk --> Rollout
    Rollout --> Evidence
    Risk --> Evidence
    Driver --> Rollout
    Driver --> State
    Driver --> Risk

    Driver --> Runtime["Runtime substrate\nDocker, OpenSandbox\nFirecracker, gVisor, Kata"]
    Driver --> Orchestrator["Orchestration substrate\nKubernetes, Ray, Batch\ncloud provider"]
    Driver --> Telemetry["Telemetry substrate\nLoongCollector, Falco\nTetragon, eBPF, K8s events"]
    Runtime --> Kernel["Host kernel / cgroup / namespace boundary"]
    Kernel --> Telemetry
    Telemetry -->|"filtered high-value events"| Risk
```

ACF owns rollout semantics, not generic infrastructure. Runtime, orchestrator, snapshot, and telemetry implementations are queried through a capability matrix before execution. If a backend cannot do memory snapshot or low-latency resume, the scheduler must degrade to filesystem/directory fork instead of pretending the capability exists.

| Plane | Responsibility |
|---|---|
| Rollout | `run`, `rollout`, `attempt`, `tool_call`, fanout, best-of-forks, promotion |
| State | Template, ready snapshot, attempt workspace, snapshot DAG, taint lineage |
| Economics | Active CPU windows, burst admission, warm reuse, snapshot physical cost, budget |
| Risk | Telemetry-context correlation, policy decision, baseline feature, response |
| Evidence | Async provenance graph, forensics bundle, replay metadata, background GC |
| Driver | Capability-gated runtime, orchestrator, telemetry, and snapshot substrates |

## Runtime driver capabilities

Runtime backends are capability-gated. `acfctl runtime list` and `acfctl runtime inspect <backend>` report what each backend can actually do instead of presenting planned adapters as usable.

| Backend | Exec | Stop | Snapshot | Fork | Resume | CPU weight | Memory snapshot | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Docker | yes | yes | directory | directory | directory | yes | no | active |
| gVisor | no | no | no | no | no | no | no | planned stub |
| Firecracker | no | no | no | no | no | no | no | planned stub |
| bubblewrap | no | no | no | no | no | no | no | planned stub |

The Docker driver implements directory-level snapshot, fork, and resume by copying workspace state and then creating a new running session. Memory-level snapshot/restore is intentionally left false until a VM-capable backend exists.

## v0.1 hardening demos

```sh
./scripts/demo_cpu_weight_control.sh
SESSIONS=50 ./scripts/demo_v01_50_concurrency.sh
./scripts/demo_ioaware_snapshot_planner.sh
```

The CPU weight demo verifies the control-plane loop with Docker `CpuShares`: `think=2`, `tool=1024`, then back to `think=2` after exec. On Linux cgroup v2, Docker maps this control path to cgroup CPU weight behavior; a direct `cpu.weight` node-agent writer is a later Linux-specific optimization.

The concurrency demo sets `ACF_BURST_MAX_INFLIGHT` and proves that not every simultaneous tool call is promoted to the high-priority CPU profile.

The I/O-aware snapshot demo shows hot metadata path detection, I/O fanout rejection, and graph trace reasons for not choosing overlay.

## Roadmap

Near term:

- JSON output mode for automation
- Stronger promotion barrier: telemetry watermark, risk finalization, and taint freeze
- Snapshot taint propagation
- Stronger process manager and process tree enforcement
- Raw TCP policy enforcement for non-HTTP protocols
- Falco/Tetragon/LoongCollector JSONL telemetry receivers

Later:

- OpenSandbox runtime driver
- gVisor and bubblewrap capability adapters
- Firecracker disk/memory snapshot capability path
- Backend-aware admission and scheduling intent for Kubernetes/Ray/cloud batch
- Rich provenance graph queries and forensics bundles

## Testing

```sh
go test ./...
```

Local runtime state lives under `.acf/` by default and is intentionally ignored. Public docs live under [docs/](docs/); runnable examples live under [examples/](examples/) and [scripts/](scripts/).

<div align="center">
<sub>Apache-2.0 licensed | local-first MVP | built around Go, Docker, and SQLite</sub>
</div>