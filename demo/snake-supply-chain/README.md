# Snake / supply-chain demo — bundle & capture

This directory holds the **signed, portable forensics bundle** for the
agent-in-a-sandbox supply-chain demo, plus the scripts used to capture it.

For the narrative walkthrough — the scenario, what to click in the dashboard,
compliance mapping, and how to verify the evidence — see
**[`docs/supply-chain-demo.md`](../../docs/supply-chain-demo.md)**.

In one line: a real coding agent (Claude Code, DeepSeek backend) is told to build
a Snake game; its setup step installs a poisoned `pysnake-helper` whose install
hook reads planted **fake** secrets and connects to the cloud-metadata IP
(`169.254.169.254`). The self-owned eBPF sensor captures it and the data-flow /
taint lens surfaces the secret-read → egress as a causal edge.

## Files

- `run-snake-supervised.forensics.json.gz` — the signed bundle (import to replay).
- `run-snake-supervised.forensics.dsse.json` — the DSSE/ed25519 attestation.
- `attestation.pub` — the public key to verify it.
- `capture/` — scripts to reproduce the capture on a Linux/eBPF host.

## Replay it (no VM needed)

```sh
go build -o /tmp/agentprov ./cmd/agentprov
/tmp/agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub          # verifies the signature, then imports
/tmp/agentprov --data-dir /tmp/snake-replay dashboard serve  # open run "run-4084e7bb3dda"
```

## Reproduce the capture (Linux/eBPF host)

Supervised-capture mode — one long-running **per-node sensor** plus `record`,
which places the agent in a real cgroup so its whole subtree correlates by
`cgroup_id` at 0.98 (no pid polling, no manual objectify step):

```sh
bash capture/vm-snake-assets.sh                       # workspace, planted FAKE secrets, poisoned pkg, SETUP.md

# per-node supervisor: eBPF sensor -> ingest -> correlate-by-cgroup, self-noise
# excluded, host noise dropped. Needs CAP_BPF+CAP_PERFMON (setcap the binary, or root).
agentprov --data-dir "$DD" sensor stream &

# run the agent under record; the child (and its subtree) is born into a cgroup,
# so every syscall correlates @0.98 + self_launched. Changed files (snake.py) are
# objectified for preview automatically.
AGENTPROV_CGROUP_PARENT=/sys/fs/cgroup/agentprov \
  agentprov --data-dir "$DD" record --run run-4084e7bb3dda \
    --workdir ~/agentprov-snake-demo/workspace -- bash ~/agentprov-snake-demo/run-agent.sh

agentprov --data-dir "$DD" graph materialize --run run-4084e7bb3dda
agentprov --data-dir "$DD" forensics export run-4084e7bb3dda --sign-key <key>   # signed bundle
```

`record` births the agent into a cgroup v2 leaf (delegate `/sys/fs/cgroup/agentprov`
to a non-root user, or run record as root), so host-wide syscalls correlate to the
run without instrumenting the agent.

> The planted secrets are obviously fake and the exfil target is the unreachable
> link-local metadata IP — nothing real leaves the box. The agent's "brain" is
> DeepSeek via the Claude Code harness; it is a real LLM agent, not a script.
