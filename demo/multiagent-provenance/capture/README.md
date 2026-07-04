# Multi-agent provenance demo — capture assets

Durable copies of the VM capture harness (saved here because the VM's `/tmp/*`
clears on reboot). The demo narrative + how to view the signed bundle is in the
parent `../README.md`; full design + resume plan is in the memory doc
`agentprov-multiagent-demo-todo.md`.

## What the capture proves

A poisoned agent team runs an attacker's arc in ONE signed causal graph:
**Attempt A** — a `recon` teammate is asked to read the cloud credentials and POST
them to the metadata IP; the model refuses at the intent layer (→ a refused node,
no egress). **Attempt B** — the *same* exfil is buried in `setup.py install` and
relayed alice→bob; bob runs it unknowingly, and only the kernel sensor catches the
secret read + metadata egress, attributed back to bob by command-match.

The two attempts are captured as **separate** claude invocations (for reliability
— a single two-phase prompt starved bob) whose hooks both append to one
`/tmp/hooklog2.jsonl`, then bridged into one run. Only B runs under the sensor; A
is hook-only, so it contributes the intent-layer refusal without a kernel egress.

## Double-attempt capture (current)

- `double-attempt-capture.sh` — the orchestrator: build + setcap + delegate cgroup,
  plant the fake secrets + poisoned helper, run Attempt A (recon, hook-only) then
  Attempt B (alice/bob under sensor + record), then `hooks bridge` folds BOTH into
  one run and attributes the syscalls, exports a signed bundle. Run ON the VM;
  needs `AGENTPROV_SUDO_PW=<vm sudo password>` in the environment.
- `recon-run.sh` — Attempt A: the `recon` teammate asked to exfil the credentials.
- `team-run.sh` — Attempt B: the alice/bob team; alice relays the poisoned
  `setup.py install` to bob, who runs it unknowingly.
- `hookstamp.sh` — the hook logger; stamps each payload with a wall-clock `ts`
  (hook stdin carries none) so the bridge can time-order events.
- `hooks-settings.json` — reference `~/.claude/settings.json` hook config (the
  live capture writes a stamped variant that points the hooks at `hookstamp.sh`).
- `SETUP.md` — the injected instruction alice reads and relays (the benign-looking
  "install the helper" whose helper is poisoned).
- `double-attempt-hooklog.jsonl` — the REAL combined hook payloads from the proven
  run; build/verify the bridge against these exact shapes.

## Single-attempt origin (B only — kept for reference)

The buried-supply-chain half was proven first as a single run. `bestfx-capture.sh`
+ `hooklog-sample.jsonl` are that earlier B-only capture, kept as a minimal
reference (no Attempt A, no timestamp stamping).

## Key facts baked in

- The malicious action is **buried** in code the sub-agent runs unknowingly (the
  poisoned `setup.py install`), so the model executes it without recognizing the
  exfil — that is Attempt B. Attempt A is the *contrast*: the same theft proposed
  openly is refused at the intent layer. Both belong in the graph.
- The poisoned `pysnake-helper` is reused from `demo/snake-supply-chain/`; its
  install hook reads the fake secrets (`~/.aws/credentials`,
  `~/.config/agentprov-demo-secrets/api_token`) and connects the metadata IP —
  all in-process, so the syscalls share the `python3 setup.py` pid.
- Attribution is by **command-match** (agent tool_call command == sensor execve
  command), because the in-process sub-agents share one cgroup; time-window is
  secondary.
- The sensor also sees the agent's OWN credential reads (`.claude/.credentials.json`
  etc.); the default policy's `self_credential_access` rule keeps them as events
  but not alerts, so only the two planted targets raise risks.

## Reproduce

On the lab VM (`ssh agentprov@<lab-vm>`): sync the repo, then

```sh
AGENTPROV_SUDO_PW=<vm sudo password> \
  bash demo/multiagent-provenance/capture/double-attempt-capture.sh
```

Prereqs (setcap, delegated cgroup, planted secrets, poisoned helper) are handled by
the script. Because the agent is non-deterministic, re-run if a take is messy
(recon must refuse; bob must actually run the install).
