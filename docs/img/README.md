# Dashboard / demo screenshots

Screenshots and short replay media referenced from the top-level `README.md`.
They are generated from the portable `demo/snake-supply-chain` forensics bundle.

| File | What to capture |
|------|-----------------|
| `dashboard-graph-explorer-taint.png` | Graph Explorer with the **Data-flow · taint** lens selected on `run-snake-supervised`; the red dashed `possible_sensitive_data_flow` edges visible. |
| `dashboard-side-panel-preview.png` | A node selected so the **Side Panel** shows Evidence + the artifact Preview (e.g. `workspace_file/snake.py`). |
| `demo-snake-taint-replay.png` | The taint lens mid **time-scrub** (▶): secret-read nodes shown, the metadata-IP egress about to appear. |
| `demo-snake-taint-replay.gif` | Short animated replay of the taint lens / time scrubber for README embedding. |
| `demo-multiagent-overview.png` | Dashboard overview for `run-double-attempt`: signed graph status, run overview, risk groups, and first timeline page. |
| `demo-multiagent-orchestration.png` | Multi-agent orchestration lens: lead agent, sub-agents, peer message, tool calls, and syscall attribution. |
| `demo-multiagent-agent-network.gif` | README animation captured from the dashboard's native play button in the orchestration lens. |
| `demo-multiagent-agent-network-01-start.png` | Source frame before native playback starts. |
| `demo-multiagent-agent-network-02-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-03-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-04-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-05-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-06-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-07-play.png` | Native playback source frame. |
| `demo-multiagent-risk-path.png` | Focused risk selection: metadata-IP risk plus focused evidence table. |
| `demo-multiagent-network-egress.png` | Network / egress lens for the multi-agent run, focused on outbound evidence. |

To regenerate them: replay the captured run and open the dashboard —

```sh
./agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub
./agentprov --data-dir /tmp/snake-replay dashboard serve   # http://127.0.0.1:7396
```
