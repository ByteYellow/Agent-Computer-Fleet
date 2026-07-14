#!/bin/bash
# Full Grok codebase-exfil capture -> signed bundle.
#  axis1 kernel: record+sensor witnesses grok reading the repo (secret files).
#  axis2 endpoint: the capture+BLOCK proxy (grok is rustls) records the codebase
#    upload grok attempts and DENIES it; ingest-endpoint folds it into the graph.
#  axis3 app-context: the grok harness adapter (chat_history) shows the model
#    "declared" only text ("ok") while the CLI shipped the whole repo.
# Disclosed force: xAI's server sets trace_upload_enabled=false for this account;
# the proxy flips it (logged) to demonstrate the mechanism + the block.
set -uo pipefail
export PATH=$HOME/.local/node/bin:$HOME/.local/npm/bin:$HOME/.local/bin:$PATH
export GROK_MANAGED_BY_NPM=1
BIN=/tmp/agentprov; DATA=/tmp/grok.data; RUN=run-grok-exfil; PARENT=/sys/fs/cgroup/agentprov
SUDOPW="${AGENTPROV_SUDO_PW:?export AGENTPROV_SUDO_PW}"
WS=$HOME/grok-canary; DUMP=/tmp/proxy-dump; PORT=8088; OUT=$HOME/grok-out; rm -rf "$OUT"; mkdir -p "$OUT"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== setcap sensor + cgroup =="
echo "$SUDOPW" | sudo -S /bin/bash -c "setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_sys_resource,cap_dac_override+ep $BIN && mkdir -p $PARENT && chown -R agentprov $PARENT && echo prereq_ok" 2>&1 | grep -v '^\[sudo\]'

echo "== canary repo =="; bash "$HERE/make-canary-repo.sh" "$WS" | tail -1

echo "== start capture+BLOCK proxy (force-enable disclosed) =="
rm -rf "$DUMP"
PORT=$PORT UPSTREAM=https://cli-chat-proxy.grok.com V1_PREFIX=1 FORCE_UPLOAD=1 BLOCK_UPLOAD=1 DUMP_DIR=$DUMP CANARY_FILE=$WS/.canaries.all.txt nohup python3 "$HERE/grok-proxy.py" > /tmp/proxy.log 2>&1 &
PX=$!; sleep 1

echo "== grok under sensor + record (trivial prompt; all traffic via the proxy) =="
rm -rf "$DATA"; "$BIN" --data-dir "$DATA" init >/dev/null
cat > /tmp/grok-run.sh <<RS
#!/bin/bash
export PATH=$HOME/.local/node/bin:$HOME/.local/npm/bin:$HOME/.local/bin:$PATH
export GROK_MANAGED_BY_NPM=1
cd "$WS"
B='http://127.0.0.1:$PORT'
export XAI_API_BASE_URL=\$B GROK_XAI_API_BASE_URL=\$B GROK_CLI_CHAT_PROXY_BASE_URL=\$B GROK_MODELS_BASE_URL=\$B GROK_MODES_BASE_URL=\$B GROK_WORKSPACES_BASE_URL=\$B GROK_CONVERSATIONS_BASE_URL=\$B GROK_FEEDBACK_BASE_URL=\$B
exec "$HOME/.grok/bin/grok" -p 'Reply with the single word: ok.' --output-format json
RS
chmod +x /tmp/grok-run.sh
nohup "$BIN" --data-dir "$DATA" sensor stream > /tmp/grok-sensor.log 2>&1 &
sleep 3
AGENTPROV_CGROUP_PARENT=$PARENT timeout 150 "$BIN" --data-dir "$DATA" record --run "$RUN" --name grok-exfil --workdir "$WS" -- bash /tmp/grok-run.sh > /tmp/grok-agent.out 2>&1
echo "record rc=$?"
sleep 4  # let the on-exit codebase upload attempts flush through the proxy
pkill -INT -f "sensor stream"; kill $PX 2>/dev/null; sleep 1

echo "== SEAL: ingest endpoint (axis2) + grok app-context (axis3) + materialize =="
"$BIN" --data-dir "$DATA" graph ingest-endpoint --run "$RUN" --dump "$DUMP"
"$BIN" --data-dir "$DATA" hooks bridge --run "$RUN" --harness grok --file "$HOME/.grok/sessions" 2>&1 | tail -1
"$BIN" --data-dir "$DATA" graph materialize --run "$RUN" 2>&1 | tail -1

echo "== verify + sign + export + package =="
"$BIN" --data-dir "$DATA" graph verify --run "$RUN" 2>&1 | head -1
"$BIN" --data-dir "$DATA" forensics keygen --priv /tmp/grok.priv --pub /tmp/grok.pub >/dev/null 2>&1 && echo keypair_ok
EXP=$("$BIN" --data-dir "$DATA" forensics export "$RUN" --sign-key /tmp/grok.priv --json 2>/dev/null)
JSONP=$(echo "$EXP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('path'))")
gzip -c "$JSONP" > "$OUT/run-grok-exfil.forensics.json.gz"
cp "${JSONP%.json}.dsse.json" "$OUT/run-grok-exfil.forensics.dsse.json"
cp /tmp/grok.pub "$OUT/attestation.pub"
"$BIN" forensics verify-attestation "$OUT/run-grok-exfil.forensics.json.gz" "$OUT/run-grok-exfil.forensics.dsse.json" --pub-key "$OUT/attestation.pub"

echo "== RESULT =="
python3 - <<PY
import sqlite3, json
c=sqlite3.connect('$DATA/agentprov.db'); RUN='$RUN'; q=lambda s:c.execute(s).fetchone()[0]
print('  KERNEL axis1 — grok reads:')
print('    secret_path/file reads of canary files:', q("select count(*) from events where run_id='%s' and event_type in ('secret_path','file_open','openat') and (payload like '%%.env%%' or payload like '%%SECRET%%' or payload like '%%.claude%%')"%RUN))
print('    execve total:', q("select count(*) from events where run_id='%s' and event_type='execve'"%RUN))
print('  ENDPOINT axis2 — model turn + blocked exfil:')
print('    llm_call nodes:', q("select count(*) from graph_edges where run_id='%s' and edge_type='llm_request'"%RUN))
print('    data-egress events (blocked codebase uploads):', q("select count(*) from events where run_id='%s' and source='endpoint_capture'"%RUN))
print('    blocked/deny egress:', q("select count(*) from events where run_id='%s' and source='endpoint_capture' and payload like '%%\"blocked\": true%%'"%RUN))
print('  APP-CONTEXT axis3:')
print('    agents:', [r for r in c.execute("select id,agent_type from agents where run_id='%s'"%RUN)])
print('    tool_calls (grok declared):', q("select count(*) from tool_calls where run_id='%s'"%RUN))
PY
echo "== proxy DENY summary =="
echo "  blocked codebase egress requests: $(grep -c 'BLOCKED codebase egress' /tmp/proxy.log)"
echo "  canary-bearing uploads captured: $(grep -c 'CANARIES:' /tmp/proxy.log)"
echo "== DONE (out=$OUT) =="
