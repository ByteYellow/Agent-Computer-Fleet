#!/usr/bin/env bash
# Emit one real model/tool-intent request through curl/OpenSSL so the native
# sensor can capture it as tls_write evidence. Secrets stay in headers and are
# never written to this file or the request body.
set -euo pipefail

SCENARIO="${1:-agentprov-demo}"
COMMAND="${2:-python3 ../pysnake-helper/setup.py install --user}"
ENV_FILE="${AGENTPROV_DEMO_ENV_FILE:-$HOME/.agentprov-demo/deepseek-claude.env}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_FILE"
fi

BASE_URL="${ANTHROPIC_BASE_URL:-}"
TOKEN="${ANTHROPIC_AUTH_TOKEN:-${ANTHROPIC_API_KEY:-}}"
MODEL="${AGENTPROV_DEMO_MODEL:-deepseek-chat}"

if [[ -z "$BASE_URL" || -z "$TOKEN" ]]; then
  echo "agentprov llm intent probe skipped: ANTHROPIC_BASE_URL or token is missing" >&2
  exit 0
fi

BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT
python3 - "$BODY" "$MODEL" "$COMMAND" "$SCENARIO" <<'PY'
import json
import sys

path, model, command, scenario = sys.argv[1:5]
body = {
    "model": model,
    "max_tokens": 128,
    "messages": [
        {
            "role": "user",
            "content": (
                "Use the run_shell tool for this sandboxed agent task. "
                "Return the tool call only."
            ),
        }
    ],
    "tools": [
        {
            "name": "run_shell",
            "description": "Run a shell command inside the sandbox.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "scenario": {"type": "string"},
                },
                "required": ["command"],
            },
        }
    ],
    "metadata": {"user_id": "agentprov-demo-" + scenario},
}
body["messages"][0]["content"] += " Command: " + command
with open(path, "w", encoding="utf-8") as f:
    json.dump(body, f, separators=(",", ":"))
PY

curl --http1.1 -sS -X POST "${BASE_URL%/}/v1/messages" \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "x-api-key: $TOKEN" \
  --data-binary "@$BODY" | head -c "${AGENTPROV_LLM_INTENT_PREVIEW_BYTES:-500}"
echo
