#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ACFCTL="${ACFCTL:-./acfctl}"
DATA_DIR="${DATA_DIR:-.acf-demo-cpu-weight}"

go build -o "$ACFCTL" ./cmd/acfctl
rm -rf "$DATA_DIR"

"$ACFCTL" --data-dir "$DATA_DIR" init >/dev/null
lease_id=$("$ACFCTL" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)
session_id=$("$ACFCTL" --data-dir "$DATA_DIR" session create --lease "$lease_id")
container_id=$("$ACFCTL" --data-dir "$DATA_DIR" session inspect "$session_id" | awk -F= '/^container_id=/{print $2}')

echo "session_id=$session_id"
echo "container_id=${container_id:0:12}"
docker inspect "$container_id" --format 'after_create_cpu_shares={{.HostConfig.CpuShares}}'

"$ACFCTL" --data-dir "$DATA_DIR" session cpu-profile "$session_id" --profile tool
docker inspect "$container_id" --format 'after_manual_tool_cpu_shares={{.HostConfig.CpuShares}}'

"$ACFCTL" --data-dir "$DATA_DIR" exec "$session_id" --stream -- sh -lc 'echo tool-phase; sleep 1'
docker inspect "$container_id" --format 'after_exec_cpu_shares={{.HostConfig.CpuShares}}'

"$ACFCTL" --data-dir "$DATA_DIR" telemetry list --run run-demo-bugfix --type cpu_weight_set
"$ACFCTL" --data-dir "$DATA_DIR" cost show run-demo-bugfix

"$ACFCTL" --data-dir "$DATA_DIR" session rm "$session_id" >/dev/null
