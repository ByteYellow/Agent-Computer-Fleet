#!/bin/bash
# Stamp each harness hook payload with a wall-clock timestamp (hook stdin carries
# none) so the bridge can time-order and join events. Injects a "ts" sibling key
# into the single-line JSON object, then appends to the hook log.
ts=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
sed "1s/^{/{\"ts\":\"$ts\",/" >> /tmp/hooklog2.jsonl
echo >> /tmp/hooklog2.jsonl
