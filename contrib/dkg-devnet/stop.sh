#!/usr/bin/env bash
# Stop all devnet nodes.
set -uo pipefail
source "${BASE:-$HOME/limonata-dkg-devnet}/devnet.env"
for i in $(seq 0 $((N-1))); do
  if [ -f "$BASE/node$i.pid" ]; then
    kill "$(cat "$BASE/node$i.pid")" 2>/dev/null && echo "stopped node$i" || echo "node$i not running"
    rm -f "$BASE/node$i.pid"
  fi
done
