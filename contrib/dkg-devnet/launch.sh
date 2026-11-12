#!/usr/bin/env bash
# Start all devnet nodes (background, nohup). Per-node adversary env is optional:
#   NODE2_ENV="DKG_CHAFF9=8" ./launch.sh     # node2 sprays chaff (needs a -tags dkgattack binary)
#   NODE1_ENV="DKG_HOLD_FILE=/tmp/hold1" ./launch.sh   # node1 withholds shares until that file exists
set -euo pipefail
source "${BASE:-$HOME/limonata-dkg-devnet}/devnet.env"
mkdir -p "$BASE/logs"
for i in $(seq 0 $((N-1))); do
  H="$BASE/node$i"
  EVAR="NODE${i}_ENV"; EX="${!EVAR:-}"
  nohup env $EX "$BIN" start --home "$H" --chain-id "$CHAIN_ID" --evm.evm-chain-id "$EVM_CHAIN_ID" \
      --minimum-gas-prices 0aLIMO --log_level info > "$BASE/logs/node$i.log" 2>&1 &
  echo $! > "$BASE/node$i.pid"
  echo "node$i up (pid $(cat "$BASE/node$i.pid"))  log: $BASE/logs/node$i.log${EX:+   env: $EX}"
done
echo "all $N nodes launched. Watch:  ./observe.sh    |    tail -f $BASE/logs/node0.log"
