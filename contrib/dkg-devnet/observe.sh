#!/usr/bin/env bash
# Show devnet height + the current DKG epoch / committee / threshold key.
set -uo pipefail
source "${BASE:-$HOME/limonata-dkg-devnet}/devnet.env"
RPC="http://$NODE0_RPC"
H=$(curl -s --max-time 4 "$RPC/status" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['sync_info']['latest_block_height'])" 2>/dev/null || echo "?")
echo "chain=$CHAIN_ID  node0=$RPC  height=$H"
FH=$(curl -s --max-time 5 "$RPC/block_search?query=%22encmempool_dkg_finalized.epoch%20EXISTS%22&per_page=1&order_by=%22desc%22" 2>/dev/null | python3 -c "import sys,json;b=json.load(sys.stdin)['result']['blocks'];print(b[0]['block']['header']['height'] if b else '')" 2>/dev/null)
if [ -n "${FH:-}" ]; then
  echo "last DKG finalization @ height $FH:"
  curl -s --max-time 6 "$RPC/block_results?height=$FH" | python3 -c "
import sys,json
for e in (json.load(sys.stdin)['result'].get('finalize_block_events') or []):
    if e['type']=='encmempool_dkg_finalized':
        print('   '+'  '.join(f\"{a['key']}={a['value'][:64]}\" for a in e['attributes']))
"
else
  echo "no DKG finalization yet - it opens ~height 40 and finalizes ~70. Re-run shortly."
fi
