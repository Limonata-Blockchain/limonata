#!/usr/bin/env bash
# =============================================================================
# Limonata DKG devnet kit  -  setup
# =============================================================================
# Stands up an ISOLATED N-validator chain with the transparent validator DKG
# + encrypted mempool ACTIVE at genesis, mirroring the live testnet params
# (committee <=16, share budget 256 -> threshold 171, deal window 20, complaint
# window 10, EncExec on). For adversarial / upgrade testing OFF the live network.
#
# It NEVER touches ~/.limonatad or the live chain. Everything lives under $BASE.
#
# Usage:
#   BIN=/path/to/limonatad N=4 BASE=$HOME/limonata-dkg-devnet ./dkg-devnet.sh
#   ./launch.sh          # start all nodes
#   ./observe.sh         # watch the DKG finalize + committee
#   ./stop.sh            # stop all nodes
#
# Requirements: the SAME limonatad binary the live chain runs (build from tag
# limonata-v0.3.4, or use the release asset). For Byzantine share tests, build a
# second binary with `-tags dkgattack` (see README).
# =============================================================================
set -euo pipefail

N="${N:-4}"
BIN="${BIN:-$HOME/go/bin/limonatad}"
BASE="${BASE:-$HOME/limonata-dkg-devnet}"
CHAIN_ID="${CHAIN_ID:-limonata-devnet-1}"
EVM_CHAIN_ID="${EVM_CHAIN_ID:-10777}"
DENOM=aLIMO
KEYRING=test
KEYALGO=eth_secp256k1

case "$BASE" in *".limonatad"*) echo "REFUSING: BASE must not be the live home ($BASE)"; exit 1;; esac
command -v jq      >/dev/null || { echo "ERROR: need jq"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: need python3"; exit 1; }
BINPATH="$(command -v "$BIN" || true)"; [ -x "$BIN" ] || [ -n "$BINPATH" ] || { echo "ERROR: binary not found (BIN=$BIN)"; exit 1; }
e18(){ python3 -c "print(int($1)*10**18)"; }
nodeid(){ "$BIN" comet show-node-id --home "$1" 2>/dev/null || "$BIN" tendermint show-node-id --home "$1"; }

echo "==> [1/5] wipe + init $N nodes under $BASE  (chain=$CHAIN_ID, evm=$EVM_CHAIN_ID)"
rm -rf "$BASE"; mkdir -p "$BASE"
for i in $(seq 0 $((N-1))); do
  H="$BASE/node$i"
  "$BIN" init "devnet-node$i" --chain-id "$CHAIN_ID" --home "$H" >/dev/null 2>&1
  "$BIN" keys add "val$i" --keyring-backend $KEYRING --algo $KEYALGO --home "$H" >/dev/null 2>&1
done

G="$BASE/node0/config/genesis.json"; TMP="$BASE/node0/config/tmp.json"

echo "==> [2/5] base genesis: denom=$DENOM, mint OFF, free gas, fast gov, max_validators=16, VE@5"
jq --arg d "$DENOM" '
    .app_state.staking.params.bond_denom=$d
  | .app_state.staking.params.max_validators=16
  | .app_state.staking.params.unbonding_time="600s"
  | .app_state.gov.params.min_deposit[0].denom=$d
  | .app_state.gov.params.voting_period="30s"
  | (.app_state.gov.params.expedited_voting_period="15s")
  | .app_state.evm.params.evm_denom=$d
  | .app_state.mint.params.mint_denom=$d
  | .app_state.mint.params.inflation_min="0.000000000000000000"
  | .app_state.mint.params.inflation_max="0.000000000000000000"
  | .app_state.mint.minter.inflation="0.000000000000000000"
  | .app_state.mint.minter.annual_provisions="0.000000000000000000"
  | .app_state.feemarket.params.no_base_fee=false
  | .app_state.feemarket.params.base_fee="0.000000000000000001"
  | .app_state.feemarket.params.min_gas_price="0.000000000000000000"
  | .consensus.params.abci.vote_extensions_enable_height="5"
  ' "$G" >"$TMP" && mv "$TMP" "$G"

echo "==> [3/5] x/encmempool: TRANSPARENT DKG ACTIVE at genesis (live-matching params)"
jq '.app_state.encmempool = {params:{
      reveal_delay:1, max_reveal_window:100,
      enc_enabled:true, enc_exec_enabled:true, decrypt_delay:10,
      max_in_flight_enc_tx:32768, max_in_flight_per_submitter:2048, max_verify_ops_per_block:16384,
      enc_submit_bond:1000000000000000, enc_submit_bond_denom:"aLIMO", enc_submit_bond_burn_bps:100,
      dkg_enabled:true, dkg_transparent:true,
      dkg_start_height:40, dkg_deal_window:20, dkg_complaint_window:10,
      dkg_retry_backoff:5, dkg_max_attempts:8, dkg_min_rekey_gap:30,
      dkg_max_members:0, dkg_share_budget:0, dkg_max_epoch_blocks:0, dkg_rekey_on_stake_drift_bps:500
   }, commits:[], pending:[]}' "$G" >"$TMP" && mv "$TMP" "$G"

# EVM requires denom metadata for evm_denom + an erc20 representation of the native coin.
jq '.app_state.bank.denom_metadata=[{
      description:"Limonata devnet native coin.",
      denom_units:[{denom:"aLIMO",exponent:0,aliases:["attoLIMO"]},{denom:"LIMO",exponent:18,aliases:[]}],
      base:"aLIMO",display:"LIMO",name:"Limonata",symbol:"LIMO",uri:"",uri_hash:""}]
  | .app_state.erc20.native_precompiles=["0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"]
  | .app_state.erc20.token_pairs=[{contract_owner:1,erc20_address:"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",denom:"aLIMO",enabled:true}]
  ' "$G" >"$TMP" && mv "$TMP" "$G"

echo "==> [4/5] fund validators + faucet, gentx each, collect on node0"
"$BIN" keys add faucet --keyring-backend $KEYRING --algo $KEYALGO --home "$BASE/node0" >/dev/null 2>&1
FAUCET=$("$BIN" keys show faucet -a --keyring-backend $KEYRING --home "$BASE/node0")
"$BIN" genesis add-genesis-account "$FAUCET" "$(e18 100000000)$DENOM" --keyring-backend $KEYRING --home "$BASE/node0"
for i in $(seq 0 $((N-1))); do
  A=$("$BIN" keys show val$i -a --keyring-backend $KEYRING --home "$BASE/node$i")
  "$BIN" genesis add-genesis-account "$A" "$(e18 10000000)$DENOM" --keyring-backend $KEYRING --home "$BASE/node0"
done
# distribute the accounts-genesis to nodes 1..N-1 so each can gentx (node0 already has it), then collect on node0
for i in $(seq 1 $((N-1))); do cp "$G" "$BASE/node$i/config/genesis.json"; done
for i in $(seq 0 $((N-1))); do
  "$BIN" genesis gentx val$i "$(e18 1000000)$DENOM" --keyring-backend $KEYRING --chain-id "$CHAIN_ID" --home "$BASE/node$i" >/dev/null 2>&1
  cp "$BASE/node$i"/config/gentx/*.json "$BASE/node0/config/gentx/" 2>/dev/null || true
done
"$BIN" genesis collect-gentxs --home "$BASE/node0" >/dev/null 2>&1
"$BIN" genesis validate-genesis --home "$BASE/node0"
for i in $(seq 1 $((N-1))); do cp "$BASE/node0/config/genesis.json" "$BASE/node$i/config/genesis.json"; done

echo "==> [5/5] per-node config: distinct ports, full-mesh peers, fast blocks, app mempool"
declare -a NID
for i in $(seq 0 $((N-1))); do NID[$i]=$(nodeid "$BASE/node$i"); done
for i in $(seq 0 $((N-1))); do
  base=$((40000 + i*1000)); H="$BASE/node$i"; C="$H/config/config.toml"; APP="$H/config/app.toml"
  peers=""; for j in $(seq 0 $((N-1))); do [ "$j" -ne "$i" ] && peers="$peers,${NID[$j]}@127.0.0.1:$((40000 + j*1000 + 656))"; done; peers="${peers#,}"
  sed -i \
    -e "s#^laddr = \"tcp://127.0.0.1:26657\"#laddr = \"tcp://127.0.0.1:$((base+657))\"#" \
    -e "s#^laddr = \"tcp://0.0.0.0:26656\"#laddr = \"tcp://0.0.0.0:$((base+656))\"#" \
    -e "s#^persistent_peers = \"\"#persistent_peers = \"$peers\"#" \
    -e 's#^addr_book_strict = true#addr_book_strict = false#' \
    -e 's#^allow_duplicate_ip = false#allow_duplicate_ip = true#' \
    -e 's#^type = "flood"#type = "app"#' \
    -e 's#^timeout_commit = .*#timeout_commit = "1s"#' \
    "$C"
  # app.toml ports via python (multi-section toml). node0 keeps grpc/api/json-rpc on; others off.
  ONFLAG=$([ "$i" = "0" ] && echo true || echo false)
  python3 - "$APP" "$base" "$EVM_CHAIN_ID" "$ONFLAG" <<'PY'
import sys,re
app,base,evm,on = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]=="true"
t=open(app).read()
t=re.sub(r'^evm-chain-id = .*', f'evm-chain-id = {evm}', t, flags=re.M)
t=re.sub(r'^minimum-gas-prices = .*', 'minimum-gas-prices = "0aLIMO"', t, flags=re.M)
# gRPC
t=re.sub(r'(\[grpc\][^\[]*?)address = "[^"]*"', lambda m: m.group(1)+f'address = "localhost:{base+90}"', t, flags=re.S)
t=re.sub(r'(\[grpc\]\naddress[^\[]*?)enable = \w+', lambda m: m.group(0), t, flags=re.S)
# API + JSON-RPC + enables via targeted section edits
def set_enable(section, val):
    global t
    t=re.sub(r'(\['+re.escape(section)+r'\][^\[]*?)enable = \w+', lambda m: re.sub(r'enable = \w+', f'enable = {str(val).lower()}', m.group(0),count=1), t, flags=re.S)
set_enable('grpc', on); set_enable('grpc-web', False); set_enable('api', on)
t=re.sub(r'(\[api\][^\[]*?)address = "[^"]*"', lambda m: m.group(1)+f'address = "tcp://localhost:{base+317}"', t, flags=re.S)
# JSON-RPC section is [json-rpc]
def set_jsonrpc(val):
    global t
    t=re.sub(r'(\[json-rpc\][^\[]*?)enable = \w+', lambda m: re.sub(r'enable = \w+', f'enable = {str(val).lower()}', m.group(0),count=1), t, flags=re.S)
    t=re.sub(r'(\[json-rpc\][^\[]*?)address = "[^"]*"', lambda m: m.group(1)+f'address = "127.0.0.1:{base+545}"', t, flags=re.S)
    t=re.sub(r'(\[json-rpc\][^\[]*?)ws-address = "[^"]*"', lambda m: m.group(1)+f'ws-address = "127.0.0.1:{base+546}"', t, flags=re.S)
set_jsonrpc(on)
open(app,'w').write(t)
PY
done

# stamp the base dir + N into a small env file the helper scripts read
cat > "$BASE/devnet.env" <<EOF
BIN="$BIN"
BASE="$BASE"
N=$N
CHAIN_ID="$CHAIN_ID"
EVM_CHAIN_ID=$EVM_CHAIN_ID
NODE0_RPC=127.0.0.1:40657
EOF

echo
echo "DKG DEVNET READY  ($N validators, chain=$CHAIN_ID)"
echo "  node0 RPC:      127.0.0.1:40657   (block_search / block_results here)"
echo "  node0 EVM RPC:  127.0.0.1:40545"
echo "  homes:          $BASE/node0 .. node$((N-1))"
echo "  faucet key:     'faucet' in node0 keyring (test backend)"
echo
echo "Next:  ./launch.sh   then   ./observe.sh   (DKG finalizes ~height 70)"
