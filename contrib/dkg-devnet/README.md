# Limonata DKG devnet kit

An isolated, throwaway N-validator chain with the **transparent validator DKG +
encrypted mempool ACTIVE at genesis**, mirroring the live testnet params
(committee ≤16, share budget 256 → threshold 171, deal window 20, complaint
window 10, EncExec on). Use it for **adversarial / Byzantine / upgrade testing
off the live network**. It never touches `~/.limonatad` or the live chain.

## Requirements
- The same `limonatad` binary the live chain runs. Build from the tag:
  `git fetch --tags && git checkout limonata-v0.3.4 && make install`
  (or use the release asset). Verify: `limonatad version --long` → `commit: 77fc357f`.
- `jq` and `python3`.

## Quick start
```bash
BIN=$HOME/go/bin/limonatad N=4 BASE=$HOME/limonata-dkg-devnet ./dkg-devnet.sh
./launch.sh            # start all nodes (background)
./observe.sh           # DKG epoch / committee / threshold key (finalizes ~height 70)
./stop.sh              # stop all nodes
```
`N` = number of validators (default 4). Re-running `dkg-devnet.sh` wipes and rebuilds `BASE`.

## Ports (node i, 0-indexed)
base = `40000 + i*1000`
| service | port |
|---|---|
| CometBFT P2P | base+656 |
| CometBFT RPC | base+657 |
| EVM JSON-RPC (node0 only) | base+545 |
| gRPC / API (node0 only) | base+90 / base+317 |

node0 RPC = `127.0.0.1:40657` (run `block_search` / `block_results` here).

## Observe the DKG
```bash
# latest finalization (epoch, threshold pubkey, qual, threshold):
curl -s 'localhost:40657/block_search?query="encmempool_dkg_finalized.epoch EXISTS"&per_page=1&order_by="desc"'
curl -s 'localhost:40657/block_results?height=<H>'
# round lifecycle (committee, reason, retries, deal/complaint deadlines):
#   query "encmempool_dkg_round_opened.epoch EXISTS"
```

## Byzantine testing (share withholding / chaff)
The share-level adversary is **compiled out of the default binary**. Build a second
binary with the adversary tag and point one node at it:
```bash
# build the adversary binary:
git checkout limonata-v0.3.4 && go build -tags dkgattack -o /tmp/limonatad-atk ./evmd/cmd/evmd/
# run node2 as the adversary (edit launch.sh to use BIN=/tmp/limonatad-atk for that node,
# or run it by hand) with an env knob:
NODE2_ENV="DKG_CHAFF9=8" ./launch.sh          # node2 appends up to 8 garbage decrypt shares
NODE1_ENV="DKG_HOLD_FILE=/tmp/hold1" ./launch.sh   # node1 withholds shares until /tmp/hold1 exists
```
Expected: the module is fail-closed — honest nodes reject/ignore the chaff
(`encmempool_dkg_ve_share_rejected`, `_ve_shares_clamped`) and the chain keeps
finalizing. This is why it must NOT be run on the live testnet.

For dealer-level Byzantine cases (bad dealings / poison), tamper at the source and
rebuild; watch for `encmempool_dkg_complaint`, `_dkg_poison_detected`, `_dkg_ve_deal_rejected`.

## Restart testing
Stop/start a single node and confirm it rejoins + resumes:
```bash
kill $(cat $BASE/node2.pid)                    # drop node2
# ... wait / observe ...
NODE2_ENV="" nohup $BIN start --home $BASE/node2 ... &   # bring it back
```
`$BASE/node2/dkg_enc_key.json` must persist across the restart (it's the node's DKG key).

## Upgrade testing
Submit a gov proposal on the devnet (voting period is 30s here), or test a rolling
binary swap (stop node → replace `$BIN` → start). Fast blocks (1s) + short gov make
the loop quick.

## Notes
- Chain-id `limonata-devnet-1` (distinct from live `limonata_10777-1`), evm-chain-id 10777.
- Faucet key `faucet` (test keyring, node0) holds 100M LIMO for funding test accounts.
- DKG opens its first round ~height 40 and finalizes ~height 70.
