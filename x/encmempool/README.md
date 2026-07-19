# x/encmempool - threshold-encrypted mempool (transparent validator DKG, LIVE on testnet)

> **THIS IS A LIVE, TESTED ENCRYPTED MEMPOOL. THE VALIDATOR SET GENERATES AND HOLDS THE THRESHOLD ENCRYPTION KEY TOGETHER, ON-CHAIN, INSIDE CONSENSUS - NO TRUSTED DEALER, NO KEYPER COMMITTEE, NO COORDINATOR.**

This module implements a **live threshold-encrypted mempool driven by a transparent,
stake-weighted validator DKG**. Users encrypt transactions to the committee's threshold
key; the validator set builds and holds that key together, on-chain, inside consensus
(via CometBFT vote extensions), so the master secret never exists in one place. When a
ciphertext matures, consensus reconstructs the per-epoch decryption key, decrypts it,
and executes the plaintext on-chain in deterministic order. It grew out of - and still
retains - the `commit -> reveal -> execute` state machine described below.

## What it does

1. **Commit** (`MsgCommitTx`): a user records `commit_hash = sha256(reveal_tx || salt)`
   at the current block height H. Only the commitment hash is stored on chain; the
   transaction body is not revealed. The module returns `(commit_height=H, seq)`.
2. **Reveal** (`MsgRevealTx`): at height >= H + `reveal_delay`, the committer submits
   the preimage `(reveal_tx, salt)`. The message server validates the delay and that
   `sha256(reveal_tx || salt)` matches the commitment, then **queues** the reveal. It
   does **not** execute it or emit its contents.
3. **Execute** (`BeginBlock`): the keeper iterates queued reveals in deterministic
   store-key order (big-endian `commit_height -> sender -> seq`) and emits
   `encmempool_reveal_executed{commit_height, sender, seq, execution_order}`, then
   deletes the commit and the pending entry. Unrevealed commits are garbage-collected
   after `max_reveal_window` blocks.

Decryption and execution run identically on every node inside `FinalizeBlock`, so the
module is consensus-deterministic by construction. The transparent DKG rides **ABCI++
vote extensions**: every validator contributes DLEQ-proved decryption shares as part of
consensus, and the per-epoch key is reconstructed deterministically from shares
representing more than 2/3 of committee stake.

## Security properties

- It **is** encryption. A submitted transaction is encrypted to the committee's
  threshold key and its plaintext body is unavailable to anyone - proposer included -
  until consensus reconstructs the per-epoch decryption key. The master secret is never
  assembled in one place.
- Decryption power is **stake-weighted**: shares are apportioned by bonded stake over a
  fixed budget, and reconstruction requires shares representing **more than 2/3 of
  committee stake**. The scheme **fails closed** - if stake concentration would let one
  operator (or any sub-2/3-stake coalition) decrypt alone, it will not decrypt. The key
  **auto-rekeys** on committee membership changes and on stake drift greater than 5%.
- Validators take part simply by running the node binary - no separate daemon, no
  account, no fees, no key-setup ceremony.
- "Execute" re-injects the decrypted payload into the EVM/tx pipeline at reveal
  (`EncExec`): matured ciphertexts are decrypted and executed on-chain in deterministic
  order.

## How the transparent DKG resists MEV

MEV resistance comes from **threshold encryption run by the validator set itself** -
not by a separate keyper committee, trusted dealer, or coordinator. The per-epoch
decryption key is reconstructed only after the block carrying a ciphertext commits, so
no one - proposers included - can front-run or censor on plaintext they cannot see. The
transparent DKG occupies the exact slot the commit/reveal/execute state machine was
built around: "the user reveals the preimage" is now "the validator committee
reconstructs the epoch decryption key inside consensus, and `FinalizeBlock` decrypts and
orders the matured ciphertexts." The deterministic ordering and bounded-state GC carry
over unchanged.

## Params

| param | default | meaning |
|---|---|---|
| `reveal_delay` | 1 | minimum blocks between commit and a valid reveal |
| `max_reveal_window` | 100 | blocks after which an unrevealed commit is GC'd |

## Status

**Live and tested on testnet `limonata_10777-1`.** The transparent validator DKG shipped
in the `encmempool-transparent-dkg-v1` upgrade at block 998,735 (source tags
`limonata-v0.3.2` / `limonata-v0.3.3`) and finalized its first epoch at block 998,805.
It has been exercised end-to-end. This is a testnet deployment; the module's internal
audit trail and review cycles live alongside this file in the repo.
