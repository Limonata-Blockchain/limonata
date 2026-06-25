# x/encmempool — commit-reveal mempool (EXPERIMENTAL PROOF-OF-CONCEPT)

> **THIS IS NOT AN ENCRYPTED MEMPOOL YET, AND IT PROVIDES NO MEV RESISTANCE.**

This module implements a **hash-commitment with an enforced on-chain reveal delay
and deterministic reveal ordering**. It is **not encryption**. It exists to build and
test the on-chain `commit -> delayed-reveal -> execute` state machine that a real
threshold-encryption scheme (Shutter / Ferveo) plugs into later.

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

All decision logic lives in `BeginBlock`, which runs identically on every node inside
`FinalizeBlock`. There is **no proposer-only logic and no ABCI++ vote extension**, so
the prototype is consensus-deterministic by construction.

## What it does NOT do (be honest)

- It is **not encryption**. The body is hidden from third-party observers only between
  commit and reveal, and only because the user withholds the preimage. There is no
  threshold key and nothing is decrypted by consensus.
- On the current **single-validator** testnet, the sole proposer sees every
  transaction in its own mempool at commit time and at reveal time, and can reorder or
  censor reveals. A censored reveal is simply never executed (availability loss; the
  on-chain commit is the only evidence).
- "Execute" here means the module records the deterministic execution **order** and
  emits an event. It does **not** re-inject the payload into the EVM/tx pipeline; the
  reveal a user submits is itself an ordinary transaction.

## The upgrade path to real MEV resistance

Real anti-MEV requires **threshold encryption with >= 2 independent keypers** (a
Shutter/Ferveo-style DKG), where the per-block decryption key is released only after
the block carrying the ciphertext commits. That scheme plugs into the exact slot built
here: replace "the user reveals the preimage" with "the keypers release the epoch
decryption key, and BeginBlock decrypts and orders the matured ciphertexts." The
commit/reveal/execute state machine, the deterministic ordering, and the bounded-state
GC all carry over unchanged.

## Params

| param | default | meaning |
|---|---|---|
| `reveal_delay` | 1 | minimum blocks between commit and a valid reveal |
| `max_reveal_window` | 100 | blocks after which an unrevealed commit is GC'd |

## Status

Built and tested on a single-validator throwaway testnet. **Not** deployed to the live
chain (adding the module store to a running chain requires a coordinated store-upgrade,
which is a separate, gated step).
