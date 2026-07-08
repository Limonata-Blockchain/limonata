# Design note: EVM re-injection for the encrypted mempool

Status: DESIGN (not built). Author track: Limonata DKG / encrypted-mempool.
Closes external-review finding #1 (round #7): "encrypted txs are decrypted, emitted publicly,
then deleted, but never executed."

---

## 1. The problem

Today `decryptMatured` (x/encmempool/keeper/abci.go:358-369) decrypts a matured ciphertext,
**emits the plaintext as a public event** (`plaintext_hex`), deletes the EncTx, and stops. It never
executes the transaction. The code documents this as an intentional prototype seam
(abci.go:157-166: "PROTOTYPE ... rather than re-injecting it into the EVM pipeline ... a large,
halt-risk pipeline change").

Consequence: **the feature provides zero anti-MEV today.** The plaintext is published without being
executed, so a searcher reads the event and front-runs by submitting the raw tx themselves. The
user's transaction never runs.

## 2. Goal, and the anti-MEV model

Replace "decrypt -> emit plaintext -> delete" with "decrypt -> **execute atomically in this block, in
committed order, with NO public plaintext reveal** -> delete". The transaction's *effects* (receipt,
logs, state) become public through normal execution, which is correct: by the execution block the
transaction's position is already fixed, so no one can front-run it.

Why BeginBlock ordering is sound: Cosmos runs `BeginBlock -> DeliverTx(all txs) -> EndBlock`. Decrypted
txs execute in BeginBlock, i.e. **before** the proposer's normal txs (which run in DeliverTx). The
maturity gate publishes shares at `decrypt_height` and stores them in `PreBlock` of `decrypt_height+1`;
the tx executes in `BeginBlock` of that same block. So even a proposer who has just learned the content
(from the shares consumed in this block's PreBlock) cannot insert a front-running normal tx: the
decrypted tx has already executed by the time DeliverTx runs. Ordering among decrypted txs is the
existing deterministic `(decrypt_height, seq)` sequence.

### What this closes and does NOT close
- CLOSES finding #1: no public plaintext, and the tx actually executes at a front-run-proof position.
- Does NOT close finding #2 (whale): a validator that owns >= t eval points still computes `x*A` locally
  the moment it sees `A` (even in the mempool), so it learns the content early regardless of execution.
  That is topology/stake (see the fail-closed VP-cap discussion), orthogonal to this build.

## 3. `ApplyTransaction` is only HALF of DeliverTx — the critical gaps

`(*evmkeeper.Keeper).ApplyTransaction(ctx, *ethtypes.Transaction)` (x/vm/keeper/state_transition.go:211)
is the right single call: it recovers the sender itself with the correct EIP-155 chain-id signer
(`MakeSigner(GetEthChainConfig(), height, time)`), runs in its own cache context, and surfaces a revert
gracefully (`res.VmError`, not a Go error). A bad signature / wrong chain-id returns an error, not a
panic.

But the normal EVM flow runs the EVM ante (ante/evm/mono_decorator.go) BEFORE execution, and
re-injection from BeginBlock bypasses ALL of it. Two bypasses are load-bearing and MUST be replicated,
or the chain breaks:

1. **Fees are never deducted, but leftover gas IS refunded.** `ApplyTransaction` calls `RefundGas`
   (gas.go:44), which sends `leftoverGas * gasPrice` FROM the fee-collector module account TO the sender.
   With virtual fee collection on (app.go:598) this does not error - it **silently net-credits the sender
   and drains the fee collector on every re-injected tx.** We MUST call
   `DeductTxCostsFromUserBalance` (x/vm/keeper/fees.go:63) + set the sponsored flag BEFORE
   `ApplyTransaction`, so the sender pays the up-front fee and the refund nets to `gasUsed * gasPrice`.

2. **Nonce is not incremented for CALL txs.** `ApplyMessageWithConfig` bumps the nonce only in the
   contract-creation branch (state_transition.go:492-499); a plain CALL never touches it - the normal
   bump comes from the ante's `IncrementNonce`. Without a manual increment, **the same decrypted tx can
   be replayed.** We MUST check `tx.Nonce() == account.Sequence` up front and increment after
   (mirror ante/evm 09_increment_sequence.go).

Other ante checks to replicate (all cheap, all fail-closed -> skip the tx, never halt):
`gasFeeCap >= baseFee` and sender-balance-covers-cost (07_can_transfer.go / 06_account_verification.go);
sender is an EOA; intrinsic-gas floor (ApplyMessageWithConfig re-checks this, so it is covered);
per-tx gas limit vs a cumulative block-gas ceiling (see §5).

## 4. The re-injection pipeline (per decrypted tx, in `order`)

At the plug point (abci.go:358, `plaintext` available), replace the plaintext event with:

```
1. tx := new(ethtypes.Transaction)
   if tx.UnmarshalBinary(plaintext) != nil            -> INVALID: consume + deterministic event, skip
2. childCtx, writeChild := ctx.CacheContext()          // per-tx isolation on top of the block cache ctx
   install a per-tx gas meter (infinite-with-limit = tx.Gas()), like CheckBlockGasLimit
3. mini-ante on childCtx (all fail-closed -> skip, no write):
     - recover sender via MakeSigner(chainCfg, height, time); bad sig/chain-id -> skip
     - require tx.Nonce() == acct.Sequence(sender)      -> else skip (stale/replayed)
     - require gasFeeCap >= baseFee, balance >= gasLimit*gasPrice + value -> else skip
     - DeductTxCostsFromUserBalance(sender, fee) + SetTxSponsored(false)
4. resp, err := EVMKeeper.ApplyTransaction(childCtx, tx)
     - err != nil (state-transition failure) -> skip (do NOT writeChild)
     - resp.Failed() (revert) -> this is a SUCCESSFUL inclusion of a reverting tx: keep it
5. IncrementNonce(sender)                               // mirror the ante
6. accumulate resp.GasUsed into blockDecryptGasUsed;
   if blockDecryptGasUsed > ceiling -> stop the batch this block (defer the rest, next block)
7. writeChild()                                         // commit this tx's state
   emit encmempool_tx_executed{seq, sender, tx_hash, gas_used, reverted} -- NO plaintext
8. releaseEncTx(e)                                      // consume the ciphertext regardless of outcome
```

Everything runs inside the existing per-ciphertext `recover()` (abci.go:318) and the BeginBlock-level
branched cache + recover (abci.go:39-52), so a panic is contained into a deterministic rollback + event.

## 5. Gas metering and a block ceiling

`ApplyTransaction` replaces `ctx.GasMeter()` (gas.go:82), so each tx must run on a fresh per-tx metered
child context (never the raw BeginBlock ctx, or one tx's meter reset corrupts the block meter). There is
NO automatic block-gas debit across the decrypted batch, and `maxDecryptAttemptsPerBlock = 2048`
(abci.go:178) full EVM executions with no cumulative ceiling is a per-block DoS. Enforce a cumulative
`blockDecryptGasUsed <= encryptedBlockGasBudget` (a governance param, a fraction of
`antetypes.BlockGasLimit(ctx)`); when exceeded, stop and let the rest drain next block (the existing
grace/deferral machinery already tolerates this).

## 6. Determinism and halt/fork safety (the real risk)

The ciphertext body is permissionlessly submitted, so `plaintext` is fully attacker-controlled. The EVM
state transition itself IS deterministic (consensus already depends on it in DeliverTx), so the danger
is NOT the EVM math - it is:

- **Context-setup divergence:** BeginBlock lacks the DeliverTx per-tx setup (gas meter, header hash).
  Mitigation: set up the child context to match DeliverTx faithfully; require encmempool's BeginBlock to
  run AFTER feemarket + evm BeginBlockers (base fee + `SetHeaderHash` set) - check/adjust
  `SetOrderBeginBlockers` (app.go:780-790).
- **Non-deterministic panic in a precompile/opcode path** (map order, wall-clock, host behavior) would
  FORK (some nodes commit, some roll back), which is worse than a halt. Mitigation options, in order of
  safety:
  - v1 DECISION (recommended): **disallow precompile calls in re-injected txs** (reject a tx whose `To`
    is a registered precompile, or that would call one) - restrict v1 to pure EOA->EOA / EOA->contract
    value+calldata execution. Precompiles (staking/gov/distribution/IBC/bank/erc20, app.go:581-594) call
    other keepers and are the most likely source of context-sensitive behavior outside a normal tx.
  - Later: audit each precompile for non-determinism when invoked from BeginBlock, then lift the
    restriction.
- **Per-tx recover must be deterministic:** the contained-panic path already emits a deterministic event
  and rolls back; every node must hit the identical panic on identical committed state (true for a
  deterministic EVM). The v1 precompile restriction keeps this property easy to guarantee.

## 7. Wiring

encmempool `Keeper` is a value type holding only `storeService` + `stakingKeeper` (keeper.go:20). Add a
narrow `EVMKeeper` interface in `x/encmempool/types` (matching the `StakingKeeper` pattern) exposing
`ApplyTransaction`, the fee-deduction, nonce, and account/base-fee reads it needs - x/encmempool depends
on x/vm/keeper one-way (no cycle; x/vm does not import encmempool). Thread `app.EVMKeeper`
(`*evmkeeper.Keeper`, built app.go:568) into `encmempoolkeeper.NewKeeper` (app.go:675, runs after the
EVM keeper is constructed). Nil EVMKeeper => execution disabled (keeps the dormant/default build inert).

## 8. Failure semantics (all graceful, all deterministic)

| Case | Outcome |
|---|---|
| plaintext is not a valid RLP tx | consume ciphertext, emit `encmempool_tx_invalid`, no execution |
| bad signature / wrong chain-id | consume, `encmempool_tx_invalid`, no execution |
| nonce != account sequence (stale/replay) | consume, `encmempool_tx_stale`, no execution |
| fee-cap < base fee / insufficient balance | consume, `encmempool_tx_unpayable`, no execution |
| EVM revert (`resp.Failed()`) | INCLUDED (nonce bumped, fee charged) - a normal reverting tx |
| state-transition error (`err != nil`) | consume, `encmempool_tx_failed`, roll back child, no state |
| block gas ceiling reached | defer remaining matured txs to next block (existing grace path) |
| panic (contained) | rollback child, `encmempool_decrypt_failed`, consume |

A ciphertext is ALWAYS consumed (releaseEncTx) once processed - it had its committed slot. A user whose
tx is stale/unpayable by execution time loses it (a UX consequence of the delay + base-fee movement;
document it, and advise clients to set a generous fee cap and a fresh nonce).

## 9. Removing the plaintext leak

`plaintext_hex` (abci.go:366) is DELETED. No build flag keeps it - a debug reveal is the exact leak
finding #1 names. The public output is the execution receipt/logs only.

## 10. Rollout

- New governance param `EncExecEnabled` (default FALSE). While false, keep the current behavior EXCEPT
  do not emit plaintext (drop the ciphertext with an `encmempool_decrypted_noexec` marker) - so the leak
  is closed immediately, independent of the execution build landing.
- Ship behind the param, dormant on 10777. Enable only after: the mini-ante is audited, the v1
  precompile restriction is in, and the fee/nonce accounting is proven on a throwaway multi-node run.
- Audit-gated for mainnet like the rest of the DKG track.

## 11. Open decisions for Jason

1. **Precompile policy in v1**: reject re-injected txs that touch precompiles (recommended, safest), or
   invest in a per-precompile determinism audit now?
2. **Block gas budget for decrypted txs**: what fraction of the block gas limit? (start conservative,
   e.g. 25%, tune on a live drain.)
3. **Failed-tx visibility**: emit per-outcome events (as in §8) for observability, or stay quiet? Events
   do not leak plaintext, so I lean toward emitting them.
4. **Immediate leak close**: land the "no plaintext event + `EncExecEnabled` param" change FIRST (small,
   closes finding #1's leak now), then build execution behind it? (Recommended.)

## 12. Phased implementation plan

- **P0 (small, immediate):** remove the `plaintext_hex` event; add `EncExecEnabled` param (default off).
  Closes the public-plaintext leak now. No execution yet.
- **P1:** wire `EVMKeeper` into encmempool; add the `types.EVMKeeper` interface.
- **P2:** the mini-ante + `ApplyTransaction` pipeline (§4) with the v1 precompile restriction, per-tx
  metered child context, cumulative block-gas ceiling, and the failure events (§8).
- **P3:** fix BeginBlocker ordering (after feemarket/evm); confirm base fee + header hash are set.
- **P4:** tests - unit (decode/mini-ante/each failure case) + a multi-node throwaway proving execution,
  fee accounting (fee collector not drained), nonce increment (no replay), determinism (identical
  apphash across nodes), and the gas ceiling deferral. Then one adversarial audit pass.
