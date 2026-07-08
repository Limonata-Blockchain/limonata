// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

import (
	"math/big"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	evmante "github.com/cosmos/evm/ante/evm"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/ethereum/go-ethereum/core"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

// maxDecryptExecGasPerBlockBps caps the total EVM gas the decrypted-tx re-injection may spend in one
// block, as a fraction (basis points) of the block gas limit. Decrypted txs execute in BeginBlock,
// BEFORE the block's normal txs; bounding their aggregate gas keeps them from starving normal-tx
// capacity or blowing block time. 2500 bps = 25%. Excess matured ciphertexts stay in state and
// execute on a later block (the deterministic bounded-scan suffix).
const maxDecryptExecGasPerBlockBps = 2500

// defaultDecryptExecGasPerBlock is the per-block decrypt-exec gas budget used when the block gas
// limit is unavailable/unlimited (evmd disables the block gas meter and the default consensus
// MaxGas is -1). Audit D2: without a floor the ceiling would be 0, and an ON feature would then
// STRAND every matured ciphertext (break before consume). 30M gas ~ a couple of heavy txs/block.
const defaultDecryptExecGasPerBlock = 30_000_000

// reinjectTxIndexBase offsets the per-tx TxIndex of decrypted txs far above any real per-block tx
// count, so their EVM object-store transient state (gas-used / sponsor, keyed by TxIndex, reset only
// at Commit) never collides with the normal DeliverTx txs at indices 0..N (audit A1).
const reinjectTxIndexBase = 1 << 30

// encExecEnabled reports whether decrypt->execute re-injection should run this block: the governance
// param is on AND the EVM/account keepers were wired (both nil in the minimal unit-test build). When
// false, decryptMatured takes the P0 no-execution path (decrypt + consume, never emit plaintext).
func (k Keeper) encExecEnabled(encExec bool) bool {
	return encExec && k.evmKeeper != nil && k.accountKeeper != nil
}

// decryptExecOutcome is the event-tag result of attempting to re-inject one decrypted tx. It NEVER
// carries plaintext - only the outcome + gas, so the execution stays observable without leaking the
// content (review #1).
type decryptExecOutcome struct {
	executed bool   // ApplyTransaction ran (the tx was included; may still have reverted)
	reverted bool   // executed AND the EVM reverted (a normal reverting tx, still charged/nonced)
	gasUsed  uint64 // EVM gas used (0 when not executed)
	tag      string // machine-readable outcome for the event
	txHash   string // the eth tx hash (empty when undecodable)
}

// executeDecryptedTx runs a decrypted RLP Ethereum transaction through the EVM in BeginBlock,
// replicating the EVM ante's fee/nonce/balance steps that ApplyTransaction bypasses (it refunds
// leftover gas but never buys it, and never bumps a CALL's nonce). It MUST be called on a per-tx
// CACHE context that the caller commits only when executed==true; a failed check returns
// executed=false so the caller discards the child context. It NEVER panics on attacker-controlled
// bytes: every failure returns a tagged outcome.
//
// v1 fork-safety: a tx whose top-level `To` is a registered precompile is REJECTED (precompiles call
// other keepers and are the most likely source of context-sensitive behavior outside a normal tx).
func (k Keeper) executeDecryptedTx(ctx sdk.Context, plaintext []byte, gasBudget uint64) decryptExecOutcome {
	// 1. Decode the RLP Ethereum transaction.
	tx := new(ethtypes.Transaction)
	if err := tx.UnmarshalBinary(plaintext); err != nil {
		return decryptExecOutcome{tag: "invalid_rlp"}
	}
	txHash := tx.Hash().Hex()

	// Blob txs (EIP-4844) are rejected by the normal EVM ante's AcceptedTxType allowlist and carry
	// blob-fee accounting this BeginBlock path does not set up; refuse them (audit).
	if tx.Type() == ethtypes.BlobTxType {
		return decryptExecOutcome{tag: "unsupported_tx_type", txHash: txHash}
	}
	// Per-tx gas cap (audit D1): the child runs on an infinite gas meter, so without this a single
	// decrypted tx could declare an arbitrarily large gas limit and burn seconds of BeginBlock EVM
	// compute before the cumulative ceiling check fires. A tx above the whole-block decrypt budget
	// can never execute, so reject it here (it is consumed, not deferred).
	if gasBudget > 0 && tx.Gas() > gasBudget {
		return decryptExecOutcome{tag: "gas_too_large", txHash: txHash}
	}

	// 2. Load the EVM config and recover the sender with the chain-rules signer (bad sig / wrong
	//    chain-id => rejected, not a panic).
	cfg, err := k.evmKeeper.EVMConfig(ctx, ctx.BlockHeader().ProposerAddress)
	if err != nil {
		return decryptExecOutcome{tag: "evm_config", txHash: txHash}
	}
	signer := ethtypes.MakeSigner(evmtypes.GetEthChainConfig(), big.NewInt(ctx.BlockHeight()), uint64(ctx.BlockTime().Unix())) //#nosec G115
	coreMsg, err := core.TransactionToMessage(tx, signer, cfg.BaseFee)
	if err != nil {
		return decryptExecOutcome{tag: "bad_signature", txHash: txHash}
	}
	from := coreMsg.From

	// 3. Precompile reject (v1 fork-safety): refuse a tx that directly targets a precompile.
	if to := tx.To(); to != nil {
		if _, isPrecompile, _ := k.evmKeeper.GetPrecompileInstance(ctx, *to); isPrecompile {
			return decryptExecOutcome{tag: "precompile_blocked", txHash: txHash}
		}
	}

	// 4. Nonce must equal the sender's current sequence (replay + strict ordering).
	if k.evmKeeper.GetNonce(ctx, from) != tx.Nonce() {
		return decryptExecOutcome{tag: "bad_nonce", txHash: txHash}
	}

	// 5. Fee-cap + balance. VerifyFee enforces gasFeeCap >= baseFee and returns the fee coins;
	//    CheckSenderBalance ensures the sender can cover value + gas so buyGas cannot fail.
	ethCfg := evmtypes.GetEthChainConfig()
	blockNum := big.NewInt(ctx.BlockHeight())
	blockTime := uint64(ctx.BlockTime().Unix()) //#nosec G115
	fees, err := evmkeeper.VerifyFee(
		tx, evmtypes.GetEVMCoinDenom(), cfg.BaseFee,
		ethCfg.IsHomestead(blockNum), ethCfg.IsIstanbul(blockNum), ethCfg.IsShanghai(blockNum, blockTime),
		false, // isCheckTx: this is deterministic delivery, not a mempool check
	)
	if err != nil {
		return decryptExecOutcome{tag: "fee_cap", txHash: txHash}
	}
	if err := evmkeeper.CheckSenderBalance(sdkmath.NewIntFromBigInt(k.evmKeeper.GetBalance(ctx, from).ToBig()), tx, false); err != nil {
		return decryptExecOutcome{tag: "unpayable", txHash: txHash}
	}
	if err := evmante.CanTransfer(ctx, k.evmKeeper, *coreMsg, cfg.BaseFee, cfg.Params, ethCfg.IsLondon(blockNum)); err != nil {
		return decryptExecOutcome{tag: "cant_transfer", txHash: txHash}
	}

	// 6+7. Buy gas up front (ApplyTransaction only REFUNDS; without this its refund drains the fee
	//      collector). sponsored=false routes the refund to the sender so the round-trip nets to
	//      gasUsed*gasPrice.
	k.evmKeeper.SetTxSponsored(ctx, false)
	if err := k.evmKeeper.DeductTxCostsFromUserBalance(ctx, fees, from, false); err != nil {
		return decryptExecOutcome{tag: "fee_deduct", txHash: txHash}
	}

	// 8. Execute. A state-transition error (bad config, intrinsic gas, etc.) => caller discards the
	//    child context. A revert is surfaced via res.Failed(), not an error - a normal reverting tx.
	res, err := k.evmKeeper.ApplyTransaction(ctx, tx)
	if err != nil {
		return decryptExecOutcome{tag: "exec_error", txHash: txHash}
	}

	// 9. Increment the nonce UNCONDITIONALLY (audit C1). It is idempotent: a SUCCESSFUL contract-
	//    CREATE already bumped the sequence inside the StateDB, so IncrementNonce sees txNonce <
	//    sequence and no-ops; but a REVERTED create's StateDB bump is rolled back by ApplyTransaction,
	//    and a CALL never bumps at all, so those still need the manual increment. Without this, a
	//    reverted create is charged a fee but keeps its nonce -> the identical tx replays forever.
	if acc := k.accountKeeper.GetAccount(ctx, sdk.AccAddress(from.Bytes())); acc != nil {
		_ = evmante.IncrementNonce(ctx, k.accountKeeper, acc, tx.Nonce())
	}

	out := decryptExecOutcome{executed: true, gasUsed: res.GasUsed, txHash: txHash, tag: "executed"}
	if res.Failed() {
		out.reverted = true
		out.tag = "reverted"
	}
	return out
}

// decryptExecGasCeiling returns this block's cumulative EVM-gas budget for decrypted-tx execution
// (a fraction of the block gas limit).
// decryptExecGasCeiling returns this block's cumulative EVM-gas budget for decrypted-tx execution.
// It is NEVER 0 while execution is on: when a positive block gas limit is known it is
// maxDecryptExecGasPerBlockBps of it, otherwise the defaultDecryptExecGasPerBlock floor (audit D2 -
// a 0 ceiling would strand every ciphertext). Deterministic: consensus params + the fixed constants.
func decryptExecGasCeiling(ctx sdk.Context) uint64 {
	if cp := ctx.ConsensusParams(); cp.Block != nil && cp.Block.MaxGas > 0 {
		frac := uint64(cp.Block.MaxGas) / 10000 * maxDecryptExecGasPerBlockBps //#nosec G115
		if frac < defaultDecryptExecGasPerBlock {
			return frac
		}
	}
	return defaultDecryptExecGasPerBlock
}
