package keeper

import (
	"encoding/hex"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// BeginBlock executes matured reveals in deterministic store-key order
// (big-endian commitHeight -> sender -> seq) and garbage-collects stale commits.
//
// All logic lives in BeginBlock so every node computes identical state: there is no
// proposer-only logic and no ABCI++ vote extension. This is the load-bearing reason
// the prototype is consensus-safe.
//
// HONESTY: this is a delay/ordering primitive, NOT encryption. "Execute" here means
// the module records the deterministic execution order and emits an event; it does
// not re-inject the payload into the EVM/tx pipeline. The reveal that a user submits
// is itself an ordinary tx. Real MEV resistance requires threshold encryption with
// >= 2 independent keypers, which plugs into this exact commit/reveal/execute slot.
func (k Keeper) BeginBlock(ctx sdk.Context) error {
	p := k.GetParams(ctx)
	cur := uint64(ctx.BlockHeight())

	// 1. Collect pending reveals into an explicit slice (keys already sorted).
	var pending []types.PendingReveal
	k.IteratePending(ctx, func(pr types.PendingReveal) { pending = append(pending, pr) })

	// 2. Execute matured reveals in deterministic order.
	order := uint64(0)
	for _, pr := range pending {
		if cur < pr.CommitHeight+p.RevealDelay {
			continue // not matured (the reveal gate already enforces this; defensive)
		}
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_reveal_executed",
			sdk.NewAttribute("sender", pr.Sender),
			sdk.NewAttribute("commit_height", strconv.FormatUint(pr.CommitHeight, 10)),
			sdk.NewAttribute("seq", strconv.FormatUint(pr.Seq, 10)),
			sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
		))
		order++
		k.DeletePending(ctx, pr.CommitHeight, pr.Sender, pr.Seq)
		k.DeleteCommit(ctx, pr.CommitHeight, pr.Sender, pr.Seq)
	}

	// 3. GC commits that were never revealed within the window (bounded state).
	if p.MaxRevealWindow > 0 {
		var stale []types.Commit
		k.IterateCommits(ctx, func(c types.Commit) {
			if c.Height+p.MaxRevealWindow < cur {
				stale = append(stale, c)
			}
		})
		for _, c := range stale {
			k.DeleteCommit(ctx, c.Height, c.Sender, c.Seq)
			k.DeletePending(ctx, c.Height, c.Sender, c.Seq)
		}
	}

	// 4. Threshold-encryption path (OPT-IN). Decrypt + reveal ciphertexts whose
	//    decrypt height is now, when >= t keyper shares are present. Fully
	//    deterministic (identical on every node) — consensus-safe.
	if p.EncEnabled && p.Threshold > 0 {
		k.decryptMatured(ctx, cur, p)
	}
	return nil
}

// decryptMatured combines keyper shares to decrypt every EncTx maturing at height
// cur, in deterministic (seq) order. PROTOTYPE: it emits the decrypted body as an
// event (proving decryption) rather than re-injecting it into the EVM pipeline,
// and it takes the first t shares without verifying each share is well-formed (a
// production system needs per-share correctness proofs).
func (k Keeper) decryptMatured(ctx sdk.Context, cur uint64, p types.Params) {
	var matured []types.EncTx
	k.IterateEncTxAtHeight(ctx, cur, func(e types.EncTx) { matured = append(matured, e) })

	order := uint64(0)
	for _, e := range matured {
		shares := k.CollectShares(ctx, e.DecryptHeight, e.Seq)
		if uint64(len(shares)) >= uint64(p.Threshold) {
			ds := make([]*threshold.DecryptShare, 0, p.Threshold)
			for _, s := range shares[:p.Threshold] {
				ds = append(ds, &threshold.DecryptShare{Index: s.Index, D: s.D})
			}
			shared, err := threshold.Recover(ds)
			var plaintext []byte
			if err == nil {
				plaintext, err = threshold.Decrypt(shared, &threshold.Ciphertext{A: e.A, Nonce: e.Nonce, Body: e.Body})
			}
			if err == nil {
				ctx.EventManager().EmitEvent(sdk.NewEvent(
					"encmempool_decrypted",
					sdk.NewAttribute("submitter", e.Submitter),
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
					sdk.NewAttribute("plaintext_hex", hex.EncodeToString(plaintext)),
				))
				order++
			} else {
				ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10))))
			}
		} else {
			ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_missed",
				sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
				sdk.NewAttribute("shares", strconv.Itoa(len(shares)))))
		}
		// GC the ciphertext + its shares regardless (bounded state).
		k.DeleteEncTx(ctx, e.DecryptHeight, e.Seq)
		k.DeleteSharesFor(ctx, e.DecryptHeight, e.Seq)
	}
}
