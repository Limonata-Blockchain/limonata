package keeper

import (
	"encoding/hex"
	"errors"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
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
	if p.EncEnabled && (p.Threshold > 0 || p.DkgEnabled) {
		k.decryptMatured(ctx, cur, p)
	}
	return nil
}

// decryptMatured combines keyper shares to decrypt every EncTx maturing at height
// cur, in deterministic (seq) order. PROTOTYPE: it emits the decrypted body as an
// event (proving decryption) rather than re-injecting it into the EVM pipeline.
//
// On the DKG path (e.Epoch > 0) it routes through dkg.RecoverVerified: each keyper's
// partial is checked against its public share key (recomputed from the epoch's DKG
// commitments) via the stored DLEQ proof, so a malicious keyper's bad partial is
// DROPPED WITH ATTRIBUTION instead of silently corrupting the Lagrange combine. On
// the legacy path (epoch 0) it uses the unverified threshold.Recover as before.
func (k Keeper) decryptMatured(ctx sdk.Context, cur uint64, p types.Params) {
	var matured []types.EncTx
	k.IterateEncTxAtHeight(ctx, cur, func(e types.EncTx) { matured = append(matured, e) })

	order := uint64(0)
	for _, e := range matured {
		shares := k.CollectShares(ctx, e.DecryptHeight, e.Seq)
		shared, need, err := k.recoverSharedSecret(ctx, p, e, shares)
		switch {
		case err == errNotEnoughShares:
			ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_missed",
				sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
				sdk.NewAttribute("have", strconv.Itoa(len(shares))),
				sdk.NewAttribute("need", strconv.Itoa(need))))
		case err != nil:
			ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
				sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
				sdk.NewAttribute("reason", err.Error())))
		default:
			plaintext, derr := threshold.Decrypt(shared, &threshold.Ciphertext{A: e.A, Nonce: e.Nonce, Body: e.Body})
			if derr == nil {
				ctx.EventManager().EmitEvent(sdk.NewEvent(
					"encmempool_decrypted",
					sdk.NewAttribute("submitter", e.Submitter),
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
					sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
					sdk.NewAttribute("plaintext_hex", hex.EncodeToString(plaintext)),
				))
				order++
			} else {
				ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("reason", derr.Error())))
			}
		}
		// GC the ciphertext + its shares regardless (bounded state).
		k.DeleteEncTx(ctx, e.DecryptHeight, e.Seq)
		k.DeleteSharesFor(ctx, e.DecryptHeight, e.Seq)
	}
}

var errNotEnoughShares = errors.New("not enough shares")

// recoverSharedSecret recovers x*A for an EncTx from the collected keyper shares,
// choosing the DKG-verified path (epoch > 0) or the legacy path (epoch 0). It
// returns errNotEnoughShares (with the required count) when < t shares are present.
func (k Keeper) recoverSharedSecret(ctx sdk.Context, p types.Params, e types.EncTx, shares []types.EncShare) (shared *secp256k1.JacobianPoint, need int, err error) {
	if e.Epoch > 0 {
		ak, ok := k.GetActiveKey(ctx, e.Epoch)
		if !ok {
			return nil, 0, errors.New("no active key for epoch")
		}
		need = int(ak.Threshold)
		if len(shares) < need {
			return nil, need, errNotEnoughShares
		}
		commitments, perr := dkg.ParseCommitmentPoints(ak.PublicCommitments)
		if perr != nil {
			return nil, need, perr
		}
		partials := make([]dkg.VerifiedShare, 0, len(shares))
		for _, s := range shares {
			proof, perr := dkg.ParseDLEQProof(s.Proof)
			if perr != nil {
				continue // unproven share: RecoverVerified would drop it anyway
			}
			partials = append(partials, dkg.VerifiedShare{
				Share: &threshold.DecryptShare{Index: s.Index, D: s.D}, Proof: proof,
			})
		}
		shared, err = dkg.RecoverVerified(commitments, e.A, need, partials)
		return shared, need, err
	}

	// legacy trusted-setup path
	need = int(p.Threshold)
	if len(shares) < need {
		return nil, need, errNotEnoughShares
	}
	ds := make([]*threshold.DecryptShare, 0, need)
	for _, s := range shares[:need] {
		ds = append(ds, &threshold.DecryptShare{Index: s.Index, D: s.D})
	}
	shared, err = threshold.Recover(ds)
	return shared, need, err
}
