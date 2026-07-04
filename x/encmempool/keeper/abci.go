package keeper

import (
	"encoding/hex"
	"errors"
	"fmt"
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
// REMAINING GAP (deferred): re-injecting the decrypted plaintext (an RLP EVM tx) into
// EVM execution. That requires decoding the tx, running it through x/vm's state
// transition + ante/gas/nonce accounting inside BeginBlock in this deterministic
// order — a large, halt-risk pipeline change. It is intentionally NOT done here so
// the multi-node reliability hardening stays build-stable; the decrypted-body event
// is the stable seam a future EVM-injection step plugs into.
//
// On the DKG path (e.Epoch > 0) it routes through dkg.RecoverVerified: each keyper's
// partial is checked against its public share key (recomputed from the epoch's DKG
// commitments) via the stored DLEQ proof, so a malicious keyper's bad partial is
// DROPPED WITH ATTRIBUTION instead of silently corrupting the Lagrange combine. On
// the legacy path (epoch 0) it uses the unverified threshold.Recover as before.
// maxDecryptAttemptsPerBlock bounds the number of threshold-recovery attempts (each
// does up to t DLEQ verifications + a Lagrange combine) BeginBlock performs at a single
// height. Ciphertexts maturing at one height are already gas-bounded (one submit block
// maps to exactly one decrypt height), so this is defense-in-depth: it caps the crypto
// work per block so no flood of ciphertexts can stall block production. The cap is far
// above any legitimate per-block volume, so normal operation never reaches it.
const maxDecryptAttemptsPerBlock = 2048

func (k Keeper) decryptMatured(ctx sdk.Context, cur uint64, p types.Params) {
	// Process everything matured by `cur` (decrypt height <= cur), which INCLUDES any
	// ciphertext DEFERRED from a prior height when the per-block cap was hit — so nothing
	// is silently lost. Deterministic (decryptHeight, seq) order on every node.
	var matured []types.EncTx
	k.IterateEncTxUpTo(ctx, cur, func(e types.EncTx) { matured = append(matured, e) })

	order := uint64(0)
	attempts := 0
	for i, e := range matured {
		// BOUNDED CRYPTO WORK: once the per-block attempt cap is hit, DEFER the remaining
		// matured ciphertexts to a later block rather than DROPPING them (MEDIUM FIX). They
		// stay in state (still ref-counted against their epoch) and are picked up next block
		// by IterateEncTxUpTo, so no share-carrying work is silently lost — only spread
		// across blocks. Deterministic: `matured` is in (decryptHeight, seq) order on every
		// node, so all nodes defer the identical suffix.
		if attempts >= maxDecryptAttemptsPerBlock {
			ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_deferred",
				sdk.NewAttribute("height", strconv.FormatUint(cur, 10)),
				sdk.NewAttribute("deferred", strconv.Itoa(len(matured)-i))))
			break
		}
		attempts++
		// CONSENSUS SAFETY: BeginBlock must never panic on data-dependent input, or a
		// single malformed EncTx (e.g. a permissionlessly-submitted ciphertext with an
		// out-of-spec nonce) would halt the whole chain. Process each ciphertext inside
		// a recover guard; any panic is contained and reported, and the ciphertext is
		// GC'd below so a bad entry cannot wedge the chain into a crash loop.
		func(e types.EncTx) {
			defer func() {
				if r := recover(); r != nil {
					ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("reason", fmt.Sprintf("panic recovered: %v", r))))
				}
			}()
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
		}(e)
		// GC the ciphertext + its shares regardless (bounded state).
		k.DeleteEncTx(ctx, e.DecryptHeight, e.Seq)
		k.DeleteSharesFor(ctx, e.DecryptHeight, e.Seq)
		// HIGH-2 variant: this ciphertext no longer pins its DKG epoch. Drop the ref-count
		// and, if it was the LAST in-flight ciphertext for a now-superseded epoch, reclaim
		// that epoch's DkgRound + ActiveThresholdKey. Doing the prune HERE (rather than only
		// at finalize) is what lets an epoch be GC'd the instant it drains, even if it was
		// superseded while ciphertexts were still in flight.
		if e.Epoch > 0 {
			k.decEpochEncCount(ctx, e.Epoch)
			k.maybePruneEpoch(ctx, e.Epoch)
		}
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
