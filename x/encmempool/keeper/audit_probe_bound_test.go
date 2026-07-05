// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// TestProbe_RealChainDrainsKeepPinnedEpochsBounded reruns the worst-case multi-epoch
// in-flight/flap pattern (gap=0) BUT drives BeginBlock EVERY block, exactly like a live
// chain — so a ciphertext is drained (decrypted or decrypt_missed, then deleted) at its
// decrypt height, dropping its epoch ref-count. This proves the retained ActiveThresholdKey
// set stays bounded by the DecryptDelay overlap window (O(pending epochs)), NOT O(rekeys):
// the failing untracked probe only saw 5 pinned keys because it never called BeginBlock, so
// nothing ever matured. This is the corrected measurement.
func TestProbe_RealChainDrainsKeepPinnedEpochsBounded(t *testing.T) {
	const thr = 2
	const decryptDelay = 9
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	setA := []member{A, B, C}
	setB := []member{A, B, D}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: decryptDelay,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0, // dampener OFF: worst case for state growth
		DkgMembers: declaredFrom(setA),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	type liveC struct {
		epoch, seq, decrypt uint64
		ct                  *threshold.Ciphertext
		plain               string
		derived             map[uint64]*secp256k1.ModNScalar
	}
	var live []liveC

	// epoch 1 (start): open@1, deal@2, finalize@5.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	ak, derived := dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, setA, 1, thr)

	// pendingShares posts thr decryption shares for any ciphertext maturing at height bh.
	postShares := func(bh int64) {
		for _, ci := range live {
			if int64(ci.decrypt) != bh {
				continue
			}
			round, ok := k.GetDkgRound(ctx, ci.epoch)
			if !ok {
				t.Fatalf("epoch %d round pruned before its ciphertext (seq %d) matured — IN-FLIGHT BROKEN", ci.epoch, ci.seq)
			}
			posted := 0
			for _, rm := range round.Members {
				share, has := ci.derived[rm.Index]
				if !has {
					continue
				}
				ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: rm.Index, Xi: share}, ci.ct)
				if err != nil {
					t.Fatalf("ProveDecryptShare: %v", err)
				}
				if _, err := ms.SubmitDecryptionShare(ctx.WithBlockHeight(bh).WithEventManager(sdk.NewEventManager()), &types.MsgSubmitDecryptionShare{
					Keyper: rm.AccountAddr, DecryptHeight: ci.decrypt, Seq: ci.seq, Index: rm.Index,
					D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
				}); err != nil {
					t.Fatalf("SubmitDecryptionShare: %v", err)
				}
				posted++
				if posted == thr {
					break
				}
			}
		}
	}
	decrypted := map[uint64]bool{}
	beginBlock := func(bh int64) {
		postShares(bh)
		bctx := ctx.WithBlockHeight(bh).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatalf("BeginBlock @%d: %v", bh, err)
		}
		for _, ev := range bctx.EventManager().Events() {
			if ev.Type == "encmempool_decrypted" {
				var seq uint64
				for _, a := range ev.Attributes {
					if a.Key == "seq" {
						fmt.Sscanf(a.Value, "%d", &seq)
					}
				}
				decrypted[seq] = true
			}
		}
	}
	submit := func(h int64, epoch uint64, akPub []byte, der map[uint64]*secp256k1.ModNScalar, tag string) {
		plain := fmt.Sprintf("payload-%s-e%d-h%d", tag, epoch, h)
		ct, err := threshold.Encrypt(akPub, []byte(plain))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		resp, err := ms.SubmitEncrypted(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()), &types.MsgSubmitEncrypted{
			Submitter: "acc1", A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
		})
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
		live = append(live, liveC{epoch: epoch, seq: resp.Seq, decrypt: resp.DecryptHeight, ct: ct, plain: plain, derived: der})
	}

	submit(6, 1, ak.Pub, derived, "e1")

	peakKeys := 0
	curH := int64(6)
	step := func(to int64) {
		for ; curH < to; curH++ {
			beginBlock(curH) // drain at every height, like a live chain
			if ck := k.CountActiveKeys(ctx); ck > peakKeys {
				peakKeys = ck
			}
			// invariant: every epoch with a pending ciphertext keeps its key + round.
			byEpoch := map[uint64]int{}
			k.IterateEncTxUpTo(ctx, ^uint64(0)>>1, func(e types.EncTx) { byEpoch[e.Epoch]++ })
			for ep, n := range byEpoch {
				if ep == 0 {
					continue
				}
				if _, ok := k.GetActiveKey(ctx, ep); !ok {
					t.Fatalf("@%d IN-FLIGHT BROKEN: epoch %d has %d pending ct but key pruned", curH, ep, n)
				}
				if _, ok := k.GetDkgRound(ctx, ep); !ok {
					t.Fatalf("@%d IN-FLIGHT BROKEN: epoch %d has %d pending ct but round pruned", curH, ep, n)
				}
			}
		}
	}

	h := int64(6)
	for round := 0; round < 8; round++ {
		set := setA
		if (round % 2) == 0 {
			set = setB
		}
		p.DkgMembers = declaredFrom(set)
		_ = k.SetParams(ctx, p)

		openH := h + 1
		step(openH)
		k.EndBlockDKG(ctx.WithBlockHeight(openH).WithEventManager(sdk.NewEventManager()))
		epoch := k.GetCurrentEpoch(ctx)
		finalH := openH + 4
		step(openH + 1)
		ak2, der2 := dealAndFinalizeCapturing(t, k, ms, ctx, openH+1, finalH, set, epoch, thr)
		step(finalH + 1)
		submit(finalH+1, epoch, ak2.Pub, der2, fmt.Sprintf("r%d", round))
		if ck := k.CountActiveKeys(ctx); ck > peakKeys {
			peakKeys = ck
		}
		h = finalH + 1
	}

	// Drain the tail.
	var maxDecrypt int64
	for _, ci := range live {
		if int64(ci.decrypt) > maxDecrypt {
			maxDecrypt = int64(ci.decrypt)
		}
	}
	step(maxDecrypt + 2)

	// Every ciphertext must have decrypted under its RETAINED epoch key.
	for _, ci := range live {
		if !decrypted[ci.seq] {
			t.Fatalf("ciphertext seq %d (epoch %d) never decrypted — in-flight decrypt BROKEN across rekeys", ci.seq, ci.epoch)
		}
	}
	// The key finding: with real per-block draining, retained keys stayed BOUNDED by the
	// DecryptDelay overlap (~2 epochs), NOT the 9 rekeys performed. This is what makes the
	// untracked probe's failure a measurement artifact, not unbounded state.
	if peakKeys > 4 {
		t.Fatalf("retained ActiveThresholdKey peak=%d over 9 rekeys — NOT bounded by DecryptDelay overlap", peakKeys)
	}
	if fin := k.CountActiveKeys(ctx); fin > 1 {
		t.Fatalf("after full drain retained keys=%d (want 1)", fin)
	}
	t.Logf("BOUNDED: 9 rekeys, DecryptDelay=%d, peak retained keys=%d, final keys=%d; all %d ciphertexts decrypted",
		decryptDelay, peakKeys, k.CountActiveKeys(ctx), len(live))
}
