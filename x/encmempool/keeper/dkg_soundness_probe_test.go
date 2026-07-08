// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"crypto/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// These were the HIGH-1 REPRODUCTION probes (a malformed enc-share `A` was accepted at
// ingress, was structurally uncomplainable, kept its dealer in QUAL, and thereby
// poisoned every honest member's share => permanent keyless-liveness DoS). They are now
// the REGRESSION tests for the fix: the malformed dealing is REJECTED at DkgDeal
// ingress, and — defense-in-depth — a structurally-unopenable share that ever reached
// state is JUSTIFY-DISQUALIFIABLE via a complaint. Each asserts the FIXED behavior and
// therefore FAILS on the pre-fix tree.

// tiny alias so the tests read cleanly.
type secp256k1Scalar = secp256k1.ModNScalar

// TestRegression_MalformedEncShareA_RejectedAtIngress: a dealer that seals a malformed
// (non-point) `A` to every other member must be REJECTED by DkgDeal, so it can never
// enter QUAL. The honest dealers finalize a clean key that excludes it.
func TestRegression_MalformedEncShareA_RejectedAtIngress(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DkgDealWindow: 2, DkgComplaintWindow: 4,
		DkgThreshold: thr, DkgMembers: declaredFrom(members),
	}
	_ = k.SetParams(ctx, p)

	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, _ := k.GetDkgRound(ctx, 1)
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
	all := []uint64{1, 2, 3}

	dealCtx := ctx.WithBlockHeight(2)
	malformedA := []byte{0x02, 0x00} // non-empty, but NOT a 33-byte compressed point
	for di, dealerM := range members {
		commitments, shares, err := dkg.Deal(dealerM.index, all, thr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encShares := make([]*types.DkgEncShare, 0, len(all))
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatal(err)
			}
			a := ct.A
			if di == 0 && recip.index != dealerM.index {
				a = malformedA // dealer 0 corrupts A to every victim
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: a, Nonce: ct.Nonce, Body: ct.Body})
		}
		_, err = ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares})
		if di == 0 {
			if err == nil {
				t.Fatal("HIGH-1: malformed enc-share A was ACCEPTED at ingress (must be rejected)")
			}
			if _, ok := k.GetDealing(ctx, 1, dealerM.index); ok {
				t.Fatal("a rejected malformed dealing must not be stored")
			}
		} else if err != nil {
			t.Fatalf("honest DkgDeal(%s) unexpectedly rejected: %v", dealerM.acc, err)
		}
	}

	// The 2 honest dealers finalize a clean key; the malicious dealer never entered QUAL.
	finCtx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok {
		t.Fatal("expected a clean active key from the 2 honest dealers")
	}
	for _, q := range ak.Qual {
		if q == members[0].index {
			t.Fatalf("malicious dealer %d must NOT be in QUAL=%v", members[0].index, ak.Qual)
		}
	}
	t.Log("FIXED: malformed-A dealing rejected at ingress; QUAL is clean")
}

// TestRegression_MalformedEncShareA_JustifyDisqualifiable is the defense-in-depth: even
// if a structurally-unopenable dealing somehow reaches state (e.g. a genesis import that
// bypasses the handler), it is a PUBLIC fault that a member can complain about and
// disqualify. (a) unit-level VerifyJustifiedComplaint now returns cheated=true,
// proofValid=true for a malformed A; (b) the on-chain complaint path disqualifies it.
func TestRegression_MalformedEncShareA_JustifyDisqualifiable(t *testing.T) {
	// (a) unit level: a malformed enc-share A is justify-disqualifiable, not uncomplainable.
	accuser := newMember("op1", "acc1")
	commitments, _, err := dkg.Deal(1, []uint64{1, 2, 3}, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malformedA := []byte{0x02, 0x00}
	for i := 0; i < 50; i++ {
		fakeCt, _ := threshold.Encrypt(accuser.pub, make([]byte, 32))
		ds, proof, e := dkg.ProveDecryptShare(threshold.Share{Index: 2, Xi: accuser.priv}, fakeCt)
		if e != nil {
			t.Fatal(e)
		}
		cheated, proofValid := dkg.VerifyJustifiedComplaint(
			2, accuser.pub, commitments,
			malformedA, fakeCt.Nonce, fakeCt.Body, ds.D, dkg.MarshalDLEQProof(proof),
		)
		if !cheated || !proofValid {
			t.Fatalf("iter %d: malformed enc-share A must be justify-disqualifiable (got cheated=%v proofValid=%v)", i, cheated, proofValid)
		}
	}

	// (b) end-to-end: inject a malformed-A dealing directly into state (bypassing the
	// handler, as a genesis import would), then complain and disqualify it at finalize.
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DkgDealWindow: 2, DkgComplaintWindow: 4,
		DkgThreshold: thr, DkgMembers: declaredFrom(members),
	}
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, _ := k.GetDkgRound(ctx, 1)
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}

	// Inject the malformed-A dealing from members[0] straight into the store.
	mcom, _, err := dkg.Deal(members[0].index, []uint64{1, 2, 3}, thr, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	injected := types.Dealing{Epoch: 1, DealerIndex: members[0].index, Dealer: members[0].acc, Commitments: mcom}
	for _, recip := range members {
		injected.EncShares = append(injected.EncShares, types.DkgStoredEncShare{
			MemberIndex: recip.index, A: []byte{0x02, 0x00}, Nonce: make([]byte, threshold.NonceSize), Body: []byte{0x01},
		})
	}
	if err := k.SetDealing(ctx, injected); err != nil {
		t.Fatal(err)
	}
	// honest dealers 2,3 deal normally so the round can finalize with |QUAL| >= t.
	dealCtx := ctx.WithBlockHeight(2)
	for _, dealerM := range members[1:] {
		commitments, shares, err := dkg.Deal(dealerM.index, []uint64{1, 2, 3}, thr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encShares := make([]*types.DkgEncShare, 0, 3)
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatal(err)
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
		if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares}); err != nil {
			t.Fatalf("honest deal(%s): %v", dealerM.acc, err)
		}
	}

	// victim (member 2) complains about the injected malformed-A dealer. The complaint
	// must be ACCEPTED (a public, unframeable fault) — pre-fix it was rejected.
	victim := members[1]
	fakeCt, _ := threshold.Encrypt(victim.pub, make([]byte, 32))
	ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: victim.index, Xi: victim.priv}, fakeCt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.DkgComplaint(ctx.WithBlockHeight(3), &types.MsgDkgComplaint{
		Accuser: victim.acc, Epoch: 1, Against: members[0].index,
		SharedPoint: ds.D, DleqProof: dkg.MarshalDLEQProof(proof),
	}); err != nil {
		t.Fatalf("complaint against a structurally-malformed dealing was rejected: %v", err)
	}

	finCtx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok {
		t.Fatal("expected finalize to install a key from the 2 honest dealers")
	}
	for _, q := range ak.Qual {
		if q == members[0].index {
			t.Fatalf("complained-against malformed dealer %d must be disqualified, QUAL=%v", members[0].index, ak.Qual)
		}
	}
	t.Log("FIXED: a structurally-unopenable dealing is justify-disqualifiable (defense-in-depth)")
}

// TestRegression_MalformedEncShareA_LivenessPreserved drives the whole scenario end to
// end: the malicious dealer is rejected at ingress, QUAL is the clean honest set, and a
// ciphertext encrypted to the DKG key DECRYPTS on-chain — i.e. the keyless-liveness DoS
// is gone. Pre-fix, the malicious dealer stayed in QUAL and decryption was impossible.
func TestRegression_MalformedEncShareA_LivenessPreserved(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DkgDealWindow: 2, DkgComplaintWindow: 2,
		DecryptDelay: 2, DkgThreshold: thr, DkgMembers: declaredFrom(members),
	}
	_ = k.SetParams(ctx, p)

	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, _ := k.GetDkgRound(ctx, 1)
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
	all := []uint64{1, 2, 3}

	dealCtx := ctx.WithBlockHeight(2)
	malformedA := []byte{0x02, 0x00}
	// good[dealer][member] = the plaintext share a member can derive from that dealer.
	good := map[uint64]map[uint64]*secp256k1Scalar{}
	for di, dealerM := range members {
		commitments, shares, err := dkg.Deal(dealerM.index, all, thr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		good[dealerM.index] = map[uint64]*secp256k1Scalar{}
		encShares := make([]*types.DkgEncShare, 0, len(all))
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatal(err)
			}
			a := ct.A
			if di == 0 && recip.index != dealerM.index {
				a = malformedA
			} else {
				good[dealerM.index][recip.index] = shares[recip.index]
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: a, Nonce: ct.Nonce, Body: ct.Body})
		}
		_, err = ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares})
		if di == 0 {
			if err == nil {
				t.Fatal("HIGH-1: malformed-A dealing accepted at ingress (must be rejected)")
			}
		} else if err != nil {
			t.Fatalf("honest deal(%s): %v", dealerM.acc, err)
		}
	}

	finCtx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok {
		t.Fatal("expected an active key from the 2 honest dealers")
	}
	if len(ak.Qual) != 2 {
		t.Fatalf("expected QUAL of the 2 honest dealers, got %v", ak.Qual)
	}

	// A ciphertext to the clean DKG key decrypts fine — liveness preserved.
	plain := []byte("front-run me if you can")
	ct, err := threshold.Encrypt(ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	submitCtx := ctx.WithBlockHeight(6)
	if _, err := ms.SubmitEncrypted(submitCtx, &types.MsgSubmitEncrypted{Submitter: "acc1", A: ct.A, Nonce: ct.Nonce, Body: ct.Body}); err != nil {
		t.Fatalf("SubmitEncrypted: %v", err)
	}
	var e types.EncTx
	k.IterateEncTxAtHeight(submitCtx, 8, func(x types.EncTx) { e = x })

	// Shares may only be submitted at/after maturity (anti-MEV maturity gate).
	shareCtx := ctx.WithBlockHeight(int64(e.DecryptHeight))
	for _, m := range members[1:] {
		X := new(secp256k1Scalar)
		first := true
		for _, dealer := range ak.Qual {
			s := good[dealer][m.index]
			if s == nil {
				t.Fatalf("member %d cannot derive its share from QUAL dealer %d — QUAL must be clean", m.index, dealer)
			}
			if first {
				X.Set(s)
				first = false
			} else {
				X.Add(s)
			}
		}
		ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: m.index, Xi: X}, ct)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ms.SubmitDecryptionShare(shareCtx, &types.MsgSubmitDecryptionShare{
			Keyper: m.acc, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: m.index,
			D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		}); err != nil {
			t.Fatalf("SubmitDecryptionShare(%s): %v", m.acc, err)
		}
	}

	bctx := ctx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatal(err)
	}
	got, ok := decryptedPlaintext(bctx)
	if !ok || string(got) != string(plain) {
		t.Fatalf("expected clean decryption of %q, got ok=%v plain=%q", plain, ok, got)
	}
	t.Log("FIXED: malformed-A dealer rejected, QUAL clean, decryption succeeds — keyless-liveness DoS gone")
}
