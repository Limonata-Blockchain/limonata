// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// helper: compressed s*G
func baseMul(s *secp256k1.ModNScalar) []byte {
	var P secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(s, &P)
	P.ToAffine()
	return secp256k1.NewPublicKey(&P.X, &P.Y).SerializeCompressed()
}

func randScalarP() *secp256k1.ModNScalar {
	for {
		var b [32]byte
		rand.Read(b[:])
		var s secp256k1.ModNScalar
		if s.SetBytes(&b) == 0 && !s.IsZero() {
			return &s
		}
	}
}

// dummy enc-shares (one per member index) that pass the msg-handler well-formedness
// checks; content is irrelevant to finalize (which reads only commitments+complaints).
func dummyEncShares(members []member) []*types.DkgEncShare {
	out := make([]*types.DkgEncShare, 0, len(members))
	dummy := randScalarP()
	for _, recip := range members {
		ct, err := dkg.EncryptShareTo(recip.pub, dummy)
		if err != nil {
			panic(err)
		}
		out = append(out, &types.DkgEncShare{MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
	}
	return out
}

func openEpoch1(t *testing.T, k keeper.Keeper, ctx sdk.Context, members []member, thr uint32) {
	t.Helper()
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: thr, DkgMembers: declaredFrom(members),
		DkgRetryBackoff: 2, DkgMaxAttempts: 8,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok {
		t.Fatal("epoch 1 not opened")
	}
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
}

// PROBE 1 — CONSENSUS-HALT hunt: two byzantine validators craft valid-point
// commitments whose constant terms are negatives of each other, so the QUAL
// aggregate V_0 = C_{1,0} + C_{2,0} = point at infinity. finalizeRound then calls
// compressCopy(&V[0]) in the UNGUARDED EndBlock path. If that panics, two validators
// (realistic when honest daemons lag the deal window — a KNOWN gap) halt the chain.
func TestProbe_AggregateToInfinity_NoPanic(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	openEpoch1(t, k, ctx, members, thr)

	// Sort so indices are stable; craft C_{1,0}=s*G, C_{2,0}=(-s)*G.
	s := randScalarP()
	negS := new(secp256k1.ModNScalar)
	negS.Set(s).Negate()
	r1, r2 := randScalarP(), randScalarP()

	// Which member got index 1 vs 2 (by operator sort). Both accounts deal.
	deal := func(acc string, c0, c1 []byte) {
		if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
			Dealer: acc, Epoch: 1, Commitments: [][]byte{c0, c1}, EncShares: dummyEncShares(members),
		}); err != nil {
			t.Fatalf("DkgDeal(%s): %v", acc, err)
		}
	}
	deal(members[0].acc, baseMul(s), baseMul(r1))
	deal(members[1].acc, baseMul(negS), baseMul(r2))

	// Finalize at the complaint deadline (h=5) — guard against a panic (= chain halt).
	var panicked interface{}
	func() {
		defer func() { panicked = recover() }()
		k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
	}()
	if panicked != nil {
		t.Fatalf("CONSENSUS HALT: EndBlock finalize panicked on infinity aggregate: %v", panicked)
	}
	ak, ok := k.GetActiveKey(ctx, 1)
	t.Logf("installed active key? %v; Pub=%x", ok, func() []byte {
		if ok {
			return ak.Pub
		}
		return nil
	}())
	round, _ := k.GetDkgRound(ctx, 1)
	t.Logf("round status after finalize: %q qual would be both", round.Status)
}

// PROBE 2 (now a REGRESSION test) — malformed commitments must be REJECTED at ingress
// so a member cannot enter a dealing with garbage/short commitments at all, and the
// EndBlock finalize (which is independently no-panic-hardened) still recovers gracefully
// from the resulting sub-quorum. member1 submits garbage 33-byte non-points; member3
// submits wrong-length commitment bytes; both must be rejected; only member2's honest
// dealing lands, so |QUAL|=1 < t=2 and the round FAILS (never panics).
func TestProbe_MalformedCommitments_NoPanic(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	openEpoch1(t, k, ctx, members, thr)

	// member1: two 33-byte garbage "points" (not on curve) -> REJECTED at ingress.
	garbage := make([]byte, 33)
	garbage[0] = 0x02
	for i := 1; i < 33; i++ {
		garbage[i] = 0xFF
	}
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[0].acc, Epoch: 1, Commitments: [][]byte{garbage, garbage}, EncShares: dummyEncShares(members),
	}); err == nil {
		t.Fatal("garbage-commitment dealing was ACCEPTED at ingress (must be rejected)")
	}
	if _, ok := k.GetDealing(ctx, 1, members[0].index); ok {
		t.Fatal("a rejected garbage dealing must not be stored")
	}
	// member2: two honest commitments so there is a mix.
	c2, _, _ := dkg.Deal(members[1].index, []uint64{1, 2, 3}, thr, rand.Reader)
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[1].acc, Epoch: 1, Commitments: c2, EncShares: dummyEncShares(members),
	}); err != nil {
		t.Fatalf("honest deal: %v", err)
	}
	// member3: wrong-length commitment bytes (5 bytes each) -> REJECTED at ingress.
	short := []byte{1, 2, 3, 4, 5}
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[2].acc, Epoch: 1, Commitments: [][]byte{short, short}, EncShares: dummyEncShares(members),
	}); err == nil {
		t.Fatal("short-commitment dealing was ACCEPTED at ingress (must be rejected)")
	}

	var panicked interface{}
	func() {
		defer func() { panicked = recover() }()
		k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
	}()
	if panicked != nil {
		t.Fatalf("CONSENSUS HALT: finalize panicked: %v", panicked)
	}
	round, _ := k.GetDkgRound(ctx, 1)
	// Only member2 landed a well-formed dealing -> QUAL={2} size 1 < t=2 -> round FAILS.
	if round.Status != types.DkgStatusFailed {
		t.Fatalf("round should FAIL with 1 well-formed dealing < t=2, got %q", round.Status)
	}
}

// PROBE 3 (now a REGRESSION test) — a DkgDeal enc-share with a wrong-length AES-GCM
// nonce must be REJECTED at ingress, so a bad-nonce enc-share can never be stored and
// later flow into threshold.Decrypt on the complaint/decrypt paths. (The complaint
// handler remains no-panic-hardened for defense in depth.)
func TestProbe_DealBadNonce_ComplaintNoPanic(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	openEpoch1(t, k, ctx, members, thr)

	// Dealer members[0] deals real commitments but enc-shares with a 0-length nonce.
	c, _, _ := dkg.Deal(members[0].index, []uint64{1, 2, 3}, thr, rand.Reader)
	badShares := make([]*types.DkgEncShare, 0, 3)
	for _, recip := range members {
		badShares = append(badShares, &types.DkgEncShare{MemberIndex: recip.index, A: baseMul(randScalarP()), Nonce: []byte{}, Body: []byte{0x01}})
	}
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[0].acc, Epoch: 1, Commitments: c, EncShares: badShares,
	}); err == nil {
		t.Fatal("bad-nonce dealing was ACCEPTED at ingress (must be rejected)")
	}
	if _, ok := k.GetDealing(ctx, 1, members[0].index); ok {
		t.Fatal("a rejected bad-nonce dealing must not be stored")
	}

	// Defense in depth: a complaint against the (absent) dealer must not panic.
	var panicked interface{}
	func() {
		defer func() { panicked = recover() }()
		_, _ = ms.DkgComplaint(ctx.WithBlockHeight(3), &types.MsgDkgComplaint{
			Accuser: members[1].acc, Epoch: 1, Against: members[0].index,
			SharedPoint: baseMul(randScalarP()), DleqProof: make([]byte, 64),
		})
	}()
	if panicked != nil {
		t.Fatalf("DkgComplaint panicked: %v", panicked)
	}
	t.Log("bad-nonce enc-share rejected at ingress; complaint path did not panic")
}

var _ = fmt.Sprintf
