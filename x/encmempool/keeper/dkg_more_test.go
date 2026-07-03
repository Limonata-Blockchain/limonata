package keeper_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

func declaredFrom(ms []member) []types.DkgMember {
	out := make([]types.DkgMember, len(ms))
	for i, m := range ms {
		out[i] = types.DkgMember{OperatorAddr: m.op, AccountAddr: m.acc, EncPubKey: m.pub}
	}
	return out
}

// TestOnChainDKG_RerunOnMemberChange exercises the Shutter/Penumbra re-run trigger:
// the EndBlocker opens exactly one round, does NOT re-open while it is in-flight or
// while the member set is unchanged, and opens a NEW epoch when the member set
// changes.
func TestOnChainDKG_RerunOnMemberChange(t *testing.T) {
	A, B, C, D := newMember("op1", "a"), newMember("op2", "b"), newMember("op3", "c"), newMember("op4", "d")
	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DkgDealWindow: 2, DkgComplaintWindow: 2,
		DkgThreshold: 2, DkgMembers: declaredFrom([]member{A, B, C}),
	}
	_ = k.SetParams(ctx, p)

	// h1: opens epoch 1.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	if k.GetCurrentEpoch(ctx) != 1 {
		t.Fatalf("epoch should be 1, got %d", k.GetCurrentEpoch(ctx))
	}
	r1, _ := k.GetDkgRound(ctx, 1)
	if r1.Status != types.DkgStatusOpen || len(r1.Members) != 3 {
		t.Fatalf("round1 unexpected: %+v", r1)
	}

	// h2: round still in-flight (open) -> must NOT open a new epoch.
	k.EndBlockDKG(ctx.WithBlockHeight(2))
	if k.GetCurrentEpoch(ctx) != 1 {
		t.Fatal("must not open a new round while one is in-flight")
	}

	// simulate a successful finalize so the round is no longer open.
	r1.Status = types.DkgStatusActive
	_ = k.SetDkgRound(ctx, r1)

	// h3: same member set -> no re-run.
	k.EndBlockDKG(ctx.WithBlockHeight(3))
	if k.GetCurrentEpoch(ctx) != 1 {
		t.Fatal("must not re-run when the member set is unchanged")
	}

	// change the member set (drop C, add D) -> re-run to epoch 2.
	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(4))
	if k.GetCurrentEpoch(ctx) != 2 {
		t.Fatalf("member change must re-run to epoch 2, got %d", k.GetCurrentEpoch(ctx))
	}
	r2, _ := k.GetDkgRound(ctx, 2)
	if len(r2.Members) != 3 || bytes.Equal(r2.MembersHash, r1.MembersHash) {
		t.Fatalf("round2 must have the new member set + a different hash: %+v", r2)
	}
	// the new members must be {a,b,d}
	got := map[string]bool{}
	for _, m := range r2.Members {
		got[m.AccountAddr] = true
	}
	if !got["a"] || !got["b"] || !got["d"] || got["c"] {
		t.Fatalf("round2 member set wrong: %v", got)
	}
}

// TestOnChainDKG_ComplaintDisqualifiesCheater exercises the framing-resistant
// complaint: a dealer that seals a member a share inconsistent with its public
// commitments is disqualified, while a complaint against an honest dealer's valid
// share is rejected as frivolous (cannot frame).
func TestOnChainDKG_ComplaintDisqualifiesCheater(t *testing.T) {
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

	// dealer acc1 seals a BAD share (off-by-one, fails Feldman) to acc2; honest to others.
	// dealers acc2, acc3 are fully honest.
	badTo := members[1].index // acc2 is the victim
	dealCtx := ctx.WithBlockHeight(2)
	// encCT[dealerIndex][memberIndex]
	encCT := map[uint64]map[uint64]*threshold.Ciphertext{}
	for di, dealerM := range members {
		commitments, shares, err := dkg.Deal(dealerM.index, all, thr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if di == 0 {
			// corrupt the share to the victim so it no longer matches the commitments
			one := new(secp256k1.ModNScalar)
			one.SetInt(1)
			shares[badTo].Add(one)
		}
		encCT[dealerM.index] = map[uint64]*threshold.Ciphertext{}
		encShares := make([]*types.DkgEncShare, 0, len(all))
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatal(err)
			}
			encCT[dealerM.index][recip.index] = ct
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
		if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares}); err != nil {
			t.Fatalf("DkgDeal(%s): %v", dealerM.acc, err)
		}
	}

	// acc2 files a JUSTIFIED complaint against acc1 (the cheater).
	complaintCtx := ctx.WithBlockHeight(3)
	victim := members[1]
	badCT := encCT[members[0].index][victim.index]
	ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: victim.index, Xi: victim.priv}, badCT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.DkgComplaint(complaintCtx, &types.MsgDkgComplaint{
		Accuser: victim.acc, Epoch: 1, Against: members[0].index,
		SharedPoint: ds.D, DleqProof: dkg.MarshalDLEQProof(proof),
	}); err != nil {
		t.Fatalf("justified complaint rejected: %v", err)
	}

	// FRAMING CHECK: acc2 complains about honest acc3's valid share -> must be rejected.
	goodCT := encCT[members[2].index][victim.index]
	ds2, proof2, err := dkg.ProveDecryptShare(threshold.Share{Index: victim.index, Xi: victim.priv}, goodCT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.DkgComplaint(complaintCtx, &types.MsgDkgComplaint{
		Accuser: victim.acc, Epoch: 1, Against: members[2].index,
		SharedPoint: ds2.D, DleqProof: dkg.MarshalDLEQProof(proof2),
	}); err == nil {
		t.Fatal("frivolous complaint against an honest dealer was accepted (framing not prevented)")
	}

	// finalize at the complaint deadline: cheater (acc1) disqualified, QUAL = {acc2,acc3}.
	finCtx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok {
		t.Fatal("finalize did not install a key (should succeed with 2 honest dealers)")
	}
	if len(ak.Qual) != 2 {
		t.Fatalf("QUAL should exclude the cheater (expect 2), got %v", ak.Qual)
	}
	for _, q := range ak.Qual {
		if q == members[0].index {
			t.Fatal("cheating dealer was not disqualified")
		}
	}
}
