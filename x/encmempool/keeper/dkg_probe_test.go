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
	t.Logf("installed active key? %v; Pub=%x", ok, func() []byte { if ok { return ak.Pub }; return nil }())
	round, _ := k.GetDkgRound(ctx, 1)
	t.Logf("round status after finalize: %q qual would be both", round.Status)
}

// PROBE 2 — malformed attacker commitments must not panic EndBlock finalize.
// A member submits t commitments that pass the count check but are (a) garbage
// 33-byte non-points and (b) wrong length. finalize must skip the dealer, never panic.
func TestProbe_MalformedCommitments_NoPanic(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	openEpoch1(t, k, ctx, members, thr)

	// member1: two 33-byte garbage "points" (not on curve).
	garbage := make([]byte, 33)
	garbage[0] = 0x02
	for i := 1; i < 33; i++ {
		garbage[i] = 0xFF
	}
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[0].acc, Epoch: 1, Commitments: [][]byte{garbage, garbage}, EncShares: dummyEncShares(members),
	}); err != nil {
		t.Fatalf("garbage deal rejected at ingress (would need on-chain guard): %v", err)
	}
	// member2: two honest commitments so there is a mix.
	c2, _, _ := dkg.Deal(members[1].index, []uint64{1, 2, 3}, thr, rand.Reader)
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[1].acc, Epoch: 1, Commitments: c2, EncShares: dummyEncShares(members),
	}); err != nil {
		t.Fatalf("honest deal: %v", err)
	}
	// member3: wrong-length commitment bytes (5 bytes each) — still passes count==t.
	short := []byte{1, 2, 3, 4, 5}
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
		Dealer: members[2].acc, Epoch: 1, Commitments: [][]byte{short, short}, EncShares: dummyEncShares(members),
	}); err != nil {
		t.Fatalf("short deal: %v", err)
	}

	var panicked interface{}
	func() {
		defer func() { panicked = recover() }()
		k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
	}()
	if panicked != nil {
		t.Fatalf("CONSENSUS HALT: finalize panicked on malformed commitments: %v", panicked)
	}
	round, _ := k.GetDkgRound(ctx, 1)
	// Only member2 is well-formed -> QUAL={2} has size 1 < t=2 -> round must FAIL (not panic).
	t.Logf("round status: %q (expect failed: 1 well-formed < t=2)", round.Status)
}

// PROBE 3 — nonce length on DkgDeal enc-shares is NOT validated by the handler.
// A stored bad-nonce enc-share flows into threshold.Decrypt inside DkgComplaint.
// Confirm the complaint handler does not panic (msg handlers are recovered by
// baseapp, but a panic that depends on non-canonical bytes is still worth pinning).
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
	}); err != nil {
		t.Fatalf("bad-nonce deal rejected at ingress: %v", err)
	}

	// members[1] files a complaint against members[0] with a (garbage) DLEQ proof.
	var panicked interface{}
	func() {
		defer func() { panicked = recover() }()
		_, _ = ms.DkgComplaint(ctx.WithBlockHeight(3), &types.MsgDkgComplaint{
			Accuser: members[1].acc, Epoch: 1, Against: members[0].index,
			SharedPoint: baseMul(randScalarP()), DleqProof: make([]byte, 64),
		})
	}()
	if panicked != nil {
		t.Fatalf("DkgComplaint panicked on bad-nonce stored enc-share: %v", panicked)
	}
	t.Log("DkgComplaint did not panic on bad-nonce enc-share")
}

var _ = fmt.Sprintf
