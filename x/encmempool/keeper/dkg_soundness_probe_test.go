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

// PROBE A (malformed enc-share A => uncomplainable, unforgeable-share griefing).
//
// A malicious dealer publishes VALID Feldman commitments (so it passes the structural
// QUAL gate) but seals every OTHER member an enc-share whose `A` field is NOT a valid
// compressed secp256k1 point. DkgDeal only checks len(A)!=0, so the dealing is
// accepted. The victim cannot DERIVE its share from that dealer (ComputeShare parses A)
// AND cannot COMPLAIN: VerifyJustifiedComplaint runs VerifyDecryptShare(encA,...) which
// parses encA first and returns false on a malformed point, so DkgComplaint rejects
// every complaint as "invalid complaint proof (cannot frame a dealer)". The dealer
// therefore stays in QUAL, poisoning every honest member's final share while the round
// finalizes Active (no auto-retry). One malicious member => permanent keyless liveness
// DoS for the epoch.
func TestProbe_MalformedEncShareA_Uncomplainable(t *testing.T) {
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
	// dealer index 0 (acc1) is malicious: valid commitments, but MALFORMED A to acc2+acc3.
	malformedA := []byte{0x02, 0x00} // non-empty, but not a 33-byte compressed point
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
				a = malformedA // corrupt A to every victim
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: a, Nonce: ct.Nonce, Body: ct.Body})
		}
		if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares}); err != nil {
			t.Fatalf("DkgDeal(%s) rejected: %v", dealerM.acc, err)
		}
	}
	t.Log("STEP 1: DkgDeal ACCEPTED a dealing whose enc-share A is not a valid point")

	// The victim acc2 tries to complain against acc1. Because A is malformed the victim
	// cannot even compute a real shared point; it submits its best-effort attempt. Try a
	// few candidate shared_points; ALL must be rejected as an invalid (framing) proof.
	victim := members[1]
	badDealing, _ := k.GetDealing(ctx, 1, members[0].index)
	var encToVictim *types.DkgStoredEncShare
	for i := range badDealing.EncShares {
		if badDealing.EncShares[i].MemberIndex == victim.index {
			encToVictim = &badDealing.EncShares[i]
		}
	}
	if encToVictim == nil {
		t.Fatal("precondition: dealer must have provided an enc-share record for the victim")
	}
	// Sanity: the stored A really is the malformed one, so the enc==nil disqualify path
	// is NOT taken (a record exists) and the crypto complaint path is forced.
	if len(encToVictim.A) == 33 {
		t.Fatal("precondition: A should be malformed (not 33 bytes)")
	}

	complaintCtx := ctx.WithBlockHeight(3)
	// Attempt 1: honest DLEQ over a DIFFERENT (valid) A the victim invents — cannot bind
	// to the malformed stored A.
	fakeCt, _ := threshold.Encrypt(victim.pub, make([]byte, 32))
	ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: victim.index, Xi: victim.priv}, fakeCt)
	if err != nil {
		t.Fatal(err)
	}
	_, err1 := ms.DkgComplaint(complaintCtx, &types.MsgDkgComplaint{
		Accuser: victim.acc, Epoch: 1, Against: members[0].index,
		SharedPoint: ds.D, DleqProof: dkg.MarshalDLEQProof(proof),
	})
	// Attempt 2: garbage shared point + garbage proof.
	_, err2 := ms.DkgComplaint(complaintCtx, &types.MsgDkgComplaint{
		Accuser: victim.acc, Epoch: 1, Against: members[0].index,
		SharedPoint: []byte{0x02, 0x01}, DleqProof: make([]byte, 64),
	})
	if err1 == nil || err2 == nil {
		t.Fatalf("a complaint was ACCEPTED (err1=%v err2=%v) — expected both rejected", err1, err2)
	}
	t.Logf("STEP 2: victim CANNOT complain — both attempts rejected (err1=%v, err2=%v)", err1, err2)

	// The dealer is NOT disqualified => finalize installs a key with acc1 IN QUAL.
	finCtx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok {
		t.Fatal("expected an active key (round should finalize with the malicious dealer in QUAL)")
	}
	inQual := false
	for _, q := range ak.Qual {
		if q == members[0].index {
			inQual = true
		}
	}
	if !inQual {
		t.Fatalf("expected malicious dealer %d to remain in QUAL=%v", members[0].index, ak.Qual)
	}
	t.Logf("STEP 3: round finalized Active, QUAL=%v INCLUDES the malicious dealer %d", ak.Qual, members[0].index)

	// Consequence: the victim can no longer derive a valid share from the QUAL set (the
	// malicious dealer's term is underivable), so it cannot produce a usable partial.
	_, derr := dkg.DecryptShareFrom(victim.priv, victim.index, &threshold.Ciphertext{A: encToVictim.A, Nonce: encToVictim.Nonce, Body: encToVictim.Body})
	if derr == nil {
		t.Fatal("expected the victim to be UNABLE to derive its share from the malformed enc-share")
	}
	t.Logf("STEP 4: victim cannot derive its QUAL share (DecryptShareFrom: %v) — its partials will fail RecoverVerified", derr)
	t.Log("REPRODUCED: one malicious member grief-poisons every honest member's share, uncomplainable, round stays Active")
}

// PROBE A' (crypto-level root cause): for a malformed enc-share A there is NO
// (shared_point, dleq_proof) an honest victim can submit that yields cheated=true.
// VerifyJustifiedComplaint short-circuits at parsePoint(encA) inside VerifyDecryptShare
// and returns proofValid=false, so the fault is structurally un-provable via a
// complaint — even though it is PUBLIC on chain and trivially checkable directly.
func TestProbe_MalformedEncShareA_CryptoRootCause(t *testing.T) {
	accuser := newMember("op1", "acc1")
	// A well-formed dealer commitment set (any valid points) — the accuser index is 2.
	_, shares, err := dkg.Deal(1, []uint64{1, 2, 3}, 2, rand.Reader)
	_ = shares
	if err != nil {
		t.Fatal(err)
	}
	commitments, _, err := dkg.Deal(1, []uint64{1, 2, 3}, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malformedA := []byte{0x02, 0x00}
	// Try 500 random candidate (sharedPoint, dleq) — none can flip proofValid to true,
	// because encA never parses. This shows the impossibility, not just one failure.
	for i := 0; i < 500; i++ {
		fakeCt, _ := threshold.Encrypt(accuser.pub, make([]byte, 32))
		ds, proof, e := dkg.ProveDecryptShare(threshold.Share{Index: 2, Xi: accuser.priv}, fakeCt)
		if e != nil {
			t.Fatal(e)
		}
		cheated, proofValid := dkg.VerifyJustifiedComplaint(
			2, accuser.pub, commitments,
			malformedA, fakeCt.Nonce, fakeCt.Body, ds.D, dkg.MarshalDLEQProof(proof),
		)
		if proofValid || cheated {
			t.Fatalf("iter %d: complaint unexpectedly admissible (cheated=%v proofValid=%v)", i, cheated, proofValid)
		}
	}
	t.Log("REPRODUCED: malformed enc-share A is structurally uncomplainable (proofValid always false)")
}

// PROBE B (end-to-end keyless liveness): drive the malformed-A attack all the way
// through decryption. A single malicious member seals a malformed A to BOTH other
// members. After finalize (malicious dealer in QUAL), the two honest members submit
// their best-effort partials (summed only over the dealers they COULD decrypt). Both
// partials fail the on-chain DLEQ against Y_m (recomputed over the full QUAL including
// the malicious dealer), so BeginBlock cannot decrypt: the epoch is permanently
// keyless for anti-MEV traffic, and there is no auto-retry because the round is Active.
func TestProbe_MalformedEncShareA_BreaksDecryption(t *testing.T) {
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
	// good[dealerIndex][memberIndex] = plaintext share the member could derive (nil if
	// the dealer sealed it a malformed A, i.e. underivable).
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
		if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares}); err != nil {
			t.Fatalf("DkgDeal(%s): %v", dealerM.acc, err)
		}
	}

	finCtx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok || len(ak.Qual) != 3 {
		t.Fatalf("expected Active round with QUAL=3, got ok=%v qual=%v", ok, ak.Qual)
	}

	// Encrypt to the (valid) DKG pubkey and submit.
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

	// The two HONEST members (acc2, acc3) build best-effort shares: sum over the QUAL
	// dealers they could actually decrypt (i.e. excluding the malicious dealer's
	// malformed term), then post DLEQ-proved partials.
	for _, m := range members[1:] {
		X := new(secp256k1Scalar)
		first := true
		for _, dealer := range ak.Qual {
			s := good[dealer][m.index]
			if s == nil {
				continue // underivable (malicious dealer's malformed A)
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
		if _, err := ms.SubmitDecryptionShare(submitCtx, &types.MsgSubmitDecryptionShare{
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
	if _, ok := decryptedPlaintext(bctx); ok {
		t.Fatal("UNEXPECTED: decryption succeeded — attack did not break liveness")
	}
	t.Log("REPRODUCED: with 1 malicious member, the honest quorum's partials are all rejected — epoch is permanently undecryptable (keyless liveness DoS), round stays Active (no retry)")
}

// tiny alias so the probe reads cleanly.
type secp256k1Scalar = secp256k1.ModNScalar

var _ = sdk.Context{}
