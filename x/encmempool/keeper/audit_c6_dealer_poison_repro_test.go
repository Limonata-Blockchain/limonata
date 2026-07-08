// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// poisonDealingEntry builds an HONEST dealing for member m, then corrupts (in a
// WELL-SHAPED way that passes validateDealingShape: valid compressed A, 12-byte nonce,
// non-empty body) every enc-share addressed to an eval point m does NOT own. The
// commitments are left untouched and valid. `openable` controls the corruption:
//   - false: flip a body byte so AES-GCM auth FAILS  -> DecryptShareFrom errors (variant 1)
//   - true : replace the body with a valid sealing of a WRONG scalar -> opens to a wrong
//     value, no error (variant 2)
func poisonDealingEntry(t *testing.T, round types.DkgRound, m member, openable bool) keeper.VEEntry {
	t.Helper()
	e := buildDealingEntry(t, round, m)
	myIdx := idxByOp(round, m.op)
	var mine types.RoundMember
	for _, rm := range round.Members {
		if rm.Index == myIdx {
			mine = rm
		}
	}
	for i := range e.VE.Dealing.EncShares {
		p := e.VE.Dealing.EncShares[i].MemberIndex // eval point this enc-share is addressed to
		if mine.OwnsEvalPoint(p) {
			continue // keep the attacker's OWN points honest
		}
		if !openable {
			// Variant 1: well-shaped but unopenable (AES-GCM tag fails).
			e.VE.Dealing.EncShares[i].Body[0] ^= 0xff
			continue
		}
		// Variant 2: openable but WRONG — seal a fixed wrong 32-byte scalar to the point
		// owner's real enc key, so DecryptShareFrom OPENS it (no error) to a value that does
		// not match the dealer's commitments.
		owner := types.EvalPointOwner(round.Members, p)
		var ownerKey []byte
		for _, rm := range round.Members {
			if rm.Index == owner {
				ownerKey = rm.EncPubKey
			}
		}
		wrongScalar := make([]byte, 32)
		wrongScalar[31] = 7 // small canonical non-zero scalar
		ct, err := threshold.Encrypt(ownerKey, wrongScalar)
		if err != nil {
			t.Fatal(err)
		}
		e.VE.Dealing.EncShares[i].A = ct.A
		e.VE.Dealing.EncShares[i].Nonce = ct.Nonce
		e.VE.Dealing.EncShares[i].Body = ct.Body
	}
	return e
}

// deriveOK reports whether honest member m can derive its shares for the finalized epoch
// (the exact production path a live node runs in ExtendVote -> deriveEpochShares).
func deriveOK(k keeper.Keeper, ctx sdk.Context, round types.DkgRound, ak types.ActiveThresholdKey, m member) ([]threshold.Share, error) {
	myIdx := idxByOp(round, m.op)
	var myPoints []uint64
	for _, rm := range round.Members {
		if rm.Index == myIdx {
			myPoints = rm.OwnedEvalPoints()
		}
	}
	dealings := map[uint64]types.Dealing{}
	k.IterateDealings(ctx, round.Epoch, func(d types.Dealing) { dealings[d.DealerIndex] = d })
	return dkgnode.DeriveShares(myPoints, m.priv, ak.Qual, dealings)
}

// tryDecrypt encrypts a message to ak.Pub and attempts full threshold reconstruction using
// ONLY the shares the given ONLINE members can produce (the exact RecoverVerified path the
// on-chain decrypt uses). Returns nil error iff the plaintext comes back.
func tryDecrypt(t *testing.T, k keeper.Keeper, ctx sdk.Context, round types.DkgRound, ak types.ActiveThresholdKey, online []member) error {
	msg := []byte("anti-MEV-secret")
	ct, err := threshold.Encrypt(ak.Pub, msg)
	if err != nil {
		return err
	}
	commitments, err := dkg.ParseCommitmentPoints(ak.PublicCommitments)
	if err != nil {
		return err
	}
	var partials []dkg.VerifiedShare
	for _, m := range online {
		shares, derr := deriveOK(k, ctx, round, ak, m)
		if derr != nil {
			continue // this member cannot derive -> contributes nothing (variant 1)
		}
		for _, sh := range shares {
			ds, proof, perr := dkg.ProveDecryptShare(sh, ct)
			if perr != nil {
				continue
			}
			partials = append(partials, dkg.VerifiedShare{Share: ds, Proof: proof})
		}
	}
	need := int(round.Threshold)
	shared, rerr := dkg.RecoverVerified(commitments, ct.A, need, partials)
	if rerr != nil {
		return rerr
	}
	plain, derr := threshold.Decrypt(shared, ct)
	if derr != nil {
		return derr
	}
	if string(plain) != string(msg) {
		t.Fatalf("decrypted wrong plaintext")
	}
	return nil
}

// setupPoisonRound stands up an ACTIVE epoch-1 transparent committee of 3 equal-stake
// members over budget 24 (=8n), lets all 3 deal (op3 optionally POISONED), and finalizes.
func setupPoisonRound(t *testing.T, poison bool, openable bool) (keeper.Keeper, sdk.Context, types.DkgRound, types.ActiveThresholdKey, []member) {
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	vals := make([]stakingtypes.Validator, len(mem))
	for i, m := range mem {
		vals[i] = bondedVal(m.op, 100) // equal stake -> each owns 8 of 24 points
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(2, 3)
	p.DkgShareBudget = 24
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, m := range mem {
		if !k.RecordEncPubKey(ctx, m.op, m.pub, encPoP(m)) {
			t.Fatalf("announce failed for %s", m.op)
		}
	}
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok || round.Status != types.DkgStatusOpen {
		t.Fatalf("epoch 1 not opened: %+v", round)
	}
	var entries []keeper.VEEntry
	entries = append(entries, buildDealingEntry(t, round, mem[0]))
	entries = append(entries, buildDealingEntry(t, round, mem[1]))
	if poison {
		entries = append(entries, poisonDealingEntry(t, round, mem[2], openable))
	} else {
		entries = append(entries, buildDealingEntry(t, round, mem[2]))
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), entries)
	fctx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(fctx)
	round, _ = k.GetDkgRound(ctx, 1)
	ak, ok := k.GetActiveKey(ctx, 1)
	if !ok {
		t.Fatalf("round did not finalize: %+v", round)
	}
	return k, ctx, round, ak, mem
}

// TestRepro_ByzantineDealerInQual_BreaksLiveness_NoComplaintRecourse is the reproduction.
func TestRepro_ByzantineDealerInQual_BreaksLiveness_NoComplaintRecourse(t *testing.T) {
	// ---- CONTROL: all-honest committee decrypts fine with only op1+op2 online (16 >= t points).
	{
		k, ctx, round, ak, mem := setupPoisonRound(t, false, false)
		t.Logf("[control] t(threshold)=%d  QUAL=%v  budget-points=%d", round.Threshold, ak.Qual, types.TotalEvalPoints(round.Members))
		if err := tryDecrypt(t, k, ctx, round, ak, []member{mem[0], mem[1]}); err != nil {
			t.Fatalf("[control] honest online supermajority MUST decrypt, got: %v", err)
		}
		t.Logf("[control] op1+op2 (honest, online) decrypt OK -> liveness holds when all dealers honest")
	}

	// ---- ATTACK variant 1 (unopenable): op3 deals valid commitments but well-shaped-but-
	// unopenable enc-shares to op1/op2 points. It STILL enters QUAL. op1+op2 (honest, online,
	// 16 >= t points) can no longer decrypt anything.
	{
		k, ctx, round, ak, mem := setupPoisonRound(t, true, false)
		op3idx := idxByOp(round, "op3")
		inQual := false
		for _, q := range ak.Qual {
			if q == op3idx {
				inQual = true
			}
		}
		t.Logf("[attack-v1] QUAL=%v  op3(index %d) inQUAL=%v", ak.Qual, op3idx, inQual)
		if !inQual {
			t.Fatalf("[attack-v1] expected the poisoning dealer to SURVIVE in QUAL")
		}
		// The honest victims cannot even derive their shares.
		if _, err := deriveOK(k, ctx, round, ak, mem[0]); err == nil {
			t.Fatalf("[attack-v1] expected op1 share derivation to FAIL (poisoned by op3)")
		}
		if _, err := deriveOK(k, ctx, round, ak, mem[1]); err == nil {
			t.Fatalf("[attack-v1] expected op2 share derivation to FAIL (poisoned by op3)")
		}
		// Full committee online (op1+op2+op3) still cannot decrypt.
		err := tryDecrypt(t, k, ctx, round, ak, []member{mem[0], mem[1], mem[2]})
		if err == nil {
			t.Fatalf("[attack-v1] LIVENESS: expected the ciphertext to be UNDECRYPTABLE, but it decrypted")
		}
		t.Logf("[attack-v1] a single QUAL dealer made the epoch UNDECRYPTABLE: %v", err)
	}

	// ---- ATTACK variant 2 (openable-but-wrong): DeriveShares SUCCEEDS but the produced
	// partials fail RecoverVerified against the on-chain Y_p (the DLEQ drops the HONEST
	// victim's partial, not the attacker's). Ciphertext still undecryptable.
	{
		k, ctx, round, ak, mem := setupPoisonRound(t, true, true)
		s1, e1 := deriveOK(k, ctx, round, ak, mem[0])
		t.Logf("[attack-v2] op1 derive: err=%v (nil means it silently derived a WRONG share)", e1)
		_ = s1
		err := tryDecrypt(t, k, ctx, round, ak, []member{mem[0], mem[1], mem[2]})
		if err == nil {
			t.Fatalf("[attack-v2] LIVENESS: expected UNDECRYPTABLE, but it decrypted")
		}
		t.Logf("[attack-v2] openable-but-wrong poisoning also breaks decryption: %v", err)
	}

	// ---- NO RECOURSE: the transparent path has no complaint field on the VE and
	// TransparentMembers never sets AccountAddr, so the legacy MsgDkgComplaint is unusable.
	{
		_, _, round, _, _ := setupPoisonRound(t, true, false)
		for _, m := range round.Members {
			if m.AccountAddr != "" {
				t.Fatalf("expected transparent members to carry NO AccountAddr (complaint msg unusable), got %q", m.AccountAddr)
			}
		}
		t.Logf("[no-recourse] transparent RoundMembers carry no AccountAddr -> MsgDkgComplaint memberIndexByAccount==0 -> complaint always 'not a member'")
	}
}

// round-9 #2: the DERIVE-TIME belt. A returning offline victim (op1, whose points op3 poisoned while
// op1 was offline for the complaint window) must, at derive time, DETECT and ATTRIBUTE the poison to
// op3 - the residual the in-window complaint channel structurally cannot catch. An all-honest round
// yields no reports.
func TestDetectPoisonedDealers_AttributesOfflineVictimPoison(t *testing.T) {
	pts := func(round types.DkgRound, op string) []uint64 {
		vi := idxByOp(round, op)
		for _, rm := range round.Members {
			if rm.Index == vi {
				return rm.OwnedEvalPoints()
			}
		}
		return nil
	}
	deals := func(k keeper.Keeper, ctx sdk.Context, epoch uint64) map[uint64]types.Dealing {
		m := map[uint64]types.Dealing{}
		k.IterateDealings(ctx, epoch, func(d types.Dealing) { m[d.DealerIndex] = d })
		return m
	}

	// POISONED (variant 2: opens but fails Feldman) -> op1 attributes it to op3.
	k, ctx, round, ak, mem := setupPoisonRound(t, true, true)
	reports := dkgnode.DetectPoisonedDealers(pts(round, mem[0].op), mem[0].priv, ak.Qual, deals(k, ctx, round.Epoch))
	if len(reports) == 0 {
		t.Fatal("returning victim op1 must detect the poison op3 planted on its points")
	}
	op3 := idxByOp(round, "op3")
	for _, r := range reports {
		if r.Dealer != op3 {
			t.Fatalf("poison must be attributed to byzantine dealer op3 (idx %d), got dealer %d", op3, r.Dealer)
		}
	}

	// CONTROL: an all-honest finalized round -> no poison reports.
	k2, ctx2, round2, ak2, mem2 := setupPoisonRound(t, false, false)
	if r := dkgnode.DetectPoisonedDealers(pts(round2, mem2[0].op), mem2[0].priv, ak2.Qual, deals(k2, ctx2, round2.Epoch)); len(r) != 0 {
		t.Fatalf("an all-honest round must report no poison, got %d", len(r))
	}
}
