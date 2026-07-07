// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// dealAllMembers has every member post a well-formed on-chain dealing for an epoch at
// the given height, so the round can finalize with a full QUAL. It mirrors the deal
// path a live daemon runs (dkg.Deal + EncryptShareTo per member).
func dealAllMembers(t *testing.T, k keeper.Keeper, ms types.MsgServer, ctx sdk.Context, members []member, epoch uint64, thr int) {
	t.Helper()
	round, ok := k.GetDkgRound(ctx, epoch)
	if !ok {
		t.Fatalf("epoch %d not open", epoch)
	}
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	allIdx := make([]uint64, 0, len(round.Members))
	for _, rm := range round.Members {
		allIdx = append(allIdx, rm.Index)
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
	for _, dealer := range members {
		if dealer.index == 0 {
			continue // not a member of this round
		}
		commitments, shares, err := dkg.Deal(dealer.index, allIdx, thr, rand.Reader)
		if err != nil {
			t.Fatalf("deal: %v", err)
		}
		encShares := make([]*types.DkgEncShare, 0, len(members))
		for _, recip := range members {
			if recip.index == 0 {
				continue
			}
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatalf("encrypt share: %v", err)
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
		if _, err := ms.DkgDeal(ctx, &types.MsgDkgDeal{Dealer: dealer.acc, Epoch: epoch, Commitments: commitments, EncShares: encShares}); err != nil {
			t.Fatalf("DkgDeal(%s): %v", dealer.acc, err)
		}
	}
}

// TestOnChainDKG_AutoRetryOnFailedRound is the load-bearing self-heal test: a round
// that gathers ZERO dealings must fail at its complaint deadline and the EndBlocker
// must AUTOMATICALLY open a fresh round (after the backoff) — never leaving the chain
// permanently keyless — and that retried round, once members deal, must finalize.
func TestOnChainDKG_AutoRetryOnFailedRound(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 2, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMembers: declaredFrom(members),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// h1: opens epoch 1 (attempt 1). DealDeadline=3, ComplaintDeadline=5.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	r1, ok := k.GetDkgRound(ctx, 1)
	if !ok || r1.Status != types.DkgStatusOpen || r1.Attempt != 1 {
		t.Fatalf("epoch 1 should open at attempt 1: %+v", r1)
	}
	if r1.ComplaintDeadline != 5 {
		t.Fatalf("unexpected complaint deadline %d (want 5)", r1.ComplaintDeadline)
	}

	// NO member deals. h5 (== complaint deadline): finalize must FAIL the round.
	k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
	r1, _ = k.GetDkgRound(ctx, 1)
	if r1.Status != types.DkgStatusFailed {
		t.Fatalf("epoch 1 with no deals must be Failed, got %q", r1.Status)
	}
	if k.GetCurrentEpoch(ctx) != 1 {
		t.Fatal("must not reopen on the same block the round failed")
	}
	if _, ok := k.GetActiveKey(ctx, 1); ok {
		t.Fatal("a failed round must not install an active key")
	}

	// h6: still inside the retry backoff (deadline 5 + backoff 2 = 7) -> NO reopen.
	k.EndBlockDKG(ctx.WithBlockHeight(6).WithEventManager(sdk.NewEventManager()))
	if k.GetCurrentEpoch(ctx) != 1 {
		t.Fatalf("must not reopen before backoff elapses; epoch=%d", k.GetCurrentEpoch(ctx))
	}

	// h7: backoff elapsed -> AUTO-REOPEN epoch 2 at attempt 2.
	k.EndBlockDKG(ctx.WithBlockHeight(7).WithEventManager(sdk.NewEventManager()))
	if k.GetCurrentEpoch(ctx) != 2 {
		t.Fatalf("auto-retry must reopen epoch 2, got current epoch %d", k.GetCurrentEpoch(ctx))
	}
	r2, ok := k.GetDkgRound(ctx, 2)
	if !ok || r2.Status != types.DkgStatusOpen {
		t.Fatalf("epoch 2 should be open: %+v", r2)
	}
	if r2.Attempt != 2 {
		t.Fatalf("retried round must carry attempt 2, got %d", r2.Attempt)
	}
	if bytes.Equal(r2.MembersHash, nil) || len(r2.Members) != 3 {
		t.Fatalf("epoch 2 must retain the full member set: %+v", r2)
	}

	// The retried round now gets full dealings and must CONVERGE to an active key.
	// Epoch 2 opened at h7: DealDeadline=9, ComplaintDeadline=11.
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(8), members, 2, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager()))
	ak, ok := k.GetActiveKey(ctx, 2)
	if !ok {
		t.Fatal("auto-retried round did not converge to an active key")
	}
	if len(ak.Qual) != 3 {
		t.Fatalf("expected full QUAL after retry, got %v", ak.Qual)
	}
	if k.GetActiveEpoch(ctx) != 2 {
		t.Fatalf("active epoch should be 2, got %d", k.GetActiveEpoch(ctx))
	}
	r2, _ = k.GetDkgRound(ctx, 2)
	if r2.Status != types.DkgStatusActive {
		t.Fatalf("epoch 2 should be Active, got %q", r2.Status)
	}

	// Steady state: with an active key + unchanged members, no further reopen.
	k.EndBlockDKG(ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager()))
	if k.GetCurrentEpoch(ctx) != 2 {
		t.Fatalf("must not reopen once converged; epoch=%d", k.GetCurrentEpoch(ctx))
	}
}

// TestOnChainDKG_RetryPurgesStaleDeals asserts the failed round's dealings are GC'd
// on retry (so an extended outage cannot grow state without bound) and that a round
// which had < t dealings (a partial timeout) also fails and self-heals.
func TestOnChainDKG_RetryPurgesStaleDeals(t *testing.T) {
	const thr = 3 // need all 3 to qualify; we will supply only 1 -> fail
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 2,
		DkgThreshold: thr, DkgMembers: declaredFrom(members),
	}
	_ = k.SetParams(ctx, p)

	k.EndBlockDKG(ctx.WithBlockHeight(1)) // epoch 1: DealDeadline=3, ComplaintDeadline=5
	round, _ := k.GetDkgRound(ctx, 1)
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
	allIdx := []uint64{1, 2, 3}

	// Only ONE member deals -> |QUAL| = 1 < t = 3 -> the round must fail.
	dealer := members[0]
	commitments, shares, err := dkg.Deal(dealer.index, allIdx, thr, rand.Reader)
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
	if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{Dealer: dealer.acc, Epoch: 1, Commitments: commitments, EncShares: encShares}); err != nil {
		t.Fatal(err)
	}
	// sanity: the dealing is stored for epoch 1.
	if _, ok := k.GetDealing(ctx, 1, dealer.index); !ok {
		t.Fatal("expected the single dealing to be stored")
	}
	// DKG-SM-5-GC: seed a rejected-complaint negative-cache entry for epoch 1; it must be reclaimed by
	// the same purge that GCs the dealings (else 0x1C accumulates permanently across every rekey).
	_ = k.SetComplaintRejected(ctx, 1, 2, dealer.index, 7)
	if !k.HasComplaintRejected(ctx, 1, 2, dealer.index, 7) {
		t.Fatal("precondition: rejected-complaint entry should be set")
	}

	// h5: finalize fails (1 < 3). h6 (backoff 1 elapsed): auto-reopen epoch 2.
	k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
	if r, _ := k.GetDkgRound(ctx, 1); r.Status != types.DkgStatusFailed {
		t.Fatalf("epoch 1 must fail with 1<3 dealings, got %q", r.Status)
	}
	k.EndBlockDKG(ctx.WithBlockHeight(6).WithEventManager(sdk.NewEventManager()))
	if k.GetCurrentEpoch(ctx) != 2 {
		t.Fatalf("expected auto-reopen to epoch 2, got %d", k.GetCurrentEpoch(ctx))
	}
	// The stale dealing from the failed epoch 1 must have been purged.
	if _, ok := k.GetDealing(ctx, 1, dealer.index); ok {
		t.Fatal("failed round's dealing was not GC'd on retry")
	}
	// HIGH-2: the failed round's DkgRound RECORD must also be GC'd on retry.
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("failed round's DkgRound record was not GC'd on retry (HIGH-2)")
	}
	// DKG-SM-5-GC: the rejected-complaint negative cache for the failed epoch must be reclaimed too.
	if k.HasComplaintRejected(ctx, 1, 2, dealer.index, 7) {
		t.Fatal("failed round's rejected-complaint negative cache was not GC'd on retry (DKG-SM-5-GC)")
	}
}

// TestOnChainDKG_SustainedSubQuorumBoundedAndRecovers is the HIGH-2 regression test.
// Under a SUSTAINED sub-quorum (nobody deals) the EndBlocker keeps failing+retrying
// forever; the fix must keep retained DkgRound state BOUNDED (GC the failed round record
// on retry) instead of leaking one record per retry, and must STILL converge the instant
// >= t members return. Pre-fix, purgeRoundData kept every failed round's record, so
// CountDkgRounds grew without bound with the retry count — this test would fail.
func TestOnChainDKG_SustainedSubQuorumBoundedAndRecovers(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 3,
		DkgThreshold: thr, DkgMembers: declaredFrom(members),
	}
	_ = k.SetParams(ctx, p)

	// Drive many blocks with NOBODY dealing: fail -> retry -> fail -> retry ... Assert
	// the retained DkgRound record count never grows with the number of retries.
	maxRounds := 0
	lastEpoch := uint64(0)
	for h := int64(1); h <= 80; h++ {
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
		if c := k.CountDkgRounds(ctx); c > maxRounds {
			maxRounds = c
		}
		if e := k.GetCurrentEpoch(ctx); e > lastEpoch {
			lastEpoch = e
		}
	}
	if lastEpoch < 4 {
		t.Fatalf("expected several auto-retries (epoch should advance), only reached epoch %d", lastEpoch)
	}
	if maxRounds > 2 {
		t.Fatalf("HIGH-2: retained DkgRound records grew unbounded under sustained sub-quorum (peak=%d across %d retries)", maxRounds, lastEpoch)
	}
	t.Logf("bounded: %d retries, peak retained DkgRound records = %d", lastEpoch, maxRounds)

	// Quorum returns: the next round the EndBlocker opens must converge to an active key
	// with NO manual intervention.
	var round types.DkgRound
	h := int64(81)
	for ; h <= 300; h++ {
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
		if r, ok := k.GetDkgRound(ctx, k.GetCurrentEpoch(ctx)); ok && r.Status == types.DkgStatusOpen && uint64(h) < r.DealDeadline {
			round = r
			break
		}
	}
	if round.Status != types.DkgStatusOpen {
		t.Fatal("no open round appeared to converge on")
	}
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(h+1), members, round.Epoch, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager()))
	ak, ok := k.GetActiveKey(ctx, round.Epoch)
	if !ok {
		t.Fatalf("quorum returned but epoch %d did not converge to an active key", round.Epoch)
	}
	if len(ak.Qual) != 3 {
		t.Fatalf("expected full QUAL after recovery, got %v", ak.Qual)
	}
	if c := k.CountDkgRounds(ctx); c > 2 {
		t.Fatalf("retained round records not bounded after recovery: %d", c)
	}
	t.Logf("recovered: epoch %d converged with full QUAL after a sustained sub-quorum outage", round.Epoch)
}
