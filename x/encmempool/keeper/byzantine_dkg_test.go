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
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-6 (exhaustive re-audit) — item (d): byzantine dealers / shares on a
// STAKE-WEIGHTED (multi-eval-point) transparent committee, driven through the
// real EndBlockDKG finalize + the vote-extension consume path.
//
// The existing byzantine tests (malformed commitments / bad nonce / non-member /
// stale / first-wins / complaint-disqualifies) run on unweighted or n=1 shapes.
// These add the shapes only a MULTI-POINT weighted committee exposes:
//   - an ABSENT dealer is disqualified yet the round STILL finalizes when the
//     present dealers own >= t points (robustness), never a halt;
//   - a member submitting a decryption share at an eval point it does NOT own
//     (a CO-MEMBER's point) is rejected, while its OWN point is accepted (HIGH-3
//     per-point authorization on a committee where members own point RANGES);
//   - an equivocating dealer that puts two different dealings on ONE consumed
//     commit is deduped first-wins by canonicalization (fork-safety).
// ============================================================================

// weightedRoundMembers is a small committee whose stakes make members own DISTINCT
// contiguous ranges of eval points (so "a point another member owns" is well-defined).
type weightedRoundMembers struct {
	k       keeper.Keeper
	ctx     sdk.Context
	round   types.DkgRound
	members []member
}

// setupWeightedActiveRound stands up an ACTIVE epoch-1 transparent round over `mem`
// (stakes from `stake`), letting only the members in `deal` post dealings via vote
// extensions, then finalizes. It returns the finalized round view.
func setupWeightedActiveRound(t *testing.T, mem []member, stake []int64, deal map[string]bool) weightedRoundMembers {
	t.Helper()
	vals := make([]stakingtypes.Validator, len(mem))
	for i, m := range mem {
		vals[i] = bondedVal(m.op, stake[i])
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	// Committee cap 4, budget 32 (= 8*4, the minimum coupling) — small + fast, and every
	// member owns a multi-point range at these stakes.
	p := transparentParams(2, 4)
	p.DkgShareBudget = 32
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
	// Deal from the chosen subset via vote extensions (inside the deal window).
	var entries []keeper.VEEntry
	for _, m := range mem {
		if deal[m.op] {
			entries = append(entries, buildDealingEntry(t, round, m))
		}
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), entries)
	// Finalize at the complaint deadline.
	fctx := ctx.WithBlockHeight(int64(round.ComplaintDeadline)).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(fctx)
	round, _ = k.GetDkgRound(ctx, 1)
	return weightedRoundMembers{k: k, ctx: ctx, round: round, members: mem}
}

// TestCycle6_Byzantine_AbsentDealerFinalizesAndWrongPointShareRejected: with 4 equal-stake
// members (each owning a 1/4 share of the 32-point budget = 8 points), ONE dealer is absent.
// The round must still finalize (the 3 present dealers own 24 >= t points), the absent dealer
// must be excluded from QUAL, and a decryption share posted at a point the submitting member
// does NOT own must be rejected while its own point is accepted.
func TestCycle6_Byzantine_AbsentDealerFinalizesAndWrongPointShareRejected(t *testing.T) {
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", ""), newMember("op4", "")}
	stake := []int64{100, 100, 100, 100}
	deal := map[string]bool{"op1": true, "op2": true, "op3": true} // op4 ABSENT
	w := setupWeightedActiveRound(t, mem, stake, deal)

	ak, ok := w.k.GetActiveKey(w.ctx, 1)
	if !ok {
		t.Fatal("round must finalize despite an absent dealer (present dealers own >= t points)")
	}
	if w.round.Status != types.DkgStatusActive {
		t.Fatalf("round status = %s, want Active", w.round.Status)
	}
	absentIdx := idxByOp(w.round, "op4")
	for _, q := range ak.Qual {
		if q == absentIdx {
			t.Fatalf("absent dealer (idx %d) must NOT be in QUAL %v", absentIdx, ak.Qual)
		}
	}
	if len(ak.Qual) != 3 {
		t.Fatalf("QUAL = %v, want the 3 present dealers", ak.Qual)
	}

	// A REAL ciphertext to the epoch key so an AUTHORIZED share can also DLEQ-verify at ingest.
	ct, encErr := threshold.Encrypt(ak.Pub, []byte("byz-share"))
	if encErr != nil {
		t.Fatal(encErr)
	}
	e := w.k.SubmitEncTx(w.ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1)

	// Pick a point op2 owns and a point op1 owns (both non-empty ranges).
	op1Pts := ownedPoints(w.round, "op1")
	op2Pts := ownedPoints(w.round, "op2")
	if len(op1Pts) == 0 || len(op2Pts) == 0 {
		t.Fatalf("expected both members to own points: op1=%v op2=%v", op1Pts, op2Pts)
	}

	// op2 claims a point op1 OWNS -> rejected (per-point authorization, BEFORE any DLEQ check).
	wrong := keeper.VEEntry{Operator: "op2", VE: types.VoteExtension{Shares: []types.VoteExtShare{
		{Epoch: 1, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: op1Pts[0], D: []byte("d")},
	}}}
	w.k.ConsumeVoteExtensions(w.ctx.WithBlockHeight(3), []keeper.VEEntry{wrong})
	if got := w.k.CollectShares(w.ctx, e.DecryptHeight, e.Seq); len(got) != 0 {
		t.Fatalf("share at a co-member's point must be rejected, have %d", len(got))
	}

	// op2 claims a point it OWNS, with a VALID DLEQ-proved share -> accepted.
	right := keeper.VEEntry{Operator: "op2", VE: types.VoteExtension{Shares: []types.VoteExtShare{
		provedShareAt(t, w, ak, ct, "op2", op2Pts[0], e),
	}}}
	w.k.ConsumeVoteExtensions(w.ctx.WithBlockHeight(3), []keeper.VEEntry{right})
	got := w.k.CollectShares(w.ctx, e.DecryptHeight, e.Seq)
	if len(got) != 1 || got[0].Index != op2Pts[0] || got[0].Keyper != "op2" {
		t.Fatalf("share at an owned point must be accepted: %+v", got)
	}
}

// provedShareAt returns member `op`'s REAL, DLEQ-proved decryption share for ciphertext ct at the
// eval point `index`, as a vote-extension payload the ingest gate will accept.
func provedShareAt(t *testing.T, w weightedRoundMembers, ak types.ActiveThresholdKey, ct *threshold.Ciphertext, op string, index uint64, e types.EncTx) types.VoteExtShare {
	t.Helper()
	var m member
	for _, mm := range w.members {
		if mm.op == op {
			m = mm
		}
	}
	shares, err := deriveOK(w.k, w.ctx, w.round, ak, m)
	if err != nil {
		t.Fatalf("derive %s: %v", op, err)
	}
	for _, sh := range shares {
		if sh.Index == index {
			ds, proof, perr := dkg.ProveDecryptShare(sh, ct)
			if perr != nil {
				t.Fatal(perr)
			}
			return types.VoteExtShare{
				Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
				Index: ds.Index, D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
			}
		}
	}
	t.Fatalf("member %s owns no share at point %d", op, index)
	return types.VoteExtShare{}
}

// TestCycle6_Byzantine_EquivocatingDealerSameCommitFirstWins: a dealer that attaches TWO
// different dealings to a SINGLE consumed commit (an equivocation) is collapsed to its FIRST
// entry by canonicalization (operator-dedup, first-wins), so every node stores the same one —
// the fork-safety contract of ConsumeVoteExtensions.
func TestCycle6_Byzantine_EquivocatingDealerSameCommitFirstWins(t *testing.T) {
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	k, ctx, round, _ := setupTransparentRound(t, mem)

	first := buildDealingEntry(t, round, mem[0])
	second := buildDealingEntry(t, round, mem[0]) // same operator, DIFFERENT random dealing
	// Both in ONE consumed commit, first before second.
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), []keeper.VEEntry{first, second})

	stored, ok := k.GetDealing(ctx, 1, idxByOp(round, mem[0].op))
	if !ok {
		t.Fatal("the dealer's (first) dealing must be stored")
	}
	// Must equal the FIRST dealing's commitments, not the second's.
	if len(stored.Commitments) != len(first.VE.Dealing.Commitments) {
		t.Fatal("stored dealing shape mismatch")
	}
	same := true
	for i := range stored.Commitments {
		if string(stored.Commitments[i]) != string(first.VE.Dealing.Commitments[i]) {
			same = false
			break
		}
	}
	if !same {
		t.Fatal("equivocation must resolve to the FIRST dealing (canonical first-wins)")
	}
	// Exactly one dealing stored for that dealer.
	n := 0
	k.IterateDealings(ctx, 1, func(d types.Dealing) {
		if d.DealerIndex == idxByOp(round, mem[0].op) {
			n++
		}
	})
	if n != 1 {
		t.Fatalf("equivocating dealer must have exactly one stored dealing, got %d", n)
	}
}

// ownedPoints returns the eval points a member owns in the round, by operator.
func ownedPoints(round types.DkgRound, op string) []uint64 {
	for _, m := range round.Members {
		if m.OperatorAddr == op {
			return m.OwnedEvalPoints()
		}
	}
	return nil
}
