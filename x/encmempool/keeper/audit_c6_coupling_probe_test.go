// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"fmt"
	"testing"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-6 STAKE-CAPTURE LENS — the S >= 8n COUPLING is what keeps the safety
// margin positive. If a weighted round could ever OPEN with S < 8n, the
// stakeThreshold proof (points <= floor(S/3)+n-1 < t needs S >= 6n-1) erodes and
// a <=1/3 coalition could approach t. These probes attack the coupling from both
// sides:
//   (C1) GOV-PASSABLE boundary: Params.Validate accepts S == 8*maxMembers and
//        rejects S == 8*maxMembers - 1, at every committee cap incl. the max 128.
//        So no governance vote / genesis can install a sub-coupling weighted config.
//   (C2) DEFENSE-IN-DEPTH: even with INVALID params injected directly into the
//        store (SetParams does NOT validate — simulating a validation bypass), the
//        TransparentMembers runtime clamp sheds the lowest-stake candidates so the
//        round that opens ALWAYS has n <= S/8, is NEVER threshold-degraded, and a
//        <=1/3 coalition on that real opened round still holds < t points.
//   (C3) a budget so small S/8 == 0 opens NO weighted round (empty committee) —
//        no degenerate weighted round, no panic.
// ============================================================================

// TestC6_Coupling_GovValidationBoundary proves the coupling is enforced exactly at
// S = MinShareBudgetPerMember * EffectiveMaxMembers for every meaningful committee
// cap, including the absolute max committee 128 (S must be >= 1024). One below the
// boundary is rejected; the boundary itself is accepted.
func TestC6_Coupling_GovValidationBoundary(t *testing.T) {
	base := func(maxMembers, budget uint32) types.Params {
		p := transparentParams(0, maxMembers)
		p.DkgShareBudget = budget
		return p
	}
	for _, mm := range []uint32{1, 2, 3, 16, 32, 64, 128} {
		need := uint32(types.MinShareBudgetPerMember) * mm // = 8*mm
		// exactly at the coupling: MUST validate.
		if err := base(mm, need).Validate(); err != nil {
			t.Fatalf("gov-passable boundary rejected: maxMembers=%d S=%d (=8*mm) must pass Validate: %v", mm, need, err)
		}
		// one below: MUST be rejected (would let apportionment degenerate).
		if need >= 1 {
			if err := base(mm, need-1).Validate(); err == nil {
				t.Fatalf("SUB-COUPLING config ACCEPTED: maxMembers=%d S=%d (=8*mm-1) must fail Validate", mm, need-1)
			}
		}
	}
	// And the absolute committee max (128) with the default budget (256) is rejected —
	// you cannot pair a 128-cap with anything below 1024.
	if err := base(128, 256).Validate(); err == nil {
		t.Fatal("config maxMembers=128 S=256 must be rejected (256 < 8*128=1024)")
	}
	// The max cap paired with the max budget (128, 2048) is accepted, and is the largest
	// gov-passable committee: S=2048 >= 8*128.
	if err := base(128, 2048).Validate(); err != nil {
		t.Fatalf("maxMembers=128 S=2048 must pass: %v", err)
	}
}

// TestC6_Coupling_RuntimeClampHoldsUnderInvalidParams injects params that would
// VIOLATE the coupling if honored (many validators, a budget far below 8*maxMembers)
// straight into the store via SetParams (which does not validate), then drives the
// REAL committee selection + round open. The runtime clamp must keep n <= S/8 so the
// opened weighted round still satisfies S >= 8n, is not degraded, and bounds a
// <=1/3 coalition below t. This is the last line of defense behind gov validation.
func TestC6_Coupling_RuntimeClampHoldsUnderInvalidParams(t *testing.T) {
	// budgets whose S/8 is a small committee, but we announce MANY more validators than
	// S/8 so the clamp must fire; stakes are a whale+dust spread so the shed candidates
	// are the lowest-stake ones (still stake-sorted).
	for _, tc := range []struct {
		nVals  int
		budget uint32
	}{
		{nVals: 40, budget: 64},  // S/8 = 8  -> clamp 40 -> 8
		{nVals: 100, budget: 80}, // S/8 = 10 -> clamp 100 -> 10
		{nVals: 60, budget: 8},   // S/8 = 1  -> clamp 60 -> 1 (degenerate-small but valid: n=1)
	} {
		t.Run(fmt.Sprintf("nVals=%d_S=%d", tc.nVals, tc.budget), func(t *testing.T) {
			var vals []stakingtypes.Validator
			ms := make([]member, tc.nVals)
			for i := 0; i < tc.nVals; i++ {
				op := fmt.Sprintf("op%05d", i)
				ms[i] = newMember(op, "")
				// whale+dust spread: first few big, rest dust — so clamp sheds dust.
				stake := int64(1 + i)
				if i < 5 {
					stake = int64(1_000_000 - i)
				}
				vals = append(vals, bondedVal(op, stake))
			}
			k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
			// INVALID params (S < 8*EffectiveMaxMembers): DkgMaxMembers huge, budget tiny.
			p := transparentParams(0, uint32(tc.nVals)) // EffectiveMaxMembers = nVals
			p.DkgShareBudget = tc.budget
			// sanity: this config is INDEED gov-INVALID (Validate rejects it), so we are
			// exercising the defense-in-depth path, not a gov-passable one.
			if err := p.Validate(); err == nil {
				t.Fatalf("test premise wrong: params S=%d maxMembers=%d unexpectedly pass Validate", tc.budget, tc.nVals)
			}
			if err := k.SetParams(ctx, p); err != nil { // SetParams does NOT validate
				t.Fatal(err)
			}

			// Announce enc keys for everyone, then open the round through the real path.
			ann := make([]keeper.VEEntry, 0, tc.nVals)
			for _, m := range ms {
				ann = append(ann, keeper.VEEntry{Operator: m.op, VE: annVE(m)})
			}
			k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)
			k.EndBlockDKG(ctx.WithBlockHeight(1))

			round, ok := k.GetDkgRound(ctx, 1)
			if !ok || round.Status != types.DkgStatusOpen {
				t.Fatalf("round did not open: ok=%v status=%q", ok, round.Status)
			}
			n := len(round.Members)
			S := types.TotalEvalPoints(round.Members)
			maxByBudget := int(tc.budget) / types.MinShareBudgetPerMember
			// (1) the clamp held: committee never exceeds S/8.
			if n > maxByBudget {
				t.Fatalf("CLAMP FAILED: opened round has n=%d > S/8=%d (S=%d) — coupling violated", n, maxByBudget, S)
			}
			// (2) the opened round satisfies S >= 8n (the safety coupling).
			if S < types.MinShareBudgetPerMember*n {
				t.Fatalf("COUPLING VIOLATED at round-open: S=%d < 8n=%d (n=%d)", S, types.MinShareBudgetPerMember*n, n)
			}
			// (3) threshold is the non-degraded stake threshold (S >= 6n-1 holds), and
			// a <=1/3 coalition on the ACTUAL opened round holds < t points.
			tt := int(round.Threshold)
			if tt != tNew(S, n) {
				t.Fatalf("opened round threshold %d != non-degraded tNew=%d (S=%d n=%d) — clamp let a degraded round open", tt, tNew(S, n), S, n)
			}
			// build the strongest <=1/3 coalition on the REAL members: greedily take the
			// lowest-stake (most-seats-per-stake) members until just under 1/3 of committee stake.
			total := int64(0)
			for _, m := range round.Members {
				total += m.Weight.Int64()
			}
			// order members ascending by stake, accumulate points while stake*3 <= total.
			type mw struct {
				pts   int
				stake int64
			}
			mws := make([]mw, 0, n)
			for _, m := range round.Members {
				mws = append(mws, mw{pts: len(m.OwnedEvalPoints()), stake: m.Weight.Int64()})
			}
			// simple ascending sort by stake
			for a := 0; a < len(mws); a++ {
				for b := a + 1; b < len(mws); b++ {
					if mws[b].stake < mws[a].stake {
						mws[a], mws[b] = mws[b], mws[a]
					}
				}
			}
			var cstake int64
			cpts := 0
			for _, m := range mws {
				if (cstake+m.stake)*3 > total {
					break
				}
				cstake += m.stake
				cpts += m.pts
			}
			if cpts >= tt {
				t.Fatalf("SAFETY BROKEN on clamped round: <=1/3 coalition holds %d >= t=%d (n=%d S=%d)", cpts, tt, n, S)
			}
			t.Logf("injected S=%d maxMembers=%d over %d vals -> clamped to n=%d (S/8=%d), S=%d>=8n, t=%d, "+
				"strongest <=1/3 coalition holds %d < t (margin %d)", tc.budget, tc.nVals, tc.nVals, n, maxByBudget, S, tt, cpts, tt-cpts)
		})
	}
}

// TestC6_Coupling_TinyBudgetOpensNoWeightedRound: a budget below one seat's worth
// (S < MinShareBudgetPerMember) clamps the committee to 0 members, so NO round opens
// (EndBlockDKG holds on an empty member set) — there is no degenerate weighted round
// with S < 8n, and no panic.
func TestC6_Coupling_TinyBudgetOpensNoWeightedRound(t *testing.T) {
	var vals []stakingtypes.Validator
	ms := make([]member, 10)
	for i := 0; i < 10; i++ {
		op := fmt.Sprintf("op%05d", i)
		ms[i] = newMember(op, "")
		vals = append(vals, bondedVal(op, int64(100+i)))
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(0, 10)
	p.DkgShareBudget = 4 // S/8 = 0 -> committee clamped to 0
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	ann := make([]keeper.VEEntry, 0, 10)
	for _, m := range ms {
		ann = append(ann, keeper.VEEntry{Operator: m.op, VE: annVE(m)})
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)
	// Must not panic; must not open a round.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	if round, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatalf("a sub-seat budget must open NO weighted round, but epoch 1 opened: n=%d S=%d",
			len(round.Members), types.TotalEvalPoints(round.Members))
	}
	// And the committee selection itself returns empty (clamped to 0).
	if got := k.TransparentMembers(ctx, p); len(got) != 0 {
		t.Fatalf("committee must clamp to 0 at S/8=0, got %d members", len(got))
	}
}
