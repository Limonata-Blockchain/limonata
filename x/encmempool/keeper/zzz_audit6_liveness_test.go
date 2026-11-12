// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// PROBE 4 — HONEST >2/3 (snapshot) ONLINE SET PASSES THE REAL STAKE GATE.
// The strict confidentiality threshold is floor(2S/3)+1, so a minimally-over-2/3 online
// stake set can intentionally hold fewer than t evaluation points after Hamilton rounding.
// That is the price paid to remove the old <=2/3-stake reconstruction band. This probe drives
// the real on-chain combine gate and records, but no longer rejects, those narrow strict-threshold
// shortfalls.
func TestProbe_HonestSupermajorityPassesStakeGate(t *testing.T) {
	splitmix := func(x *uint64) uint64 {
		*x += 0x9E3779B97F4A7C15
		z := *x
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	seed := uint64(0xC0FFEE)
	cases := 0
	shortStrict := 0
	for iter := 0; iter < 6000; iter++ {
		n := int(splitmix(&seed)%127) + 2 // [2,128]
		sMin := types.MinShareBudgetPerMember * n
		S := sMin + int(splitmix(&seed)%uint64(2048-sMin+1))
		epoch := splitmix(&seed)

		// Random weights: mix of whale + dust to stress rounding.
		weights := make([]int64, n)
		var total int64
		shape := splitmix(&seed) % 3
		for i := 0; i < n; i++ {
			switch shape {
			case 0: // wide uniform-ish
				weights[i] = int64(1 + splitmix(&seed)%1_000_000)
			case 1: // one whale + dust
				if i == 0 {
					weights[i] = int64(500_000 + splitmix(&seed)%1_000_000)
				} else {
					weights[i] = int64(1 + splitmix(&seed)%3)
				}
			default: // heavy-tailed
				weights[i] = int64(1 + splitmix(&seed)%uint64(1<<(splitmix(&seed)%40)))
			}
			total += weights[i]
		}

		members := keeper.AllocateEvalPoints(mkMembers(weights), S, epoch)
		if types.TotalEvalPoints(members) != S {
			t.Fatalf("allocation lost points: got %d want %d", types.TotalEvalPoints(members), S)
		}
		tThr := tNew(S, n)

		// Build the online set greedily from HIGHEST stake down until its stake fraction is
		// STRICTLY > 2/3 of the committee total — an honest online supermajority.
		type mw struct {
			idx uint64
			w   int64
			pts int
		}
		ms := make([]mw, len(members))
		for i, m := range members {
			ms[i] = mw{idx: m.Index, w: m.Weight.Int64(), pts: len(m.OwnedEvalPoints())}
		}
		// sort by weight desc (simple insertion; n<=128)
		for i := 1; i < len(ms); i++ {
			for j := i; j > 0 && ms[j].w > ms[j-1].w; j-- {
				ms[j], ms[j-1] = ms[j-1], ms[j]
			}
		}
		present := map[uint64]bool{}
		var onlineStake int64
		onlinePts := 0
		reached := false
		for _, m := range ms {
			present[m.idx] = true
			onlineStake += m.w
			onlinePts += m.pts
			if 3*onlineStake > 2*total {
				reached = true
				break
			}
		}
		if !reached {
			continue // degenerate (can happen only if total==0, impossible: weights>=1)
		}
		cases++

		// The REAL redundant gate must pass for any >2/3 online stake set.
		if !keeper.DecryptingSetMeetsStake(members, present) {
			t.Fatalf("LIVENESS(gate): n=%d S=%d epoch=%d online stake %d/%d (>2/3) FAILS DecryptingSetMeetsStake",
				n, S, epoch, onlineStake, total)
		}
		if onlinePts < tThr {
			shortStrict++
		}
	}
	t.Logf("checked %d honest-supermajority cases through the stake gate; %d were intentionally below strict point threshold", cases, shortStrict)
}

// PROBE 5 — the redundant stake gate must deny sets at or below 2/3 stake even when they hold
// enough points, and pass only above the two-thirds stake boundary.
func TestProbe_StakeGateRequiresMoreThanTwoThirds(t *testing.T) {
	// A crafted whale-just-under-half + others: a set holding many points but < 2/3 stake.
	// weights: 3 members [49, 26, 25] * scale, S large.
	weights := []int64{49, 26, 25}
	S := 8 * len(weights) * 32 // comfortably >= 8n
	members := keeper.AllocateEvalPoints(mkMembers(weights), S, 1)
	// Use the whale alone (49/100): the gate must DENY even if it holds many points.
	var whaleIdx uint64
	for _, m := range members {
		if m.Weight.Int64() == 49 {
			whaleIdx = m.Index
		}
	}
	present := map[uint64]bool{whaleIdx: true}
	whalePts := 0
	for _, m := range members {
		if m.Index == whaleIdx {
			whalePts = len(m.OwnedEvalPoints())
		}
	}
	gate := keeper.DecryptingSetMeetsStake(members, present)
	t.Logf("whale 49/100 (< 2/3) holds %d/%d points, t=%d, gate_passes=%v (must be false: <=2/3 stake)",
		whalePts, S, tNew(S, len(members)), gate)
	if gate {
		t.Fatalf("stake gate passed for a <=2/3-stake set")
	}
	// Whale + any other is 75/100 or 74/100 and must pass.
	for _, m := range members {
		if m.Index != whaleIdx {
			present[m.Index] = true
			break
		}
	}
	if !keeper.DecryptingSetMeetsStake(members, present) {
		t.Fatalf("stake gate denied a >2/3-stake set")
	}

	// Exactly 2/3 stake must still be denied.
	equalMembers := keeper.AllocateEvalPoints(mkMembers([]int64{33, 33, 33}), S, 2)
	exactTwoThirds := map[uint64]bool{
		equalMembers[0].Index: true,
		equalMembers[1].Index: true,
	}
	if keeper.DecryptingSetMeetsStake(equalMembers, exactTwoThirds) {
		t.Fatalf("stake gate passed for exactly 2/3 stake")
	}
	for _, m := range members {
		present[m.Index] = true
	}
	if !keeper.DecryptingSetMeetsStake(members, present) {
		t.Fatalf("stake gate denied the full committee")
	}
}
