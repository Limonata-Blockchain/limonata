// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// PROBE 4 — HONEST >2/3 (snapshot) ONLINE SET NEVER STRANDED, through the REAL decrypt
// gate. The committed fuzz proves the POINT-COUNT inequality (online >2/3 => >= t points).
// This probe additionally drives the SECOND clamp that recoverSharedSecret applies on the
// on-chain combine — DecryptingSetMeetsStake (strict stake majority) — to confirm the
// redundant gate can never strand the guaranteed-liveness set, across extreme stake shapes
// and committees up to the cap. It builds the REAL allocated round members via
// keeper.AllocateEvalPoints, forms the online set = smallest-by-count set of top-stake
// members exceeding 2/3 snapshot stake, marks exactly their owned eval points present, and
// requires: (a) present-point count >= t AND (b) the stake gate passes.
func TestProbe_HonestSupermajorityNeverStrandedThroughGate(t *testing.T) {
	splitmix := func(x *uint64) uint64 {
		*x += 0x9E3779B97F4A7C15
		z := *x
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	seed := uint64(0xC0FFEE)
	cases := 0
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

		// (a) point-count liveness: the online >2/3 set holds >= t points.
		if onlinePts < tThr {
			t.Fatalf("LIVENESS(points): n=%d S=%d epoch=%d online stake %d/%d (>2/3) holds %d < t=%d",
				n, S, epoch, onlineStake, total, onlinePts, tThr)
		}
		// (b) the REAL redundant gate must ALSO pass for the guaranteed-liveness set.
		if !keeper.DecryptingSetMeetsStake(members, present) {
			t.Fatalf("LIVENESS(gate): n=%d S=%d epoch=%d online stake %d/%d (>2/3) FAILS DecryptingSetMeetsStake",
				n, S, epoch, onlineStake, total)
		}
	}
	t.Logf("checked %d honest-supermajority cases through BOTH the point-count threshold and the stake gate; none stranded", cases)
}

// PROBE 5 — the redundant stake gate must never bind ABOVE the guaranteed-liveness set, but it
// is DOCUMENTED to possibly bind above the crypto bar for sets in (bar, 1/2]. This probe just
// records, informationally, how often a set that HOLDS >= t points is nonetheless denied by the
// strict-majority gate (a bounded deferral, not a strand) — to confirm it only ever affects sets
// BELOW a stake majority (never the >2/3 liveness set, which PROBE 4 covers).
func TestProbe_StakeGateBindsOnlyBelowMajority(t *testing.T) {
	// A crafted whale-just-under-half + others: a set holding >= t points but < 1/2 stake.
	// weights: 3 members [49, 26, 25] * scale, S large.
	weights := []int64{49, 26, 25}
	S := 8 * len(weights) * 32 // comfortably >= 8n
	members := keeper.AllocateEvalPoints(mkMembers(weights), S, 1)
	// Present = the two smaller members (26+25=51 > 49? yes 51>49 => that's a majority). Use
	// the whale alone (49) which is < 1/2 of 100 => gate must DENY even if it holds >= t points.
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
	t.Logf("whale 49/100 (< 1/2) holds %d/%d points, t=%d, gate_passes=%v (must be false: <1/2 stake)",
		whalePts, S, tNew(S, len(members)), gate)
	if gate {
		t.Fatalf("stake gate passed for a <1/2-stake set — the redundant guard is not binding")
	}
	// And a strict majority (whale+one) must pass.
	var anyOther uint64
	for _, m := range members {
		if m.Index != whaleIdx {
			anyOther = m.Index
			break
		}
	}
	present[anyOther] = true
	if !keeper.DecryptingSetMeetsStake(members, present) {
		t.Fatalf("stake gate denied a strict-majority set")
	}
	_ = sdkmath.NewInt(0)
}
