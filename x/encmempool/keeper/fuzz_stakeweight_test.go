// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-6 (exhaustive re-audit) — item (b): a FUZZ regression on the HIGH-3
// stake-weighted secret-sharing invariant, sweeping RANDOM stake distributions
// and RANDOM coalitions across n up to the committee cap (128) and the full
// validated share-budget range [8n, 2048].
//
// It locks in the two inequalities keeper.stakeThreshold's whole proof rests on,
// as a machine-checked property over arbitrary (not just hand-constructed) shapes:
//
//	SAFETY   any coalition holding <= 1/3 of committee stake holds < t points;
//	LIVENESS any set holding  > 2/3 of committee stake holds >= t points.
//
// The deterministic constructed-boundary sweep (TestReg_HB_BothInequalities_
// PropertySweep) already covers whale+dust, exact-1/3, and offline-just-under-1/3
// at every n in [2,128]; this fuzz explores the space BETWEEN those shapes so a
// future change to AllocateEvalPoints / the threshold can never silently reopen the
// band on some distribution the constructed sweep did not name. The seed corpus runs
// under the normal `go test` (no -fuzz needed), and each seed exercises MULTIPLE
// derived coalitions (the mask, its complement, the whale-alone set, and the all-but-
// whale set), so both branches are hit on every run.
// ============================================================================

func splitmix64(x *uint64) uint64 {
	*x += 0x9E3779B97F4A7C15
	z := *x
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func FuzzCycle6_StakeAllocationSafetyLiveness(f *testing.F) {
	// A handful of varied seeds; the fuzzer mutates from these, and they alone give
	// broad coverage because each runs several derived coalitions.
	f.Add(uint64(1), uint8(0), uint16(0), uint64(1), uint64(0), uint64(0))
	f.Add(uint64(7), uint8(14), uint16(9999), uint64(0xDEADBEEF), uint64(0x5555555555555555), uint64(0))
	f.Add(uint64(2), uint8(126), uint16(1), uint64(0xA5A5A5A5A5A5A5A5), uint64(0x0F0F0F0F0F0F0F0F), uint64(0xF0F0F0F0F0F0F0F0))
	f.Add(uint64(1000003), uint8(60), uint16(4096), uint64(123456789), uint64(0xFFFFFFFFFFFFFFFF), uint64(1))
	f.Add(uint64(0), uint8(1), uint16(2048), uint64(42), uint64(3), uint64(0))

	f.Fuzz(func(t *testing.T, epoch uint64, nRaw uint8, sRaw uint16, wseed, maskA, maskB uint64) {
		n := int(nRaw)%127 + 2 // n in [2, 128]
		// Validated share-budget range for this n: [MinShareBudgetPerMember*n, maxDkgShareBudget].
		sMin := types.MinShareBudgetPerMember * n
		sMax := 2048
		if sMin > sMax {
			return // unreachable for n<=128 (8*128=1024<=2048), defensive
		}
		S := sMin + int(sRaw)%(sMax-sMin+1)

		// Random positive weights (wide range => mixed whale/dust shapes).
		weights := make([]int64, n)
		s := wseed
		maxW := int64(0)
		whale := 0
		for i := 0; i < n; i++ {
			weights[i] = int64(1 + splitmix64(&s)%1_000_000)
			if weights[i] > maxW {
				maxW, whale = weights[i], i
			}
		}

		bit := func(mask [2]uint64, i int) bool {
			if i < 64 {
				return mask[0]&(uint64(1)<<uint(i)) != 0
			}
			return mask[1]&(uint64(1)<<uint(i-64)) != 0
		}
		mask := [2]uint64{maskA, maskB}

		// Derive several coalitions and check the invariant on each.
		coalitions := []func(i int) bool{
			func(i int) bool { return bit(mask, i) },  // the fuzzed subset
			func(i int) bool { return !bit(mask, i) }, // its complement
			func(i int) bool { return i == whale },    // whale alone
			func(i int) bool { return i != whale },    // all but the whale
		}

		var total int64
		for _, w := range weights {
			total += w
		}

		for _, inSetIdx := range coalitions {
			// coalition stake
			var cstake int64
			for i := 0; i < n; i++ {
				if inSetIdx(i) {
					cstake += weights[i]
				}
			}
			setPts, totalPts, thr := pointsHeld(weights, S, epoch, func(_ int64, i int) bool { return inSetIdx(i) })

			// Sanity: largest-remainder assigns the WHOLE budget (S' == S). thr is the exact
			// t = floor(2S/3)-n+1 the keeper's stakeThreshold uses on the weighted path (mirrored
			// by tNew, cross-checked against live rounds in the TestReg_HB_* / transparent tests).
			if totalPts != S {
				t.Fatalf("allocation lost points: totalPts=%d != S=%d (n=%d)", totalPts, S, n)
			}

			switch {
			case 3*cstake <= total: // stake fraction <= 1/3
				if setPts >= thr {
					t.Fatalf("SAFETY broken: n=%d S=%d epoch=%d coalition stake %d/%d (<=1/3) holds %d >= t=%d points",
						n, S, epoch, cstake, total, setPts, thr)
				}
			case 3*cstake > 2*total: // stake fraction > 2/3
				if setPts < thr {
					t.Fatalf("LIVENESS broken: n=%d S=%d epoch=%d online stake %d/%d (>2/3) holds %d < t=%d points",
						n, S, epoch, cstake, total, setPts, thr)
				}
			}
		}
	})
}
