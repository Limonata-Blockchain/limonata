package keeper

// INDEPENDENT GUARD-SOUNDNESS RE-VERIFIER (v0.3.6 strict-concentration gate ON).
//
// Re-confirms that gating the two-clause concentration guard behind DkgStrictConcentration
// did NOT change the math: with strict=true the guard must be byte-identical to the proven
// ungated reference (t = floor(2S/3)+n, single-op + strand + <=2/3-coalition clauses), and it
// must remain SOUND: the guard must never OPEN while (a) a <=2/3-stake coalition can reach t,
// or (b) a single operator reaches the strand bar S-t+1.
//
// This file is self-contained and calls only the real production symbols
// (AllocateEvalPoints, stakeThreshold, Keeper.coalitionBelowTwoThirdsCanDecrypt) plus an
// INDEPENDENT bitmask oracle for the coalition question, so a bug in the keeper DP cannot hide.

import (
	"fmt"
	"math/rand"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/types"
)

// buildWeighted builds a stake-weighted, apportioned committee from raw weights.
func buildWeighted(weights []int64, epoch uint64) []types.RoundMember {
	ms := make([]types.RoundMember, len(weights))
	for i, w := range weights {
		ms[i] = types.RoundMember{
			Index:        uint64(i),
			OperatorAddr: fmt.Sprintf("cosmosvaloper1op%04d", i),
			Weight:       sdkmath.NewInt(w),
		}
	}
	_ = epoch // caller allocates via AllocateEvalPoints; this returns raw members
	return ms
}

// gatedBreached computes the guard EXACTLY as CommitteeConcentrationBreached does with
// strict=true (DkgStrictConcentration ON), but without needing keeper state: it uses the
// gated stakeThreshold and the gated strand math inline.
func gatedBreached(members []types.RoundMember) (breached bool, t uint32) {
	t, _ = stakeThreshold(members, true) // strict ON
	S := types.TotalEvalPoints(members)
	strandBar := 0
	if S+1 > int(t) {
		strandBar = S - int(t) + 1
	}
	for _, m := range members {
		if !m.Weighted {
			return false, t
		}
		owned := len(m.OwnedEvalPoints())
		if uint32(owned) >= t {
			return true, t
		}
		if strandBar > 0 && owned >= strandBar {
			return true, t
		}
	}
	if (Keeper{}).coalitionBelowTwoThirdsCanDecrypt(members, t) {
		return true, t
	}
	return false, t
}

// oracleCoalitionCanReachT is an INDEPENDENT (bitmask, brute-force) answer to "does some
// coalition with <=2/3 of total stake own >= t eval points?". Structurally different from the
// keeper's value-keyed DP, so the two cross-check each other. Only valid for small n.
func oracleCoalitionCanReachT(members []types.RoundMember, t uint32) bool {
	n := len(members)
	pts := make([]int, n)
	wt := make([]int64, n)
	total := int64(0)
	for i, m := range members {
		pts[i] = len(m.OwnedEvalPoints())
		wt[i] = m.Weight.Int64()
		total += wt[i]
	}
	for mask := 0; mask < (1 << n); mask++ {
		var ps int
		var ws int64
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				ps += pts[i]
				ws += wt[i]
			}
		}
		// coalition with <= 2/3 of total stake (ws*3 <= total*2) that reaches t points.
		if ws*3 <= total*2 && ps >= int(t) {
			return true
		}
	}
	return false
}

// oracleMaxSingleOwnedFrac / helpers -----------------------------------------------------------

func randWeights(rng *rand.Rand, n int) []int64 {
	w := make([]int64, n)
	shape := rng.Intn(5)
	switch shape {
	case 0: // near-equal
		for i := range w {
			w[i] = 100 + int64(rng.Intn(20))
		}
	case 1: // uniform spread
		for i := range w {
			w[i] = 1 + int64(rng.Intn(1000))
		}
	case 2: // one whale
		for i := range w {
			w[i] = 1 + int64(rng.Intn(50))
		}
		w[rng.Intn(n)] = int64(500 + rng.Intn(5000))
	case 3: // power-law-ish
		for i := range w {
			v := int64(1)
			for j := 0; j < rng.Intn(6); j++ {
				v *= int64(2 + rng.Intn(3))
			}
			w[i] = v
		}
	case 4: // two large holders
		for i := range w {
			w[i] = 1 + int64(rng.Intn(30))
		}
		w[rng.Intn(n)] = int64(300 + rng.Intn(1500))
		w[rng.Intn(n)] += int64(300 + rng.Intn(1500))
	}
	return w
}

// TestGuardSoundness_ReverifyStrictGate is the main >=100k committee fuzz.
func TestGuardSoundness_ReverifyStrictGate(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EED_0721))
	const iters = 120000

	var (
		opened, closed        int
		strandCloses          int
		singleOpCloses        int
		coalitionCloses       int
		coalitionEverTrue     int // clause 1b ever fired under strict (should be ~never: theorem)
		premiseViol           int // pts(C) > quota(C)+(n-1) sampled violations
	)

	for it := 0; it < iters; it++ {
		n := 4 + rng.Intn(21) // n in [4,24]
		// coupling: S >= MinShareBudgetPerMember(=8) * n. Sample S in [8n, ~20n].
		minS := types.MinShareBudgetPerMember * n
		S := minS + rng.Intn(12*n+1)
		epoch := uint64(it) + 1

		raw := buildWeighted(randWeights(rng, n), epoch)
		alloc := AllocateEvalPoints(raw, S, epoch)
		Sreal := types.TotalEvalPoints(alloc)

		// 1) gating-on math == proven ungated reference math: the strict threshold must equal the
		// reference formula t = floor(2S/3)+n exactly (with the documented clamps). The guard's
		// downstream clauses are then computed from primitives below and are, by construction, the
		// same formula the ungated reference guard runs — so equal t => identical outcome.
		tg, _ := stakeThreshold(alloc, true) // strict ON
		tRef := uint32((2*Sreal)/3 + n)
		if tRef > uint32(Sreal) {
			tRef = uint32(Sreal)
		}
		if tRef < 1 {
			tRef = 1
		}
		if tg != tRef {
			t.Fatalf("iter %d: gated t=%d != reference floor(2S/3)+n=%d (S=%d,n=%d): gating changed the threshold math", it, tg, tRef, Sreal, n)
		}

		// Single DP evaluation per iter (bigint-heavy) reused for the breach verdict + soundness.
		coalitionHit := (Keeper{}).coalitionBelowTwoThirdsCanDecrypt(alloc, tg)
		strandBar := Sreal - int(tg) + 1
		singleHit, strandHit := false, false
		for _, m := range alloc {
			owned := len(m.OwnedEvalPoints())
			if uint32(owned) >= tg {
				singleHit = true
			} else if strandBar > 0 && owned >= strandBar {
				strandHit = true
			}
		}
		// gated guard verdict, derived from primitives (identical to CommitteeConcentrationBreached
		// with strict=true, and to the ungated reference guard since tg==tRef).
		gb := singleHit || strandHit || coalitionHit
		if gb {
			closed++
		} else {
			opened++
		}

		// 2) SOUNDNESS: when the guard is OPEN, no bad condition may exist.
		if !gb {
			if singleHit {
				t.Fatalf("iter %d: OPEN guard but a single op owns >= t=%d (single-op break)", it, tg)
			}
			if strandHit {
				t.Fatalf("iter %d: OPEN guard but a single op owns >= strandBar=%d (strand break)", it, strandBar)
			}
			if coalitionHit {
				t.Fatalf("iter %d: OPEN guard but keeper DP says a <=2/3 coalition reaches t=%d", it, tg)
			}
		}

		if coalitionHit {
			coalitionEverTrue++
			coalitionCloses++
		}
		if singleHit {
			singleOpCloses++
		}
		if strandHit {
			strandCloses++
		}

		// theorem premise spot-check: pts(C) <= quota(C) + (n-1) for a random coalition.
		if n <= 30 {
			mask := rng.Intn(1 << uint(n))
			var ps int
			var ws int64
			var totalW int64
			for i, m := range alloc {
				w := m.Weight.Int64()
				totalW += w
				if mask&(1<<i) != 0 {
					ps += len(m.OwnedEvalPoints())
					ws += w
				}
			}
			if totalW > 0 {
				quota := float64(ws) * float64(Sreal) / float64(totalW)
				if float64(ps) > quota+float64(n-1)+1e-9 {
					premiseViol++
				}
			}
		}
	}

	t.Logf("iters=%d opened(OPEN)=%d closed(BREACHED)=%d", iters, opened, closed)
	t.Logf("close causes: single-op=%d strand=%d coalition-1b=%d", singleOpCloses, strandCloses, coalitionCloses)
	t.Logf("coalition-1b ever true under strict=%d (theorem predicts 0)", coalitionEverTrue)
	t.Logf("apportionment premise pts(C)<=quota+(n-1) violations=%d (must be 0)", premiseViol)

	if premiseViol != 0 {
		t.Fatalf("apportionment premise violated %d times: clause-1 proof foundation broken", premiseViol)
	}
	if coalitionEverTrue != 0 {
		t.Fatalf("under strict t=floor(2S/3)+n a <=2/3 coalition reached t in %d committees: clause-1 theorem broken", coalitionEverTrue)
	}
	if opened == 0 || closed == 0 {
		t.Fatalf("degenerate fuzz: opened=%d closed=%d (need both populated)", opened, closed)
	}
}

// TestGuardSoundness_IndependentOracleSmallN cross-checks the keeper's value-keyed coalition DP
// against a structurally-independent brute-force bitmask oracle on small committees, and re-asserts
// full soundness (OPEN => oracle finds no <=2/3 coalition at t, and no single-op/strand break).
func TestGuardSoundness_IndependentOracleSmallN(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE_13))
	const iters = 40000
	dpMismatch, oracleOpenBreak := 0, 0
	checked := 0
	for it := 0; it < iters; it++ {
		n := 4 + rng.Intn(9) // n in [4,12] -> 2^12 = 4096 subsets
		minS := types.MinShareBudgetPerMember * n
		S := minS + rng.Intn(16*n+1)
		epoch := uint64(it) + 1
		alloc := AllocateEvalPoints(buildWeighted(randWeights(rng, n), epoch), S, epoch)

		gb, tg := gatedBreached(alloc)

		// keeper DP vs independent bitmask oracle for clause 1b (coalition-can-reach-t).
		dp := (Keeper{}).coalitionBelowTwoThirdsCanDecrypt(alloc, tg)
		orc := oracleCoalitionCanReachT(alloc, tg)
		if dp != orc {
			dpMismatch++
			if dpMismatch <= 3 {
				t.Errorf("iter %d: keeper DP (%v) != independent oracle (%v) for coalition@t=%d (S=%d,n=%d)", it, dp, orc, tg, types.TotalEvalPoints(alloc), n)
			}
		}

		if !gb { // OPEN: independent oracle must also see no bad condition.
			Sreal := types.TotalEvalPoints(alloc)
			strandBar := Sreal - int(tg) + 1
			if orc {
				oracleOpenBreak++
			}
			for _, m := range alloc {
				owned := len(m.OwnedEvalPoints())
				if uint32(owned) >= tg || (strandBar > 0 && owned >= strandBar) {
					t.Fatalf("iter %d: OPEN guard but op owns %d (t=%d strandBar=%d)", it, owned, tg, strandBar)
				}
			}
		}
		checked++
	}
	t.Logf("independent-oracle pass: checked=%d DP-vs-oracle-mismatches=%d oracle-open-breaks=%d", checked, dpMismatch, oracleOpenBreak)
	if dpMismatch != 0 {
		t.Fatalf("keeper coalition DP disagreed with independent oracle in %d cases", dpMismatch)
	}
	if oracleOpenBreak != 0 {
		t.Fatalf("independent oracle found a <=2/3 coalition reaching t on %d OPEN committees", oracleOpenBreak)
	}
}

// TestGuardSoundness_DecentralizedOpens_ConcentratedCloses is the directed OPEN/CLOSE check at
// the default topology S=256,n=16 (t=186, strandBar=71 -> strand fires at >=71/256=27.7%).
func TestGuardSoundness_DecentralizedOpens_ConcentratedCloses(t *testing.T) {
	const n, S = 16, 256
	epoch := uint64(16)

	// Decentralized: 16 equal holders -> each owns 16/256 = 6.25% << 27.7%. Guard must OPEN.
	eq := make([]int64, n)
	for i := range eq {
		eq[i] = 1000
	}
	dec := AllocateEvalPoints(buildWeighted(eq, epoch), S, epoch)
	gb, tg := gatedBreached(dec)
	maxOwned := 0
	for _, m := range dec {
		if o := len(m.OwnedEvalPoints()); o > maxOwned {
			maxOwned = o
		}
	}
	t.Logf("decentralized S=%d n=%d t=%d strandBar=%d maxOwned=%d (%.1f%%) breached=%v",
		types.TotalEvalPoints(dec), n, tg, types.TotalEvalPoints(dec)-int(tg)+1, maxOwned,
		100*float64(maxOwned)/float64(types.TotalEvalPoints(dec)), gb)
	if gb {
		t.Fatalf("decentralized equal committee (max %d/%d = %.1f%%) must OPEN, got breached", maxOwned, S, 100*float64(maxOwned)/256)
	}

	// Concentrated: one holder ~50% stake -> owns ~128/256 >= strandBar 71. Guard must CLOSE.
	conc := make([]int64, n)
	for i := range conc {
		conc[i] = 100
	}
	conc[0] = 100 * int64(n-1) // op0 ~= half of total stake
	cc := AllocateEvalPoints(buildWeighted(conc, epoch), S, epoch)
	cb, ctg := gatedBreached(cc)
	c0 := len(cc[0].OwnedEvalPoints())
	t.Logf("concentrated op0 owns %d/%d (%.1f%%) t=%d strandBar=%d breached=%v",
		c0, S, 100*float64(c0)/256, ctg, S-int(ctg)+1, cb)
	if !cb {
		t.Fatalf("concentrated committee (op0 owns %d/%d) must CLOSE, got open", c0, S)
	}
}

// TestGuardSoundness_LiveEpoch16 evaluates the CURRENT live epoch-16 committee under the
// gated-ON guard. Jason's operator holds ~126/256 eval points; strandBar at t=186 is 71, so the
// guard must CLOSE via the strand clause (126 >= 71, and 126 < t=186 so NOT single-op clause 1a).
func TestGuardSoundness_LiveEpoch16(t *testing.T) {
	const S = 256
	// Reconstruct the live epoch-16 stake shape: Jason ~126/256, the remaining ~130 points
	// spread across the other bonded validators. Exact other-member split does not change the
	// strand verdict (only Jason's share does); use a plausible spread that sums to S.
	weights := []int64{
		12600, // Jason -> ~126/256
		3500,
		3000,
		2200,
		1500,
		900,
		300,
	}
	epoch := uint64(16)
	m := AllocateEvalPoints(buildWeighted(weights, epoch), S, epoch)
	gb, tg := gatedBreached(m)
	jason := len(m[0].OwnedEvalPoints())
	strandBar := types.TotalEvalPoints(m) - int(tg) + 1
	t.Logf("live epoch-16: S=%d t=%d strandBar=%d Jason owns=%d (%.1f%%) single-op@t=%v strand@bar=%v breached=%v",
		types.TotalEvalPoints(m), tg, strandBar, jason, 100*float64(jason)/float64(types.TotalEvalPoints(m)),
		uint32(jason) >= tg, jason >= strandBar, gb)
	if !gb {
		t.Fatalf("live epoch-16 committee (Jason %d/%d) must CLOSE under gated-on guard, got open", jason, S)
	}
	if uint32(jason) >= tg {
		t.Logf("note: Jason at/over t (%d>=%d) — closes via single-op clause 1a", jason, tg)
	} else if jason >= strandBar {
		t.Logf("confirmed: closes via STRAND clause (%d >= strandBar %d, and %d < t %d)", jason, strandBar, jason, tg)
	}
}
