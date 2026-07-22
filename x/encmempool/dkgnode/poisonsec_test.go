package dkgnode_test

// Security-hardening tests for the optimized poison detection. The perf work (per-epoch
// cache + parse/index hoist) must NOT weaken the mempool's poison-attribution guarantee:
// every poisoned (dealer, point) the original algorithm flags must still be flagged, and
// no honest dealing may be falsely flagged. These tests attack that property directly with
// randomized topologies and randomized poison patterns, and check determinism (which is
// what makes the per-epoch memoization sound).

import (
	"math/rand"
	"testing"

	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/types"
)

// applyPoison mutates a dealing in one of the three attributable ways the detector must
// catch: a dropped enc-share (ct==nil), a corrupt commitment (parse/verify fail), or a
// tampered ciphertext (decrypt/verify fail). victimPoint is one of the caller's owned points.
func applyPoison(d *types.Dealing, kind int, victimPoint uint64) {
	switch kind {
	case 0: // drop the enc-share addressed to victimPoint
		out := d.EncShares[:0]
		for _, s := range d.EncShares {
			if s.MemberIndex != victimPoint {
				out = append(out, s)
			}
		}
		d.EncShares = out
	case 1: // corrupt the Feldman commitments
		if len(d.Commitments) > 0 && len(d.Commitments[0]) > 1 {
			d.Commitments[0][1] ^= 0xFF
		}
	case 2: // tamper the ciphertext body addressed to victimPoint
		for i := range d.EncShares {
			if d.EncShares[i].MemberIndex == victimPoint && len(d.EncShares[i].Body) > 0 {
				d.EncShares[i].Body[0] ^= 0xFF
			}
		}
	}
}

// TestDetectPoisonedParityFuzz hammers the refactor against the naive reference across many
// random topologies and random poison patterns. Any divergence (a missed poison OR a false
// positive) fails the test - that is exactly a mempool-security regression.
func TestDetectPoisonedParityFuzz(t *testing.T) {
	if testing.Short() {
		t.Skip("skip crypto fuzz in -short")
	}
	rng := rand.New(rand.NewSource(0xC0FFEE)) // fixed seed: reproducible topology/poison choices
	const iters = 40
	totalReports := 0
	poisonedRuns := 0
	for it := 0; it < iters; it++ {
		dealers := 2 + rng.Intn(5)               // 2..6 dealers
		shareBudget := (dealers + 2) + rng.Intn(28) // >= dealers+2 so every dealer owns >=1 point
		if shareBudget < dealers {
			shareBudget = dealers
		}
		maxMine := shareBudget - (dealers - 1) // leave >=1 point per other dealer
		if maxMine < 1 {
			maxMine = 1
		}
		myPoints := 1 + rng.Intn(maxMine)
		thr := 1 + rng.Intn(shareBudget) // any valid threshold 1..S

		myPts, myPriv, qual, dealings := buildLiveScaleFixture(t, dealers, shareBudget, myPoints, thr)

		// Randomly poison a subset of dealers (0..dealers-1) in random ways.
		nPoison := rng.Intn(dealers)
		if nPoison > 0 {
			poisonedRuns++
		}
		perm := rng.Perm(dealers)
		for i := 0; i < nPoison; i++ {
			dealer := qual[perm[i]]
			victim := myPts[rng.Intn(len(myPts))]
			d := dealings[dealer]
			applyPoison(&d, rng.Intn(3), victim)
			dealings[dealer] = d
		}

		want := detectNaive(myPts, myPriv, qual, dealings)
		got := dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)
		if len(got) != len(want) {
			t.Fatalf("iter %d: report count differs refactor=%d naive=%d (dealers=%d S=%d mine=%d t=%d poisoned=%d)",
				it, len(got), len(want), dealers, shareBudget, myPoints, thr, nPoison)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("iter %d: report[%d] differs refactor=%+v naive=%+v", it, i, got[i], want[i])
			}
		}
		totalReports += len(want)
	}
	t.Logf("parity held across %d random topologies (%d with poison), %d total poison reports matched exactly",
		iters, poisonedRuns, totalReports)
	if totalReports == 0 {
		t.Fatal("fuzz produced no poison reports at all - it is not exercising the detection path")
	}
}

// TestDetectPoisonedDeterminism is the invariant the per-epoch cache relies on: identical
// inputs always yield an identical report slice. If this ever failed, memoizing the result
// for the epoch would be unsound (a cached result could differ from a fresh compute).
func TestDetectPoisonedDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skip crypto build in -short")
	}
	myPts, myPriv, qual, dealings := buildLiveScaleFixture(t, 6, 64, 24, 43)
	// poison a couple of dealers so the report slice is non-trivial
	applyTo := func(dealer, victim uint64, kind int) {
		d := dealings[dealer]
		applyPoison(&d, kind, victim)
		dealings[dealer] = d
	}
	applyTo(qual[1], myPts[0], 0)
	applyTo(qual[4], myPts[2], 2)

	ref := dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)
	if len(ref) == 0 {
		t.Fatal("expected poison reports from the poisoned fixture")
	}
	for i := 0; i < 12; i++ {
		got := dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)
		if len(got) != len(ref) {
			t.Fatalf("run %d: non-deterministic report count %d != %d", i, len(got), len(ref))
		}
		for j := range ref {
			if got[j] != ref[j] {
				t.Fatalf("run %d: non-deterministic report[%d] %+v != %+v", i, j, got[j], ref[j])
			}
		}
	}
	t.Logf("determinism held: %d reports identical across 12 runs (memoization is sound)", len(ref))
}
