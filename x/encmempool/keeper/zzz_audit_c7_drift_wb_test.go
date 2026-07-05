// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

// CYCLE-7 ADVERSARIAL AUDIT — lens: STAKE-DRIFT / REKEY (white-box).
// These probes attack committeeMaxCoalitionDriftBps + stakeThreshold/AllocateEvalPoints
// directly (unexported), to answer: is the metric an exact, order-independent, overflow-safe
// pure function (no fork), and does the residual drift bound D actually PRESERVE the
// snapshot-proven coupling at every VALID config?

import (
	"math/big"
	"math/rand"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/types"
)

func rm(op string, w int64) types.RoundMember {
	return types.RoundMember{OperatorAddr: op, Weight: sdkmath.NewInt(w)}
}
func rmBig(op string, w sdkmath.Int) types.RoundMember {
	return types.RoundMember{OperatorAddr: op, Weight: w}
}
func pow10(n int64) sdkmath.Int {
	return sdkmath.NewIntFromBigInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(n), nil))
}

// TestC7_DriftMetric_KnownValues pins the metric on hand-computed inputs (the same shape the
// cycle-5 verdict claims "7134/1579" for) so a silent change of the formula is caught.
func TestC7_DriftMetric_KnownValues(t *testing.T) {
	cases := []struct {
		name       string
		snap, live []types.RoundMember
		want       uint64
	}{
		// 100/100/100 -> 200/100/100 : half-TV = 1666.66.. floored 1666.
		{"single-double", []types.RoundMember{rm("a", 100), rm("b", 100), rm("c", 100)},
			[]types.RoundMember{rm("a", 200), rm("b", 100), rm("c", 100)}, 1666},
		// 30/30/40 -> 40/40/20 : sumAbs=4000, denom=20000 -> 2000 bps.
		{"coupling-demo", []types.RoundMember{rm("a", 30), rm("b", 30), rm("c", 40)},
			[]types.RoundMember{rm("a", 40), rm("b", 40), rm("c", 20)}, 2000},
		// no movement -> 0.
		{"no-drift", []types.RoundMember{rm("a", 5), rm("b", 7)},
			[]types.RoundMember{rm("a", 5), rm("b", 7)}, 0},
		// total wipe of one side's identity (a<->d swap): a full 1.0 move => 10000 bps.
		{"disjoint-sets", []types.RoundMember{rm("a", 100)},
			[]types.RoundMember{rm("d", 100)}, 10000},
	}
	for _, c := range cases {
		if got := committeeMaxCoalitionDriftBps(c.snap, c.live); got != c.want {
			t.Errorf("%s: drift=%d want=%d", c.name, got, c.want)
		}
	}
}

// TestC7_DriftMetric_PermutationInvariant is the FORK probe: the metric must be identical no
// matter what order CometBFT/the staking iterator happened to list members in.
func TestC7_DriftMetric_PermutationInvariant(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC7))
	for iter := 0; iter < 4000; iter++ {
		n := 1 + rng.Intn(12)
		snap := make([]types.RoundMember, n)
		live := make([]types.RoundMember, n)
		for i := 0; i < n; i++ {
			op := string(rune('A' + i))
			snap[i] = rm(op, int64(rng.Intn(1000)))
			live[i] = rm(op, int64(rng.Intn(1000)))
		}
		base := committeeMaxCoalitionDriftBps(snap, live)
		// Shuffle snap and live independently many ways; must not move.
		for s := 0; s < 6; s++ {
			ps := append([]types.RoundMember(nil), snap...)
			pl := append([]types.RoundMember(nil), live...)
			rng.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
			rng.Shuffle(len(pl), func(i, j int) { pl[i], pl[j] = pl[j], pl[i] })
			if got := committeeMaxCoalitionDriftBps(ps, pl); got != base {
				t.Fatalf("NON-DETERMINISTIC drift under permutation: base=%d got=%d\nsnap=%v live=%v", base, got, snap, live)
			}
		}
	}
}

// TestC7_DriftMetric_ExtremeStake exercises whale+dust and large magnitudes that stay WITHIN
// the sdkmath.Int 256-bit envelope (~1.16e77): the metric must stay in [0,10000] and match the
// exact rational half-TV. (The overflow boundary above this is its own test below.)
func TestC7_DriftMetric_ExtremeStake(t *testing.T) {
	whale := pow10(30)
	dust := sdkmath.NewInt(1)
	cases := []struct {
		name       string
		snap, live []types.RoundMember
	}{
		{"whale+dust, dust grows to 10^29",
			[]types.RoundMember{rmBig("w", whale), rmBig("d", dust)},
			[]types.RoundMember{rmBig("w", whale), rmBig("d", pow10(29))}},
		{"whale halves, dust static",
			[]types.RoundMember{rmBig("w", whale), rmBig("d", pow10(20))},
			[]types.RoundMember{rmBig("w", pow10(30).Quo(sdkmath.NewInt(2))), rmBig("d", pow10(20))}},
		{"two whales near-equal (10^30)",
			[]types.RoundMember{rmBig("w", pow10(30)), rmBig("x", pow10(30).Add(sdkmath.NewInt(1)))},
			[]types.RoundMember{rmBig("w", pow10(30).Add(sdkmath.NewInt(1))), rmBig("x", pow10(30))}},
	}
	for _, c := range cases {
		got := committeeMaxCoalitionDriftBps(c.snap, c.live)
		if got > 10000 {
			t.Errorf("%s: drift=%d exceeds 10000 (clamp/overflow bug)", c.name, got)
		}
		// Independent rational cross-check: half * sum|w_live/W_live - w_snap/W_snap| * 10000, floored.
		want := rationalHalfTVbps(c.snap, c.live)
		if got != want {
			t.Errorf("%s: drift=%d want(rational)=%d", c.name, got, want)
		}
	}
}

// TestC7_DriftMetric_OverflowPanics is the FINDING probe. The endblock.go comment claims the
// metric is "computed in EXACT big-integer arithmetic ... overflow-safe for any stake magnitude".
// That is FALSE: sdkmath.Int is a 256-bit-bounded integer whose Mul PANICS on overflow, and the
// metric multiplies (single weight) x (total committee weight) — a value ~W^2. For a committee
// whose total stake W exceeds ~2^128 (~3.4e38 base units), that product exceeds 2^256 and the
// metric PANICS. (Reachable on a high-supply / high-decimal chain, e.g. a memecoin with a
// sextillion+ supply at 18 decimals => staked base units > 3.4e38.)
func TestC7_DriftMetric_OverflowPanics(t *testing.T) {
	// Two ~10^40 whales: W ~ 2e40, and (w * W) ~ 2e80 > 2^256 (~1.16e77) => Int.Mul panics.
	snap := []types.RoundMember{rmBig("w", pow10(40)), rmBig("x", pow10(40))}
	live := []types.RoundMember{rmBig("w", pow10(40).MulRaw(2)), rmBig("x", pow10(40))}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("EXPECTED a panic from committeeMaxCoalitionDriftBps at 10^40 stake, got none " +
				"(if this stops panicking the overflow was fixed — update the finding)")
		}
		t.Logf("CONFIRMED overflow panic (recovered only by EndBlockDKG's defense-in-depth guard): %v", r)
	}()
	_ = committeeMaxCoalitionDriftBps(snap, live)
}

// rationalHalfTVbps recomputes the metric independently with big.Rat (a different code path)
// to catch any integer-arithmetic mistake in the keeper's formula.
func rationalHalfTVbps(snap, live []types.RoundMember) uint64 {
	wsnap, wlive := big.NewInt(0), big.NewInt(0)
	sm := map[string]*big.Int{}
	lm := map[string]*big.Int{}
	for _, m := range snap {
		w := m.Weight.BigInt()
		sm[m.OperatorAddr] = w
		wsnap.Add(wsnap, w)
	}
	for _, m := range live {
		w := m.Weight.BigInt()
		lm[m.OperatorAddr] = w
		wlive.Add(wlive, w)
	}
	if wsnap.Sign() <= 0 || wlive.Sign() <= 0 {
		return 0
	}
	ops := map[string]bool{}
	for k := range sm {
		ops[k] = true
	}
	for k := range lm {
		ops[k] = true
	}
	sum := new(big.Rat)
	for op := range ops {
		fs := new(big.Rat)
		if v, ok := sm[op]; ok {
			fs.SetFrac(v, wsnap)
		}
		fl := new(big.Rat)
		if v, ok := lm[op]; ok {
			fl.SetFrac(v, wlive)
		}
		d := new(big.Rat).Sub(fl, fs)
		d.Abs(d)
		sum.Add(sum, d)
	}
	// half * sum * 10000, floored.
	sum.Mul(sum, big.NewRat(10000, 2))
	q := new(big.Int).Quo(sum.Num(), sum.Denom())
	if q.Cmp(big.NewInt(10000)) > 0 {
		return 10000
	}
	return q.Uint64()
}

// TestC7_CouplingBreaksAtValidD is the headline finding probe: with a VALID
// DkgRekeyOnStakeDriftBps (Validate permits up to 10000), an ONLINE set holding > 2/3 of the
// LIVE committee stake can end up holding < t frozen eval points and be UNABLE to decrypt —
// the liveness coupling the feature exists to preserve, silently broken by a "valid" D that
// the measured drift never reaches. Demonstrated with the real AllocateEvalPoints/stakeThreshold.
func TestC7_CouplingBreaksAtValidD(t *testing.T) {
	const S = 128
	const epoch = 1
	// Snapshot fractions 0.30/0.30/0.40 (operator set {a,b,c}).
	snap := []types.RoundMember{rm("a", 30), rm("b", 30), rm("c", 40)}
	for i := range snap {
		snap[i].Index = uint64(i + 1)
	}
	alloc := AllocateEvalPoints(snap, S, epoch)
	tt, degraded := stakeThreshold(alloc)
	if degraded {
		t.Fatalf("unexpected degraded threshold")
	}
	// Online supermajority-by-LIVE-stake = {a,b}: live fractions become 0.40/0.40/0.20.
	live := []types.RoundMember{rm("a", 40), rm("b", 40), rm("c", 20)}
	drift := committeeMaxCoalitionDriftBps(snap, live) // 2000 bps

	// Points held by the online set {a,b} (frozen from the snapshot allocation).
	ptsAB := 0
	for _, m := range alloc {
		if m.OperatorAddr == "a" || m.OperatorAddr == "b" {
			ptsAB += len(m.OwnedEvalPoints())
		}
	}
	liveFracAB := 80.0 // % of live stake
	t.Logf("t=%d  drift=%d bps  online{a,b} live-stake=%.0f%%  online{a,b} frozen points=%d",
		tt, drift, liveFracAB, ptsAB)

	// A governance-VALID D that the drift never reaches (2000 < 2500) => NO rekey fires.
	validD := uint64(2500)
	if err := driftParams(validD).ValidateDkgWindows(); err != nil {
		t.Fatalf("D=%d must be a VALID config, got %v", validD, err)
	}
	if drift >= validD {
		t.Fatalf("precondition: drift %d should be < D %d (so no rekey fires)", drift, validD)
	}
	// The break: an 80%-live-stake online set holds < t points and CANNOT decrypt, yet the
	// drift (2000) is under the VALID threshold (2500) so the committee never re-snapshots.
	if ptsAB >= int(tt) {
		t.Fatalf("expected the liveness coupling to be BROKEN (online holds < t), but points=%d >= t=%d", ptsAB, tt)
	}
	t.Logf("CONFIRMED: valid D=%d bps tolerates a 2000-bps drift under which an 80%%-live-stake "+
		"online set holds %d < t=%d points and cannot decrypt (liveness coupling eroded, no rekey).", validD, ptsAB, tt)

	// For contrast: the liveness-preserving D is ~ n/S in bps = 3/128 ~ 234 bps, FAR below the
	// 10000 Validate ceiling. Show a D at/under that margin would have forced the rekey.
	tightD := uint64(200)
	if drift < tightD {
		t.Fatalf("sanity: a tight D=%d should be <= the 2000 drift", tightD)
	}
	t.Logf("A liveness-safe D here is ~%d bps (n/S); Validate permits up to 10000 with no warning.", 10000*3/S)
}

func driftParams(bps uint64) types.Params {
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 100, DecryptDelay: 2,
		DkgEnabled: true, DkgTransparent: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 5,
		DkgShareBudget: 128, DkgRekeyOnStakeDriftBps: bps,
	}
	return p
}
