package keeper

import (
	"reflect"
	"testing"
)

func sumI(a []int64) int64 {
	var s int64
	for _, x := range a {
		s += x
	}
	return s
}

// maxShareBps = the largest entry's share of the total, in basis points.
func maxShareBps(a []int64) int64 {
	t := sumI(a)
	if t == 0 {
		return 0
	}
	var m int64
	for _, x := range a {
		if x > m {
			m = x
		}
	}
	return m * 10000 / t
}

// Balanced set (each below the cap) is returned unchanged.
func TestCapPowers_BalancedUnchanged(t *testing.T) {
	raw := make([]int64, 16)
	for i := range raw {
		raw[i] = 100 // each = 6.25% < 10%
	}
	got := capPowers(raw, 1000) // 10%
	if !reflect.DeepEqual(got, raw) {
		t.Fatalf("balanced set should be unchanged, got %v", got)
	}
	if s := maxShareBps(got); s > 1000 {
		t.Fatalf("max share %d bps exceeds cap", s)
	}
}

// Feasible whale (enough other validators to dilute): whale capped to <=10%,
// small validators untouched.
func TestCapPowers_FeasibleWhaleCapped(t *testing.T) {
	raw := []int64{5000}
	for i := 0; i < 19; i++ {
		raw = append(raw, 100)
	}
	got := capPowers(raw, 1000)
	if s := maxShareBps(got); s > 1000 {
		t.Fatalf("feasible set: max share %d bps must be <= 1000", s)
	}
	if got[0] >= raw[0] {
		t.Fatalf("whale must be reduced: %d -> %d", raw[0], got[0])
	}
	for i := 1; i < len(got); i++ {
		if got[i] != 100 {
			t.Fatalf("small validator %d (below cap) must be untouched, got %d", i, got[i])
		}
	}
}

// Two validators, online 90 / offline 10, cap 80%: online converges to 80% of
// total (= 40/50), so it stays above 2/3 and a single node keeps the chain live.
func TestCapPowers_TwoValidatorsStayLive(t *testing.T) {
	got := capPowers([]int64{90, 10}, 8000)
	if s := maxShareBps(got); s > 8000 {
		t.Fatalf("max share %d bps must be <= 8000", s)
	}
	if got[0] >= 90 {
		t.Fatalf("online validator must be capped from 90, got %d", got[0])
	}
	if got[1] != 10 {
		t.Fatalf("offline (below cap) must be untouched, got %d", got[1])
	}
	if got[0]*3 <= sumI(got) { // online must keep > 1/3 so the chain can finalize
		t.Fatalf("online share dropped to/below 1/3 -> liveness risk: %v", got)
	}
}

// Infeasible set (too few validators for the cap): must still TERMINATE,
// shrink the whale, never floor below 1, and be deterministic.
func TestCapPowers_InfeasibleWhaleTerminates(t *testing.T) {
	in := []int64{9000, 50, 50}
	got := capPowers(in, 1000)
	if got[0] >= 9000 {
		t.Fatalf("whale must be reduced, got %d", got[0])
	}
	for i, v := range got {
		if v < 1 {
			t.Fatalf("entry %d floored below 1 (would unbond): %d", i, v)
		}
	}
	again := capPowers(in, 1000)
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("non-deterministic: %v vs %v", got, again)
	}
}

// A positive validator is never driven to 0 (that would unbond it in CometBFT's
// view while staking still considers it bonded).
func TestCapPowers_FloorNoUnbond(t *testing.T) {
	got := capPowers([]int64{1000000, 1}, 1000)
	for i, v := range got {
		if v < 1 {
			t.Fatalf("entry %d driven below 1: %d", i, v)
		}
	}
}

func TestCapPowers_Empty(t *testing.T) {
	if got := capPowers(nil, 1000); len(got) != 0 {
		t.Fatalf("empty input -> empty output, got %v", got)
	}
}
