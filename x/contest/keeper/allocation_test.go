package keeper

import (
	"testing"

	"cosmossdk.io/math"
)

func sum(allocs []Alloc) math.Int {
	t := math.ZeroInt()
	for _, a := range allocs {
		t = t.Add(a.Amount)
	}
	return t
}

func find(allocs []Alloc, addr string) math.Int {
	for _, a := range allocs {
		if a.Address == addr {
			return a.Amount
		}
	}
	return math.ZeroInt()
}

// Clean pro-rata with no remainder.
func TestDistributeProRata(t *testing.T) {
	pts := map[string]uint64{"alice": 1, "bob": 3}
	budget := math.NewInt(100)
	out := distribute(pts, budget, "developer")
	if !find(out, "alice").Equal(math.NewInt(25)) {
		t.Fatalf("alice expected 25, got %s", find(out, "alice"))
	}
	if !find(out, "bob").Equal(math.NewInt(75)) {
		t.Fatalf("bob expected 75, got %s", find(out, "bob"))
	}
	if !sum(out).Equal(budget) {
		t.Fatalf("conservation: sum %s != budget %s", sum(out), budget)
	}
}

// Remainder must be fully assigned (budget conserved exactly) to the top-points address.
func TestDistributeRemainderConserved(t *testing.T) {
	pts := map[string]uint64{"a": 1, "b": 1, "c": 1}
	budget := math.NewInt(100) // 100/3 = 33 each -> running 99, remainder 1
	out := distribute(pts, budget, "tester")
	if !sum(out).Equal(budget) {
		t.Fatalf("remainder lost: sum %s != %s", sum(out), budget)
	}
	// "a" sorts first and is the (tie) top -> gets the +1 remainder.
	if !find(out, "a").Equal(math.NewInt(34)) {
		t.Fatalf("a expected 34 (33+remainder), got %s", find(out, "a"))
	}
}

// Determinism: identical inputs (any map order) produce identical, sorted output.
func TestDistributeDeterministic(t *testing.T) {
	mk := func() map[string]uint64 { return map[string]uint64{"z": 5, "a": 2, "m": 3} }
	budget := math.NewInt(1_000_000)
	a := distribute(mk(), budget, "developer")
	b := distribute(mk(), budget, "developer")
	if len(a) != len(b) {
		t.Fatalf("length mismatch")
	}
	for i := range a {
		if a[i].Address != b[i].Address || !a[i].Amount.Equal(b[i].Amount) {
			t.Fatalf("nondeterministic at %d: %v vs %v", i, a[i], b[i])
		}
	}
	// sorted by address
	if a[0].Address != "a" || a[1].Address != "m" || a[2].Address != "z" {
		t.Fatalf("not sorted by address: %s,%s,%s", a[0].Address, a[1].Address, a[2].Address)
	}
	if !sum(a).Equal(budget) {
		t.Fatalf("conservation failed: %s", sum(a))
	}
}

// Empty / zero-budget guards.
func TestDistributeEdges(t *testing.T) {
	if distribute(map[string]uint64{}, math.NewInt(100), "developer") != nil {
		t.Fatal("no points -> nil")
	}
	if distribute(map[string]uint64{"a": 1}, math.ZeroInt(), "developer") != nil {
		t.Fatal("zero budget -> nil")
	}
}
