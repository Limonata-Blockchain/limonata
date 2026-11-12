package keeper

import "testing"

func TestComputeKPIs_Balanced(t *testing.T) {
	powers := make([]int64, 16)
	for i := range powers {
		powers[i] = 100 // each 6.25%
	}
	isF := make([]bool, 16)
	isF[0] = true // foundation runs one validator
	active, nak, fbps, topbps, total := computeKPIs(powers, isF)
	if active != 16 || total != 1600 {
		t.Fatalf("active/total = %d/%d", active, total)
	}
	if nak != 6 { // 6*100=600 > 1600/3=533.3
		t.Fatalf("nakamoto=%d want 6", nak)
	}
	if topbps != 625 {
		t.Fatalf("topBps=%d want 625", topbps)
	}
	if fbps != 625 {
		t.Fatalf("foundationBps=%d want 625 (one validator @6.25%%)", fbps)
	}
}

func TestComputeKPIs_Whale(t *testing.T) {
	active, nak, fbps, topbps, total := computeKPIs([]int64{920, 80}, []bool{false, false})
	if active != 2 || total != 1000 {
		t.Fatalf("active/total = %d/%d", active, total)
	}
	if nak != 1 { // the whale alone exceeds 1/3 -> can halt
		t.Fatalf("nakamoto=%d want 1", nak)
	}
	if topbps != 9200 {
		t.Fatalf("topBps=%d want 9200", topbps)
	}
	if fbps != 0 {
		t.Fatalf("foundationBps=%d want 0", fbps)
	}
}

func TestComputeKPIs_FoundationShare(t *testing.T) {
	// foundation runs validators 0 and 1 (300+200 of total 1000 = 50%)
	powers := []int64{300, 200, 100, 100, 100, 100, 100}
	isF := []bool{true, true, false, false, false, false, false}
	_, _, fbps, _, total := computeKPIs(powers, isF)
	if total != 1000 {
		t.Fatalf("total=%d", total)
	}
	if fbps != 5000 {
		t.Fatalf("foundationBps=%d want 5000", fbps)
	}
}

func TestComputeKPIs_Empty(t *testing.T) {
	active, nak, fbps, topbps, total := computeKPIs(nil, nil)
	if active != 0 || nak != 0 || fbps != 0 || topbps != 0 || total != 0 {
		t.Fatalf("empty must be all zero: %d %d %d %d %d", active, nak, fbps, topbps, total)
	}
}
