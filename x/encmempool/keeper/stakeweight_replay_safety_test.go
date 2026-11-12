// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

// EXPLICIT NUMERIC REPLAY-SAFETY TEST for the v0.3.6 DkgStrictConcentration gate.
//
// stakeThreshold's result is written to committed state (ActiveThresholdKey.Threshold) at every
// DKG finalization. Live testnet 10777 finalized ~16 epochs under the LEGACY formula
// t = floor(2S/3)+1. The v0.3.6 gate MUST therefore reproduce that legacy formula BYTE-FOR-BYTE
// when strict==false, or replaying historical blocks recomputes a different threshold -> app-hash
// divergence -> broken sync-from-genesis / state sync. This test pins that invariant numerically
// across a broad topology sweep so a future refactor of the weighted path cannot silently move the
// gate-off value, and it directly pins the default-topology transition gate-off=171 -> gate-on=186.

import (
	"fmt"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/types"
)

// buildWeightedS constructs a WEIGHTED committee of n members owning exactly S eval points in
// total (distinct point ids 1..S handed out round-robin) so that TotalEvalPoints == S and the
// weighted branch of stakeThreshold is exercised. When S < n the trailing members own zero points
// but are still flagged Weighted (which is all it takes to select the weighted path). The concrete
// eval-point assignment is irrelevant to the threshold: stakeThreshold is a pure function of S and
// n only, which is exactly the surface a replay must not perturb.
func buildWeightedS(n, S int) []types.RoundMember {
	ms := make([]types.RoundMember, n)
	for i := range ms {
		ms[i] = types.RoundMember{
			Index:        uint64(i + 1),
			OperatorAddr: fmt.Sprintf("cosmosvaloper1replay%04d", i),
			Weight:       sdkmath.NewInt(1),
			Weighted:     true,
		}
	}
	for p := 1; p <= S; p++ {
		i := (p - 1) % n
		ms[i].EvalPoints = append(ms[i].EvalPoints, uint64(p))
	}
	return ms
}

// legacyThreshold is the pre-v0.3.6 reference: t = floor(2S/3)+1, with the SAME clamps the
// production code applies (never above S, never below 1). Computed independently here so the test
// fails if the production weighted gate-off path ever drifts from this exact arithmetic.
func legacyThreshold(S int) int {
	tt := (2*S)/3 + 1
	if tt > S {
		tt = S
	}
	if tt < 1 {
		tt = 1
	}
	return tt
}

// TestStakeThreshold_ReplaySafety_LegacyFormulaUnchanged sweeps S=1..2000 across
// n in {1,2,3,4,8,16,32,64} and asserts stakeThreshold(members,false) == floor(2S/3)+1 exactly.
// This is the #1 correctness requirement for the gate: gate-off MUST be byte-identical to the
// formula that produced ~16 historical DKG finalizations on the live chain.
func TestStakeThreshold_ReplaySafety_LegacyFormulaUnchanged(t *testing.T) {
	nset := []int{1, 2, 3, 4, 8, 16, 32, 64}
	checked := 0
	for _, n := range nset {
		for S := 1; S <= 2000; S++ {
			members := buildWeightedS(n, S)
			if got := types.TotalEvalPoints(members); got != S {
				t.Fatalf("builder bug: n=%d S=%d TotalEvalPoints=%d (want %d)", n, S, got, S)
			}
			gotT, degraded := stakeThreshold(members, false) // strict OFF == legacy replay path
			want := legacyThreshold(S)
			if int(gotT) != want {
				t.Fatalf("REPLAY-SAFETY BREAK: stakeThreshold(strict=false) n=%d S=%d = %d, "+
					"legacy floor(2S/3)+1 = %d. Gate-off is no longer byte-identical to the "+
					"formula historical blocks were finalized under -> app-hash divergence on replay.",
					n, S, gotT, want)
			}
			if degraded {
				t.Fatalf("legacy gate-off path unexpectedly reported degraded at n=%d S=%d", n, S)
			}
			checked++
		}
	}
	t.Logf("replay-safety: %d (n,S) topologies all match legacy t=floor(2S/3)+1 with strict=false", checked)
}

// TestStakeThreshold_DefaultTopology_GateOff171_GateOn186 pins the concrete transition at the
// live default topology S=256, n=16: gate-off must be 171 (floor(2*256/3)+1, the value stored in
// the live ActiveThresholdKey) and gate-on must be 186 (floor(2*256/3)+16). This is the exact
// number the devnet upgrade rehearsal must observe flip in committed state.
func TestStakeThreshold_DefaultTopology_GateOff171_GateOn186(t *testing.T) {
	const S, n = 256, 16
	members := buildWeightedS(n, S)
	if got := types.TotalEvalPoints(members); got != S {
		t.Fatalf("builder bug: TotalEvalPoints=%d (want %d)", got, S)
	}
	off, degOff := stakeThreshold(members, false)
	on, degOn := stakeThreshold(members, true)
	if off != 171 {
		t.Fatalf("gate-off threshold = %d, want 171 (floor(2*256/3)+1)", off)
	}
	if on != 186 {
		t.Fatalf("gate-on threshold = %d, want 186 (floor(2*256/3)+16)", on)
	}
	if degOff || degOn {
		t.Fatalf("unexpected degraded flag: off=%v on=%v", degOff, degOn)
	}
	t.Logf("S=256 n=16: gate-off t=%d -> gate-on t=%d (+n confidentiality raise = %d)", off, on, on-off)
}
