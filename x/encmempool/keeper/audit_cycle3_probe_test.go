// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"sort"
	"testing"

	sdkmath "cosmossdk.io/math"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-3 ADVERSARIAL AUDIT PROBES — FLIPPED into regressions.
//
// These originally REPRODUCED the cycle-3 findings on 19d5cb6f (zero-weight eval-point
// collision stalling finalize = L-1; the S<n config hole re-opening HIGH-3 = H-A). They now
// assert the holes are CLOSED and must stay closed:
//   - a zero-weight member of a weighted committee owns NOTHING (no {Index} fallback, no
//     collision, TotalEvalPoints == S) and the round FINALIZES;
//   - Params.Validate REJECTS any transparent config whose budget cannot secure the
//     committee cap (S >= MinShareBudgetPerMember * cap), so the degenerate apportionment
//     regime can neither ship at genesis nor be voted in;
//   - the HIGH-3 closure holds at the LIVE default budget with the corrected threshold.
// ============================================================================

// TestReg_L1_ZeroWeightMemberOwnsNothing (flipped TestProbe_ZeroWeightMemberCollision):
// a Weight==0 (NOT nil) member sitting in a WEIGHTED committee is allocated ZERO eval
// points and must OWN ZERO points. Pre-fix, OwnedEvalPoints fell back to {Index} because
// the weight was not "positive", colliding with the point another member legitimately
// owned: TotalEvalPoints exceeded the budget, every dealing was rejected (duplicate
// enc-share), QUAL stayed empty and the round could NEVER finalize.
func TestReg_L1_ZeroWeightMemberOwnsNothing(t *testing.T) {
	members := []types.RoundMember{
		{Index: 1, OperatorAddr: "opA", Weight: sdkmath.ZeroInt()}, // bonded but zero tokens
		{Index: 2, OperatorAddr: "opB", Weight: sdkmath.NewInt(100)},
		{Index: 3, OperatorAddr: "opC", Weight: sdkmath.NewInt(100)},
	}
	out := keeper.AllocateEvalPoints(members, 24, 1)

	if len(out[0].EvalPoints) != 0 {
		t.Fatalf("zero-weight member should get an empty EvalPoints block, got %v", out[0].EvalPoints)
	}
	if owned := out[0].OwnedEvalPoints(); len(owned) != 0 {
		t.Fatalf("L-1 REGRESSION: zero-weight weighted member must own NOTHING, got %v", owned)
	}
	// No collision: every point in 1..S has exactly ONE owner.
	for pt := uint64(1); pt <= 24; pt++ {
		owners := 0
		for _, m := range out {
			if m.OwnsEvalPoint(pt) {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("L-1 REGRESSION: eval point %d has %d owners (want exactly 1)", pt, owners)
		}
	}
	// The domain invariant holds: TotalEvalPoints == the budget S exactly.
	if total := types.TotalEvalPoints(out); total != 24 {
		t.Fatalf("L-1 REGRESSION: TotalEvalPoints=%d, want the budget 24 exactly", total)
	}
	// And the flag survives what broke the nil-check design: a JSON store round-trip
	// (sdkmath.Int marshals nil as "0", erasing the nil-vs-zero distinction).
	rt := jsonRoundTripMembers(t, out)
	if owned := rt[0].OwnedEvalPoints(); len(owned) != 0 {
		t.Fatalf("L-1 REGRESSION: zero-weight member owns %v after a JSON round-trip", owned)
	}
	if total := types.TotalEvalPoints(rt); total != 24 {
		t.Fatalf("L-1 REGRESSION: TotalEvalPoints=%d after JSON round-trip, want 24", total)
	}
}

// TestReg_L1_ZeroWeightMemberFinalizes (flipped TestProbe_ZeroWeightMemberStallsFinalize):
// the FULL transparent keeper loop with one zero-token bonded validator in the committee
// must store every dealing and FINALIZE (install an active key). Pre-fix this stalled
// deterministically (0 dealings stored, round failed, no key — a chain-wide feature stall
// any single zero-token bonded validator could cause).
func TestReg_L1_ZeroWeightMemberFinalizes(t *testing.T) {
	stakes := map[string]int64{"opA": 0, "opB": 100, "opC": 100} // opA bonded with zero tokens
	ops := []string{"opA", "opB", "opC"}
	byOp := map[string]member{}
	var vals []stakingtypes.Validator
	for _, op := range ops {
		byOp[op] = newMember(op, "")
		vals = append(vals, bondedVal(op, stakes[op]))
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(0, 0)
	p.DkgShareBudget = 24 // 8 * the 3-seat committee (H-A coupling)
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	ann := make([]keeper.VEEntry, 0, len(ops))
	for _, op := range ops {
		ann = append(ann, keeper.VEEntry{Operator: op, VE: annVE(byOp[op])})
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok || round.Status != types.DkgStatusOpen {
		t.Fatalf("epoch 1 not opened: %+v", round)
	}
	// Confirm opA is a member with zero weight, owning zero points.
	zeroWeightPresent := false
	for _, m := range round.Members {
		if m.OperatorAddr == "opA" && !m.Weight.IsNil() && m.Weight.IsZero() {
			zeroWeightPresent = true
			if owned := m.OwnedEvalPoints(); len(owned) != 0 {
				t.Fatalf("L-1 REGRESSION: zero-weight committee member owns %v", owned)
			}
		}
	}
	if !zeroWeightPresent {
		t.Skip("zero-weight member not selected into committee; scenario not reproduced")
	}

	entries := make([]keeper.VEEntry, 0, len(round.Members))
	for _, rm := range round.Members {
		entries = append(entries, buildDealingEntry(t, round, byOp[rm.OperatorAddr]))
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), entries)

	stored := 0
	k.IterateDealings(ctx, 1, func(types.Dealing) { stored++ })
	if stored != len(round.Members) {
		t.Fatalf("L-1 REGRESSION: %d/%d dealings stored with a zero-weight member present (collision rejects dealings)",
			stored, len(round.Members))
	}

	k.EndBlockDKG(ctx.WithBlockHeight(int64(round.ComplaintDeadline)))
	if _, ok := k.GetActiveKey(ctx, 1); !ok {
		r, _ := k.GetDkgRound(ctx, 1)
		t.Fatalf("L-1 REGRESSION: round did not finalize with a zero-token bonded validator present (status=%s)", r.Status)
	}
}

// TestReg_HA_ValidateRejectsBudgetBelowCommitteeCap (flipped
// TestProbe_H3_BudgetBelowCommittee_Independent): the exact configs the cycle-3 auditors
// used to re-open HIGH-3 (S=6 with a 16-seat cap; S=24 with the 128-seat cap; S=256 with
// the 128-seat cap) must now FAIL Params.Validate — the same validator gates genesis
// (module.ValidateGenesis) and governance (MsgUpdateParams), so the hole can neither ship
// nor be voted in. Valid coupled configs must still pass.
func TestReg_HA_ValidateRejectsBudgetBelowCommitteeCap(t *testing.T) {
	base := func() types.Params {
		p := types.DefaultParams()
		p.EncEnabled = true
		p.DecryptDelay = 2
		p.DkgEnabled = true
		p.DkgTransparent = true
		return p
	}
	bad := []struct {
		name               string
		budget, maxMembers uint32
	}{
		{"S6_cap16_auditor_repro", 6, 0},     // the reproduced hole: t reachable by 31.2% stake
		{"S24_cap128", 24, 128},              // 13.28%-stake minority reached t=17 pre-fix
		{"S256_cap128", 256, 128},            // even the default budget cannot secure the max cap
		{"S127_cap16_boundary", 127, 0},      // one below the 8*16 coupling
		{"S4096_over_ve_bound", 4096, 128},   // M-2: budget above the VE-size-derived ceiling
		{"S2049_over_ve_bound_min", 2049, 0}, // M-2 boundary
	}
	for _, c := range bad {
		p := base()
		p.DkgShareBudget = c.budget
		p.DkgMaxMembers = c.maxMembers
		if err := p.Validate(); err == nil {
			t.Fatalf("H-A REGRESSION (%s): budget=%d cap=%d passed Validate — the degenerate-apportionment config hole is open",
				c.name, c.budget, c.maxMembers)
		}
	}
	good := []struct {
		name               string
		budget, maxMembers uint32
	}{
		{"defaults", 0, 0},              // 256 >= 8*16
		{"S128_cap16_boundary", 128, 0}, // exactly 8*16
		{"S1024_cap128", 1024, 128},     // exactly 8*128 — the full committee range stays usable
		{"S2048_cap128_max", 2048, 128}, // the M-2 budget ceiling itself is valid
	}
	for _, c := range good {
		p := base()
		p.DkgShareBudget = c.budget
		p.DkgMaxMembers = c.maxMembers
		if err := p.Validate(); err != nil {
			t.Fatalf("coupling over-rejects (%s): budget=%d cap=%d: %v", c.name, c.budget, c.maxMembers, err)
		}
	}
	// The coupling is transparent-path-only: the legacy/declared path is byte-identical.
	p := base()
	p.DkgTransparent = false
	p.DkgShareBudget = 6
	m := newMember("op1", "acc1")
	p.DkgMembers = []types.DkgMember{{OperatorAddr: m.op, AccountAddr: m.acc, EncPubKey: m.pub}}
	if err := p.Validate(); err != nil {
		t.Fatalf("legacy path must not be affected by the transparent coupling: %v", err)
	}
}

// TestReg_HA_RuntimeCommitteeClamp: defense-in-depth BENEATH validation — if an
// unvalidated store write smuggles in a budget the committee cap cannot be secured by
// (here S=24 against 16 candidates), the keeper CLAMPS the committee to
// floor(S/MinShareBudgetPerMember) top-stake seats before hashing/opening, so the
// apportionment regime S >= 8n holds at every round-open and allocation can never
// degenerate to operator-address order. Deterministic and loud, never a halt.
func TestReg_HA_RuntimeCommitteeClamp(t *testing.T) {
	var vals []stakingtypes.Validator
	byOp := map[string]member{}
	for i := 0; i < 16; i++ {
		op := "op" + string(rune('a'+i))
		byOp[op] = newMember(op, "")
		vals = append(vals, bondedVal(op, 100)) // equal stake — the degenerate case
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(0, 0)
	p.DkgShareBudget = 24 // INVALID vs the 16-seat cap (Validate would reject); forced via SetParams
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	for op, m := range byOp {
		k.RecordEncPubKey(ctx, op, m.pub, encPoP(m))
	}
	committee := k.ActiveMembers(ctx, p)
	if want := 24 / types.MinShareBudgetPerMember; len(committee) != want {
		t.Fatalf("H-A REGRESSION: committee not clamped to floor(S/%d)=%d seats, got %d",
			types.MinShareBudgetPerMember, want, len(committee))
	}
	if !hasEvent(ctx, "encmempool_dkg_committee_clamped") {
		t.Fatal("H-A: the runtime clamp must be LOUD (encmempool_dkg_committee_clamped)")
	}
	// The clamped committee allocates non-degenerately: with S=24 over 3 equal seats every
	// member owns exactly 8 points — capability tracks stake, not address order.
	alloc := keeper.AllocateEvalPoints(committee, 24, 1)
	for _, m := range alloc {
		if got := len(m.OwnedEvalPoints()); got != 8 {
			t.Fatalf("clamped committee must allocate 8 points/seat, %s got %d", m.OperatorAddr, got)
		}
	}
}

// TestProbe_H3_ProductionBudget256 re-verifies HIGH-3 closure at the LIVE default budget
// (S=256) with the corrected threshold t = floor(2S/3) - n + 1. A 1/3-stake seat-majority
// must hold < t points and be unable to reconstruct off-chain.
func TestProbe_H3_ProductionBudget256(t *testing.T) {
	stakes := map[string]int64{"honest_A": 5000, "honest_B": 5000}
	for i := 0; i < 5; i++ {
		stakes["attacker_"+string(rune('a'+i))] = 1000 // total attacker 5000 = 1/3 of 15000
	}
	c := runTransparentDKG(t, stakes, 256)
	// n=7 committee: t = floor(512/3) - 7 + 1 = 164.
	if want := uint32(2*256/3 - 7 + 1); c.ak.Threshold != want {
		t.Fatalf("expected t=%d for S=256, n=7, got %d", want, c.ak.Threshold)
	}
	attackers := opsWithPrefix(c, "attacker")
	if len(attackers) <= len(c.round.Members)/2 {
		t.Fatalf("precondition: attacker must be a seat majority, got %d/%d", len(attackers), len(c.round.Members))
	}
	plain := []byte("front-run me at production budget")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	pts, recovered := c.coalitionReconstructs(t, attackers, ct, plain)
	if recovered || pts >= int(c.ak.Threshold) {
		t.Fatalf("HIGH-3 REGRESSION at S=256: attacker holds %d/%d points, recovered=%v", pts, c.ak.Threshold, recovered)
	}
	t.Logf("S=256: 1/3-stake seat-majority (%d seats) holds %d < t=%d points; cannot reconstruct",
		len(attackers), pts, c.ak.Threshold)
}

// TestProbe_H3_SybilRemainderSeats probes whether a stake-MINORITY can inflate its eval-point
// count above the proportional share by SPLITTING into many tiny validators to farm
// largest-remainder "remainder seats" (each +1 point). It asserts the minority still holds < t.
func TestProbe_H3_SybilRemainderSeats(t *testing.T) {
	// One honest whale @ 5100 (51%) + 49 attacker dust @ 100 each (49%); the committee cap (16)
	// admits the whale + 15 dust.
	stakes := map[string]int64{"honest_whale": 5100}
	for i := 0; i < 49; i++ {
		stakes["attacker_"+string(rune('a'+i%26))+string(rune('a'+i/26))] = 100
	}
	c := runTransparentDKG(t, stakes, 256)
	attackers := opsWithPrefix(c, "attacker")
	honest := opsWithPrefix(c, "honest")
	as, hs := c.coalitionStake(attackers), c.coalitionStake(honest)
	if as >= hs {
		t.Fatalf("precondition: attacker must be stake minority, got %d>=%d", as, hs)
	}
	atkPts := 0
	for _, op := range attackers {
		atkPts += len(c.memberPoints(op))
	}
	t.Logf("attacker stake=%d/%d (%d seats) farmed %d eval points; t=%d",
		as, as+hs, len(attackers), atkPts, c.ak.Threshold)
	if atkPts >= int(c.ak.Threshold) {
		t.Fatalf("HIGH-3 REGRESSION: stake-minority Sybil farmed %d >= t=%d points", atkPts, c.ak.Threshold)
	}
	plain := []byte("sybil remainder-seat farming")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, recovered := c.coalitionReconstructs(t, attackers, ct, plain); recovered {
		t.Fatal("HIGH-3 REGRESSION: Sybil minority reconstructed off-chain")
	}
}

// TestProbe_WeightedRecoverDeterministicSurplus confirms the on-chain recover path is
// order/subset deterministic when MORE than t decryption shares are present: RecoverVerified
// combines a deterministic subset (first t by ascending eval-point index) and yields the same
// shared secret regardless of the order the shares were collected in — a fork-safety check.
func TestProbe_WeightedRecoverDeterministicSurplus(t *testing.T) {
	stakes := map[string]int64{"a": 1000, "b": 1000, "c": 1000, "d": 1000, "e": 1000}
	c := runTransparentDKG(t, stakes, 40) // 8 * the 5-seat committee (H-A coupling)
	plain := []byte("surplus shares must recover deterministically")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	// Everyone serves ALL their points => far more than t shares present.
	all := make([]string, 0)
	for _, m := range c.round.Members {
		all = append(all, m.OperatorAddr)
	}
	sort.Strings(all)
	pts, recovered := c.coalitionReconstructs(t, all, ct, plain)
	if !recovered || pts < int(c.ak.Threshold) {
		t.Fatalf("full committee must recover: points=%d t=%d recovered=%v", pts, c.ak.Threshold, recovered)
	}
	t.Logf("full committee served %d >= t=%d points; recovered deterministically", pts, c.ak.Threshold)
}

// jsonRoundTripMembers pushes members through the exact JSON store encoding a DkgRound uses
// (the round-trip that erases sdkmath.Int's nil-vs-zero distinction — the reason L-1 is
// fixed with an explicit Weighted flag instead of a Weight.IsNil() check).
func jsonRoundTripMembers(t *testing.T, in []types.RoundMember) []types.RoundMember {
	t.Helper()
	r := types.DkgRound{Epoch: 1, Members: in, Status: types.DkgStatusActive}
	k, ctx := newKeeperSK(t, 1, &mockStaking{})
	if err := k.SetDkgRound(ctx, r); err != nil {
		t.Fatal(err)
	}
	out, ok := k.GetDkgRound(ctx, 1)
	if !ok {
		t.Fatal("round-trip failed")
	}
	return out.Members
}
