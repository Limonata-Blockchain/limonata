package keeper_test

import (
	"testing"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// FLIPPED cycle-3 H-A e2e probe. The original proved END-TO-END that a governance-set
// budget S smaller than the committee size n (a config that PASSED the old Params.Validate)
// let a stake MINORITY reconstruct the epoch secret off-chain while the honest stake
// supermajority was locked out: with S<n and equal stake all Hamilton floors are 0 and all
// remainders equal, so the whole budget went to the FIRST S members by operator-address
// order — decryption power tracked ADDRESS ORDER, not stake.
//
// CLOSED on two independent layers, both asserted here:
//  1. Params.Validate now REJECTS the config (S=6 vs the 16-seat default cap violates
//     S >= MinShareBudgetPerMember*cap) — it can neither ship at genesis nor be voted in
//     (genesis ValidateGenesis and MsgUpdateParams share this validator).
//  2. Even FORCED into the store past validation (raw SetParams), the runtime
//     defense-in-depth clamps the committee to floor(S/MinShareBudgetPerMember) = 0 seats:
//     NO round opens at all — deterministic and loud — rather than a round whose
//     apportionment degenerates to operator-address order. No stake-blind allocation can
//     ever be produced, so the minority-reconstructs / supermajority-locked-out inversion
//     is structurally unreachable.
func TestReg_HA_BudgetBelowCommittee_Closed(t *testing.T) {
	const budget = 6 // S = 6 < committee (16): the auditors' reproduced config
	stakes := map[string]int64{}
	for _, op := range []string{"a00", "a01", "a02", "a03", "a04"} {
		stakes[op] = 100
	}
	for _, op := range []string{"b05", "b06", "b07", "b08", "b09", "b10", "b11", "b12", "b13", "b14", "b15"} {
		stakes[op] = 100
	}

	// LAYER 1 — the config is un-shippable and un-votable.
	p := transparentParams(0, 0)
	p.DkgShareBudget = budget
	if err := p.Validate(); err == nil {
		t.Fatal("H-A REGRESSION: S=6 with a 16-seat committee cap passed Params.Validate")
	}

	// LAYER 2 — forced past validation, the keeper refuses to form a degenerate committee.
	ops := make([]string, 0, len(stakes))
	for op := range stakes {
		ops = append(ops, op)
	}
	var vals []stakingtypes.Validator
	byOp := map[string]member{}
	for _, op := range ops {
		byOp[op] = newMember(op, "")
		vals = append(vals, bondedVal(op, stakes[op]))
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	if err := k.SetParams(ctx, p); err != nil { // raw write, bypasses Validate by design
		t.Fatal(err)
	}
	ann := make([]keeper.VEEntry, 0, len(ops))
	for _, op := range ops {
		ann = append(ann, keeper.VEEntry{Operator: op, VE: annVE(byOp[op])})
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)

	if got := k.ActiveMembers(ctx, p); len(got) != 0 {
		t.Fatalf("H-A REGRESSION: budget 6 formed a %d-member committee (must clamp to 0 — no seat can get %d points)",
			len(got), types.MinShareBudgetPerMember)
	}
	if !hasEvent(ctx, "encmempool_dkg_committee_clamped") {
		t.Fatal("H-A: the runtime refusal must be LOUD (encmempool_dkg_committee_clamped)")
	}

	k.EndBlockDKG(ctx.WithBlockHeight(1))
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("H-A REGRESSION: a round opened under the degenerate S<n config (stake-blind allocation reachable)")
	}
}
