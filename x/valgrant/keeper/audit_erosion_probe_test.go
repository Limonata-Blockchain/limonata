package keeper

import (
	"testing"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// HIGH-ERODE - the grantee must NOT be able to erase the grant's clawback-able
// share count by cycling their OWN liquid through grant.ValidatorOp.
//
// The pre-fix reconcileGrantShares attributed EVERY decrease at
// grant.ValidatorOp to the grant FIRST and NEVER re-increased GrantedShares, so
// the sequence
//
//	grant 1000  ->  self-bond 1000 OWN  ->  unbond that same OWN 1000
//
// drove GrantedShares 1000 -> 1000 -> 0 while the foundation's 1000 was still
// bonded at grant.ValidatorOp. A later clawback then reclaimed NOTHING.
//
// These probes drive the REAL hooks (addDelegationHook / unbondHook invoke the
// actual AfterDelegationModified / BeforeDelegationRemoved code), so what they
// measure is the ledger the clawback truly reads.
// ===========================================================================

// unbondHook removes `shares` from (del, valBech) at the current exchange rate
// and fires the staking hooks exactly as x/staking's Unbond does (AfterDelegationModified
// on a partial unbond, BeforeDelegationRemoved when the delegation is emptied).
// It models the GRANTEE undelegating - the mock's Undelegate() models the MODULE's
// clawback undelegation and deliberately does not fire hooks.
func (m *mockStakingKeeper) unbondHook(ctx sdk.Context, del sdk.AccAddress, valBech string, shares math.LegacyDec) math.Int {
	d := m.get(del, valBech)
	if d == nil {
		return math.ZeroInt()
	}
	if shares.GTE(d.shares) {
		returned := d.tokens
		m.fireBeforeRemoved(ctx, del, valBech)
		delete(m.dels[string(del.Bytes())], valBech)
		return returned
	}
	returned := shares.MulInt(d.tokens).Quo(d.shares).TruncateInt()
	d.shares = d.shares.Sub(shares)
	d.tokens = d.tokens.Sub(returned)
	m.fireAfterModified(ctx, del, valBech)
	return returned
}

// EROSION, the plain sequence. Grant 1000 at grant.ValidatorOp; the grantee
// self-bonds 1000 of their OWN liquid at the same validator (merged 2000), then
// withdraws exactly that own 1000. The foundation's 1000 never moved, so
// GrantedShares MUST still be 1000 and the clawback MUST still reclaim 1000.
func TestGrantErosion_SelfBondThenWithdrawOwn_GrantSurvives(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr

	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000)) // module-placed grant

	// 1. the grantee commingles 1000 of their OWN liquid at grant.ValidatorOp.
	f.sk.addDelegationHook(f.ctx, f.granteeBz, vGrant, math.NewInt(1000))
	if g, _ := f.k.GetGrant(f.ctx, f.granteeStr); !parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("after own self-bond: GrantedShares=%q want 1000", g.GrantedShares)
	}

	// 2. the grantee withdraws exactly their OWN 1000 back out.
	f.sk.unbondHook(f.ctx, f.granteeBz, vGrant, math.LegacyNewDec(1000))

	live := f.sk.sharesOf(f.granteeBz, vGrant)
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	t.Logf("erosion sequence: live shares at grant.ValidatorOp=%s  GrantedShares=%q", live, g.GrantedShares)

	if !live.Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("live shares at grant.ValidatorOp=%s want 1000 (the foundation principal never moved)", live)
	}
	if !parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("GrantedShares=%q want 1000: the foundation's 1000 is STILL bonded here; "+
			"only the grantee's own money came and went", g.GrantedShares)
	}

	// 3. and the clawback must actually reclaim it.
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("PrincipalPending=%q want 1000 (the whole foundation principal is reclaim-able)", resp.PrincipalPending)
	}
}

// EROSION, the repeated (grind) form: the grantee cycles their own liquid in and
// out N times. Every cycle used to shave 1000 off GrantedShares; the first cycle
// alone zeroed it. The ledger must be invariant under the cycle.
func TestGrantErosion_RepeatedCycles_LedgerInvariant(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr

	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000))

	for i := 0; i < 5; i++ {
		f.sk.addDelegationHook(f.ctx, f.granteeBz, vGrant, math.NewInt(250))
		f.sk.unbondHook(f.ctx, f.granteeBz, vGrant, math.LegacyNewDec(250))
	}

	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if !parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("GrantedShares=%q want 1000 after 5 in/out cycles of the grantee's OWN funds", g.GrantedShares)
	}
}

// The ledger must stay in step with the SDK's OWN vesting bucketing. The grantee
// self-bonds 1000 own on top of the 1000 grant, then unbonds 1500 - dipping 500
// into the foundation principal. x/auth's TrackUndelegation charges the FREE
// bucket first (x := min(DelegatedFree, D)), so the SDK re-locks 500 in-account
// and still counts 500 as locked-delegated. The per-validator ledger must agree:
// GrantedShares 500 at grant.ValidatorOp, and the clawback recovers the whole
// 1000 (500 bonded + 500 swept in-account).
func TestGrantErosion_PartialDipIntoPrincipal_MatchesVestingBucketing(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr

	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000))

	f.sk.addDelegationHook(f.ctx, f.granteeBz, vGrant, math.NewInt(1000)) // own 1000 -> merged 2000
	f.sk.unbondHook(f.ctx, f.granteeBz, vGrant, math.LegacyNewDec(1500))  // own 1000 + 500 of the grant

	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if !parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(500)) {
		t.Fatalf("GrantedShares=%q want 500 (the SDK's free-first TrackUndelegation leaves 500 locked-delegated)", g.GrantedShares)
	}
}
