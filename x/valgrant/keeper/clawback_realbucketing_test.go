package keeper

import (
	"testing"
	"time"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// HIGH-B (deferred sweep) — REAL vesting bucketing.
//
// The cycle-4 deferred-sweep tests hand-set the PLVA's LockedCoins with
// DelegatedVesting=0, so they never exercised the SDK's FREE-FIRST
// TrackUndelegation and hid the orphaning regression. These probes instead drive
// the ACTUAL SDK vesting methods (PermanentLockedAccount.TrackDelegation for the
// grant-then-self-bond delegation order, then BaseVestingAccount.TrackUndelegation
// for the return) so DelegatedVesting / DelegatedFree — and therefore LockedCoins
// — match on-chain reality. On the OLD (LockedCoins-capped) sweep these tests
// FAIL (pool receives 0 / a fraction, principal orphaned to the grantee); on the
// FIX they PASS (the full recorded reclaim reaches the pool, gas + own self-bond
// preserved byte-exact).
// ===========================================================================

// realisticGrantPLVA builds the grantee as a PermanentLockedAccount and drives the
// SDK's REAL vesting bucketing for the on-chain delegation ORDER: the module bonds
// the LOCKED grant first at issuance (grantBonded), then the grantee self-bonds
// their OWN free funds (freeBonded). This fills DelegatedVesting=grantBonded and
// DelegatedFree=freeBonded exactly as x/staking would — NOT hand-set — so
// LockedCoins is authentic. Returns the PLVA.
func realisticGrantPLVA(t *testing.T, f *fixture, origVesting, grantBonded, freeBonded int64) *vestingtypes.PermanentLockedAccount {
	t.Helper()
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(origVesting))))
	if err != nil {
		t.Fatal(err)
	}
	bt := f.ctx.BlockTime()
	// (1) LOCKED grant delegation first: fills DelegatedVesting (X := min(max(V-DV,0),D)).
	if grantBonded > 0 {
		bal := sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(origVesting)))
		plva.TrackDelegation(bt, bal, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(grantBonded))))
	}
	// (2) OWN free self-bond after: the vesting bucket is already full so it fills
	// DelegatedFree (Y := D - X). This is the commingle that TrackUndelegation later
	// drains FIRST, mis-bucketing the returned grant principal as spendable.
	if freeBonded > 0 {
		bal := sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(origVesting+freeBonded)))
		plva.TrackDelegation(bt, bal, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(freeBonded))))
	}
	f.ak.SetAccount(f.ctx, plva)
	return plva
}

// completeUnbondingReturn models x/staking CompleteUnbonding returning `amt`
// reclaimed tokens to the grantee at maturity: it credits the spendable balance
// AND applies the SDK's REAL free-first TrackUndelegation to the PLVA (the exact
// step that re-buckets a commingled reclaim as spendable and makes LockedCoins
// under-report). Bucketing is a no-op once the account is a plain BaseAccount.
func (f *fixture) completeUnbondingReturn(t *testing.T, amt int64) {
	t.Helper()
	coins := sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(amt)))
	f.bank.add(f.granteeBz, coins)
	if plva, ok := f.ak.GetAccount(f.ctx, f.granteeBz).(*vestingtypes.PermanentLockedAccount); ok {
		plva.TrackUndelegation(coins)
		f.ak.SetAccount(f.ctx, plva)
	}
}

func (f *fixture) lockedCoins(t *testing.T) math.Int {
	t.Helper()
	acc := f.ak.GetAccount(f.ctx, f.granteeBz)
	if plva, ok := acc.(*vestingtypes.PermanentLockedAccount); ok {
		return plva.LockedCoins(f.ctx.BlockTime()).AmountOf(testDenom)
	}
	return math.ZeroInt()
}

func (f *fixture) sweepAfterUnbonding(t *testing.T) sdk.Context {
	t.Helper()
	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	return afterCtx
}

// captureBlock runs the deferred sweep at a PRE-maturity block time (a block during
// the unbonding window). The clawback is not yet mature, so the sweep only CAPTURES
// each tracked entry's live, re-slash-aware Balance into ResolvedBalance — it must
// not sweep or delete anything. This is the block the real chain runs every ~2s; a
// re-slash landing before it is reflected in the captured value (HIGH-C).
func (f *fixture) captureBlock(t *testing.T, at time.Time) {
	t.Helper()
	if err := f.k.SweepMaturedClawbacks(f.ctx.WithBlockTime(at)); err != nil {
		t.Fatalf("capture-block sweep errored: %v", err)
	}
}

// matureAndReturn models x/staking's EndBlock at maturity: it completes every matured
// unbonding entry at valBech (removing it) and credits the returned Balance to the
// grantee's account with the SDK's real free-first TrackUndelegation — exactly what
// CompleteUnbonding does. Returns the amount actually returned (re-slash-aware).
func (f *fixture) matureAndReturn(t *testing.T, valBech string, at time.Time) math.Int {
	t.Helper()
	returned := f.sk.completeMaturedUBD(f.granteeBz, valBech, at)
	if returned.IsPositive() {
		f.completeUnbondingReturn(t, returned.Int64())
	}
	return returned
}

// CO-LOCATED, NO SLASH — the structural norm: the grant (1000) and the grantee's
// OWN 1000 self-bond are commingled in ONE delegation at grant.ValidatorOp. The
// gov clawback undelegates the 1000 locked shares; at maturity CompleteUnbonding
// returns 1000 bucketed FREE-FIRST (DelegatedFree 1000->0, DelegatedVesting stays
// 1000) so LockedCoins reads 0. The OLD sweep capped at LockedCoins=0 and orphaned
// the full 1000 to the grantee; the FIX delivers all 1000 to the pool.
func TestDeferredSweep_Colocated_NoSlash_RealBucketing_FullReclaim(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 1000) // DelegatedVesting=1000, DelegatedFree=1000
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(50))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000)) // merged 1000 grant + 1000 own

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" || resp.PrincipalReturned != "0" {
		t.Fatalf("pending/returned = %s/%s want 1000/0", resp.PrincipalPending, resp.PrincipalReturned)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(1000)) {
		t.Fatalf("own self-bond seized: %s want 1000", f.sk.tokensOf(f.granteeBz, f.valStr))
	}

	// unbonding matures: 1000 returns, mis-bucketed as spendable (LockedCoins -> 0).
	f.completeUnbondingReturn(t, 1000)
	if !f.lockedCoins(t).IsZero() {
		t.Fatalf("setup invariant: LockedCoins=%s want 0 (returned principal mis-bucketed FREE)", f.lockedCoins(t))
	}

	afterCtx := f.sweepAfterUnbonding(t)

	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want 1000 (FULL reclaim to pool; old LockedCoins cap orphaned it to 0)", pool)
	}
	if !liquid.Equal(math.NewInt(50)) {
		t.Fatalf("grantee liquid=%s want 50 (gas preserved byte-exact)", liquid)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
	if _, stillVesting := f.ak.GetAccount(afterCtx, f.granteeBz).(*vestingtypes.PermanentLockedAccount); stillVesting {
		t.Fatal("PLVA not unlocked after sweeping principal")
	}
}

// CO-LOCATED, CAP 40% SLASH — the MISSION's proven-failing case ("co-located CAP
// 40% -> pool got 0"). Merged 2000 shares slashed to 1200 tokens. The clawback
// reclaims the fair slashed value of the 1000 locked shares (600); CompleteUnbonding
// returns 600 bucketed FREE-FIRST (DelegatedFree 1000->400, DelegatedVesting 1000)
// so LockedCoins=0. FIX: the pool receives the full 600 fair value; the grantee's
// own self-bond (1000 sh / 600 tok) and 50 gas are preserved byte-exact.
func TestDeferredSweep_Colocated_Slash40_RealBucketing_FullReclaim(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 1000)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(50))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000))
	f.sk.slash(f.granteeBz, f.valStr, math.NewInt(1200)) // 40% slash

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil-slashed"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "600" {
		t.Fatalf("pending=%s want 600 (fair slashed value of the 1000 locked shares)", resp.PrincipalPending)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(600)) || !f.sk.sharesOf(f.granteeBz, f.valStr).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("own self-bond seized: tok=%s sh=%s want 600/1000", f.sk.tokensOf(f.granteeBz, f.valStr), f.sk.sharesOf(f.granteeBz, f.valStr))
	}

	f.completeUnbondingReturn(t, 600)
	if !f.lockedCoins(t).IsZero() {
		t.Fatalf("setup invariant: LockedCoins=%s want 0", f.lockedCoins(t))
	}

	afterCtx := f.sweepAfterUnbonding(t)
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(600)) {
		t.Fatalf("pool=%s want 600 (full fair reclaim; mission case old-code orphaned to 0)", pool)
	}
	if !liquid.Equal(math.NewInt(50)) {
		t.Fatalf("grantee liquid=%s want 50 (gas preserved byte-exact)", liquid)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(600)) {
		t.Fatalf("own self-bond changed post-sweep: %s want 600", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
}

// SEPARATE / CROSS — the grant is bonded at grant.ValidatorOp (vGrant) and the
// grantee's OWN 1000 self-bond is at a DIFFERENT validator (vOther). The
// account-global vesting buckets are still DV=1000 (grant) / DF=1000 (own), so the
// returned grant is mis-bucketed FREE-FIRST just the same. FIX: full 1000 to pool,
// the own self-bond at vOther untouched, gas preserved.
func TestDeferredSweep_Separate_RealBucketing_FullReclaim(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr
	vOther := valoper(0x55)
	realisticGrantPLVA(t, f, 1000, 1000, 1000) // DV=1000, DF=1000 (account-global)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(50))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000)) // grant at grant.ValidatorOp
	f.sk.delegate(f.granteeBz, vOther, math.NewInt(1000)) // OWN self-bond elsewhere

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("pending=%s want 1000", resp.PrincipalPending)
	}
	if !f.sk.tokensOf(f.granteeBz, vOther).Equal(math.NewInt(1000)) {
		t.Fatalf("own self-bond at vOther touched: %s want 1000", f.sk.tokensOf(f.granteeBz, vOther))
	}

	f.completeUnbondingReturn(t, 1000)
	if !f.lockedCoins(t).IsZero() {
		t.Fatalf("setup invariant: LockedCoins=%s want 0", f.lockedCoins(t))
	}

	afterCtx := f.sweepAfterUnbonding(t)
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want 1000 (full reclaim; old code orphaned it)", pool)
	}
	if !liquid.Equal(math.NewInt(50)) {
		t.Fatalf("grantee liquid=%s want 50 (gas preserved)", liquid)
	}
	if !f.sk.tokensOf(f.granteeBz, vOther).Equal(math.NewInt(1000)) {
		t.Fatalf("own self-bond at vOther seized by sweep: %s want 1000", f.sk.tokensOf(f.granteeBz, vOther))
	}
}

// PURE-LOCKED — no free self-bond (DelegatedFree=0). TrackUndelegation drains
// DelegatedVesting (there is no free bucket to drain first), so the return is
// correctly RE-LOCKED (LockedCoins=1000). This case was already correct on the old
// code; it is a regression guard that the FIX (which unlocks before sending) still
// delivers the full principal and preserves gas.
func TestDeferredSweep_PureLocked_RealBucketing_FullReclaim(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 0) // DV=1000, DF=0
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(50))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("pending=%s want 1000", resp.PrincipalPending)
	}

	f.completeUnbondingReturn(t, 1000)
	if !f.lockedCoins(t).Equal(math.NewInt(1000)) {
		t.Fatalf("setup invariant: LockedCoins=%s want 1000 (pure-vesting return re-locks correctly)", f.lockedCoins(t))
	}

	afterCtx := f.sweepAfterUnbonding(t)
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want 1000 (full principal)", pool)
	}
	if !liquid.Equal(math.NewInt(50)) {
		t.Fatalf("grantee liquid=%s want 50 (gas preserved)", liquid)
	}
	if _, stillVesting := f.ak.GetAccount(afterCtx, f.granteeBz).(*vestingtypes.PermanentLockedAccount); stillVesting {
		t.Fatal("PLVA not unlocked after sweeping locked principal")
	}
}

// RE-SLASH SHORTFALL + REAL BUCKETING — the recorded reclaim (300) exceeds what
// CompleteUnbonding actually returns after a re-slash during the unbonding window
// (200), and that 200 is mis-bucketed FREE (LockedCoins=0). The sweep credits the
// pool EXACTLY the tracked unbonding entry's re-slashed matured Balance (200) — read
// from x/staking, NOT the pre-recorded 300, NOT a LockedCoins cap (which reads 0),
// NOT (balance - gas) — leaving the grantee's 10 gas byte-exact (HIGH-C).
func TestDeferredSweep_ReslashShortfall_RealBucketing_EntryBalanceNotRecorded(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 300, 300, 300)                                        // commingled: DV=300 (grant), DF=300 (own)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(10)))) // 10 liquid gas
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "300", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "300", TrackedShares: "600"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(600)) // merged 300 grant + 300 own

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "300" {
		t.Fatalf("recorded reclaim=%s want 300", resp.PrincipalPending)
	}

	// A re-slash during unbonding drops the entry Balance 300 -> 200; a capture block
	// records it; maturity returns only 200 (mis-bucketed FREE, LockedCoins -> 0).
	f.sk.reslashUBD(f.granteeBz, f.valStr, math.NewInt(200))
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(200)) {
		t.Fatalf("returned=%s want 200", got)
	}
	if !f.lockedCoins(t).IsZero() {
		t.Fatalf("setup invariant: LockedCoins=%s want 0", f.lockedCoins(t))
	}

	after := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(after); err != nil {
		t.Fatalf("sweep errored: %v", err)
	}
	pool := f.bank.GetBalance(after, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(after, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(200)) {
		t.Fatalf("pool=%s want 200 (re-slashed entry Balance; NOT 300 recorded, NOT 0 from LockedCoins)", pool)
	}
	if !liquid.Equal(math.NewInt(10)) {
		t.Fatalf("grantee liquid=%s want 10 (gas preserved byte-exact)", liquid)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
}
