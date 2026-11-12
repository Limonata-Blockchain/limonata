package keeper

import (
	"bytes"
	"testing"
	"time"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// HIGH-A-CROSS — the module-performed delegation at issuance records the EXACT
// granted shares (the per-validator ledger seed).
// ===========================================================================

// IssueLocked delegates the locked principal to grant.ValidatorOp itself, so
// GrantedShares/TrackedShares are recorded from the MINT result — the
// unambiguous, order-independent seed the reclaim later uses instead of the
// account-global DelegatedVesting aggregate.
func TestIssueLocked_RecordsGrantedSharesViaModuleDelegation(t *testing.T) {
	f := newFixture(t)
	admin := sdk.AccAddress(bytes.Repeat([]byte{0x44}, 20)).String()
	if err := f.k.SetParams(f.ctx, types.Params{Admin: admin}); err != nil {
		t.Fatal(err)
	}
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1050)))) // pool funds the grant
	f.sk.addValidator(f.valStr)                                                     // grant.ValidatorOp exists

	srv := NewMsgServerImpl(f.k)
	if _, err := srv.IssueLocked(f.ctx, &types.MsgIssueLocked{
		Admin: admin, Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOperator: f.valStr,
	}); err != nil {
		t.Fatalf("IssueLocked failed: %v", err)
	}

	g, found := f.k.GetGrant(f.ctx, f.granteeStr)
	if !found {
		t.Fatal("grant not found")
	}
	if !parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("GrantedShares=%q want 1000 (module delegated the locked principal)", g.GrantedShares)
	}
	if !parseDecOrZero(g.TrackedShares).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("TrackedShares=%q want 1000", g.TrackedShares)
	}
	if !f.sk.sharesOf(f.granteeBz, f.valStr).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("granted delegation shares=%s want 1000 (module-placed at grant.ValidatorOp)", f.sk.sharesOf(f.granteeBz, f.valStr))
	}
}

// Bootstrap-order fallback: when grant.ValidatorOp does not yet exist, the module
// cannot delegate, so GrantedShares stays 0 and the locked principal remains
// IN-ACCOUNT on the PLVA (swept by the immediate in-account path on clawback).
// This never seizes anything and never mis-records a free share.
func TestIssueLocked_NoValidator_LeavesPrincipalInAccount(t *testing.T) {
	f := newFixture(t)
	admin := sdk.AccAddress(bytes.Repeat([]byte{0x44}, 20)).String()
	if err := f.k.SetParams(f.ctx, types.Params{Admin: admin}); err != nil {
		t.Fatal(err)
	}
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1050))))
	// grant.ValidatorOp is NOT registered -> GetValidator fails -> no module delegation.

	srv := NewMsgServerImpl(f.k)
	if _, err := srv.IssueLocked(f.ctx, &types.MsgIssueLocked{
		Admin: admin, Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOperator: f.valStr,
	}); err != nil {
		t.Fatalf("IssueLocked failed: %v", err)
	}

	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if parseDecOrZero(g.GrantedShares).IsPositive() {
		t.Fatalf("GrantedShares=%q want 0 (validator absent -> no module delegation)", g.GrantedShares)
	}
	if !f.sk.sharesOf(f.granteeBz, f.valStr).IsZero() {
		t.Fatalf("unexpected delegation at grant.ValidatorOp: %s want 0", f.sk.sharesOf(f.granteeBz, f.valStr))
	}
	// the locked principal is in-account on the PLVA (LockedCoins == 1000).
	acc := f.ak.GetAccount(f.ctx, f.granteeBz)
	plva, ok := acc.(*vestingtypes.PermanentLockedAccount)
	if !ok {
		t.Fatal("grantee is not a PermanentLockedAccount")
	}
	if !plva.LockedCoins(f.ctx.BlockTime()).AmountOf(testDenom).Equal(math.NewInt(1000)) {
		t.Fatalf("in-account locked=%s want 1000", plva.LockedCoins(f.ctx.BlockTime()).AmountOf(testDenom))
	}
}

// ===========================================================================
// HIGH-B — deferred sweep: full-nanosecond maturity + LockedCoins cap +
// conditional unlock. Never seizes liquid; principal always reaches the pool.
// ===========================================================================

// setPending installs a single-entry PendingClawback maturing at `completion`
// (full nanoseconds), with the whole-second-truncated CompletionUnix that the OLD
// gate used — so a block in the sub-second gap exercises the timing fix.
func (f *fixture) setPending(sweep string, completion time.Time) {
	pc := types.PendingClawback{
		Grantee: f.granteeStr,
		Entries: []types.PendingClawbackEntry{{
			Validator:       f.valStr,
			Amount:          sweep,
			CompletionUnix:  completion.Unix(),     // truncated (what the OLD gate compared)
			CompletionNanos: completion.UnixNano(), // full precision (what the FIX compares)
		}},
		SweepAmount: sweep,
		InitiatedAt: f.ctx.BlockTime().Unix(),
	}
	if err := f.k.SetPendingClawback(f.ctx, pc); err != nil {
		panic(err)
	}
}

func (f *fixture) pendingCount() int {
	n := 0
	f.k.IteratePendingClawbacks(f.ctx, func(types.PendingClawback) { n++ })
	return n
}

// TIMING GATE: a block landing in the SUB-SECOND GAP between the truncated second
// and the real (nanosecond) unbonding completion must NOT sweep — x/staking has
// not returned the coins yet. The OLD whole-second-truncated gate fired here,
// deleting the pending record, seizing the grantee's liquid gas, and orphaning the
// principal. The fix waits.
func TestDeferredSweep_SubSecondGap_DoesNotFireEarly(t *testing.T) {
	f := newFixture(t)
	// principal still UNBONDING (not returned): LockedCoins 0; grantee holds 10 gas.
	makeGrantPLVA(t, f, 300, 300)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(10))))

	completion := time.Unix(1_700_100_000, 500_000_000) // T.5s (real maturity)
	gap := time.Unix(1_700_100_000, 200_000_000)        // T.2s (past truncated-T, before real)
	f.setPending("300", completion)

	gapCtx := f.ctx.WithBlockTime(gap)
	if err := f.k.SweepMaturedClawbacks(gapCtx); err != nil {
		t.Fatalf("sweep errored: %v", err)
	}

	// pending record PRESERVED (not prematurely deleted) — the essential timing fix.
	if got := f.pendingCount(); got != 1 {
		t.Fatalf("pending clawbacks=%d want 1 (must NOT fire in the sub-second gap)", got)
	}
	// grantee's liquid gas untouched; pool got nothing.
	if !f.bank.GetBalance(gapCtx, f.granteeBz, testDenom).Amount.Equal(math.NewInt(10)) {
		t.Fatalf("grantee liquid=%s want 10 (gas must NOT be swept early)", f.bank.GetBalance(gapCtx, f.granteeBz, testDenom).Amount)
	}
	if !f.bank.GetBalance(gapCtx, f.poolAddr, testDenom).Amount.IsZero() {
		t.Fatalf("pool=%s want 0 (nothing mature yet)", f.bank.GetBalance(gapCtx, f.poolAddr, testDenom).Amount)
	}
}

// RE-SLASH (real bucketing) is covered by
// TestDeferredSweep_ReslashShortfall_RealBucketing_FloorNotLockedCoins in
// clawback_realbucketing_test.go: the returned re-slashed principal is bucketed
// FREE by TrackUndelegation (LockedCoins reads 0), and the (balance - gasAllowance)
// floor — NOT a LockedCoins cap — delivers exactly the returned amount to the pool
// while preserving the grantee's gas. The old hand-set LockedCoins model (which set
// DelegatedVesting=0 and never exercised the free-first return) hid HIGH-B and has
// been removed.

// HAPPY PATH: full principal returned & re-locked -> the whole recorded reclaim
// reaches the pool; gas preserved; pending cleared. (Principal always to pool.)
func TestDeferredSweep_FullPrincipalReachesPool(t *testing.T) {
	f := newFixture(t)
	makeGrantPLVA(t, f, 300, 0) // LockedCoins == 300 (full principal re-locked)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(310))))

	completion := time.Unix(1_700_100_000, 500_000_000)
	after := time.Unix(1_700_100_001, 0)
	f.setPending("300", completion)

	afterCtx := f.ctx.WithBlockTime(after)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("sweep errored: %v", err)
	}
	if !f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount.Equal(math.NewInt(300)) {
		t.Fatalf("pool=%s want 300 (full principal to pool)", f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount)
	}
	if !f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount.Equal(math.NewInt(10)) {
		t.Fatalf("grantee liquid=%s want 10 (gas preserved)", f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
}
