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
// HIGH-C — deferred sweep credits the pool the SPECIFIC unbonding entry's ACTUAL
// matured balance (re-slash-aware), NEVER the pre-recorded amount, NEVER
// (balance - gas), NEVER the grantee's earned rewards / own liquid.
//
// These probes drive the REAL vesting+staking+slashing path:
//   - realisticGrantPLVA fills DelegatedVesting/DelegatedFree via the SDK's actual
//     TrackDelegation (authentic LockedCoins);
//   - the governance clawback force-undelegates the locked shares, creating a REAL
//     x/staking UnbondingDelegationEntry (modelled by the mock);
//   - reslashUBD DECREMENTS that entry's Balance in place during the unbonding
//     window — exactly as SlashUnbondingDelegation does when evidence of an old
//     infraction surfaces after the clawback;
//   - a capture block (the ~2s block the chain runs every unbonding day) records the
//     re-slashed Balance;
//   - matureAndReturn completes the entry, returning ONLY the re-slashed Balance with
//     the SDK's real free-first TrackUndelegation.
//
// Each asserts pool == actual-returned AND the grantee's earned rewards / gas /
// own self-bond byte-exact — the assertion the cycle-5 probes missed (they gave the
// grantee zero liquid beyond gas, so (balance - gas) happened to equal the return).
// ===========================================================================

// COMMINGLED re-slash + pre-existing earned rewards. The grant (1000, DV) and the
// grantee's OWN 1000 self-bond (DF) are merged in ONE delegation; the grantee also
// holds 500 earned-reward liquid + 10 gas. A re-slash during unbonding leaves only
// 700 of the recorded 1000 to return (bucketed FREE-FIRST -> LockedCoins 0).
//
// CORRECT (HIGH-C): the pool receives EXACTLY the 700 that returned; the grantee's
// 510 own liquid and 1000 own self-bond are byte-exact untouched.
// OLD BUG: sweep = min(1000, balance(1210) - gas(10) = 1200) = 1000 -> pool 1000,
// seizing 300 of the grantee's own earned rewards.
func TestAudit_DeferredSweep_Reslash_Commingled_PoolEqualsActual(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 1000) // DV=1000 (grant), DF=1000 (own)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(510))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000)) // merged 1000 grant + 1000 own

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("recorded reclaim = %s want 1000", resp.PrincipalPending)
	}

	// RE-SLASH during unbonding: the created entry's Balance drops 1000 -> 700.
	f.sk.reslashUBD(f.granteeBz, f.valStr, math.NewInt(700))
	// A capture block during the unbonding window records the re-slashed 700.
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	// Maturity: x/staking returns ONLY the re-slashed 700, bucketed FREE (LockedCoins 0).
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(700)) {
		t.Fatalf("returned=%s want 700", got)
	}
	if !f.lockedCoins(t).IsZero() {
		t.Fatalf("setup invariant: LockedCoins=%s want 0 (re-slashed return mis-bucketed FREE)", f.lockedCoins(t))
	}

	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(700)) {
		t.Fatalf("pool=%s want 700 (EXACTLY the re-slashed principal that returned)", pool)
	}
	if !liquid.Equal(math.NewInt(510)) {
		t.Fatalf("grantee liquid=%s want 510 byte-exact (500 rewards + 10 gas); own liquid was seized", liquid)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(1000)) {
		t.Fatalf("own self-bond changed: %s want 1000", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
	if _, stillVesting := f.ak.GetAccount(afterCtx, f.granteeBz).(*vestingtypes.PermanentLockedAccount); stillVesting {
		t.Fatal("PLVA not unlocked after sweeping principal")
	}
}

// PURE-LOCKED re-slash + pre-existing earned rewards (no free self-bond, DF=0). The
// re-slashed return RE-LOCKS (pure-vesting drains DelegatedVesting -> LockedCoins
// tracks the actual 700). This is the case the OLD LockedCoins cap handled correctly
// but the cycle-5 (balance - gas) floor regressed once own liquid is present.
//
// CORRECT (HIGH-C): pool 700, grantee 510 own liquid byte-exact.
func TestAudit_DeferredSweep_Reslash_PureLocked_PoolEqualsActual(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 0) // DV=1000, DF=0 (pure-locked)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(510))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000)) // pure grant, no own self-bond

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("recorded reclaim = %s want 1000", resp.PrincipalPending)
	}

	f.sk.reslashUBD(f.granteeBz, f.valStr, math.NewInt(700))
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(700)) {
		t.Fatalf("returned=%s want 700", got)
	}
	if !f.lockedCoins(t).Equal(math.NewInt(700)) {
		t.Fatalf("setup invariant: LockedCoins=%s want 700 (pure-vesting re-slashed return re-locks)", f.lockedCoins(t))
	}

	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(700)) {
		t.Fatalf("pool=%s want 700 (re-slashed principal only)", pool)
	}
	if !liquid.Equal(math.NewInt(510)) {
		t.Fatalf("grantee liquid=%s want 510 byte-exact (own liquid seized)", liquid)
	}
}

// ENTRY FULLY SLASHED TO ZERO (double-sign tombstone during unbonding). The entry's
// Balance drops to 0, so CompleteUnbonding returns NOTHING. The sweep must deliver 0
// and seize NOTHING from the grantee's 510 own liquid.
func TestAudit_DeferredSweep_Reslash_ToZero_DeliversZeroNoSeizure(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 1000)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(510))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000))

	srv := NewMsgServerImpl(f.k)
	if _, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "double-sign"}); err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	f.sk.reslashUBD(f.granteeBz, f.valStr, math.ZeroInt()) // 100% slash of the unbonding entry
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.IsZero() {
		t.Fatalf("returned=%s want 0", got)
	}

	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.IsZero() {
		t.Fatalf("pool=%s want 0 (entry fully slashed; nothing returned)", pool)
	}
	if !liquid.Equal(math.NewInt(510)) {
		t.Fatalf("grantee liquid=%s want 510 byte-exact (nothing must be seized)", liquid)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
}

// NO RE-SLASH but the grantee spent its gas below the nominal allowance (spendable 3
// < gas 10). The full principal returns; capture records the unchanged Balance. The
// pool must receive the FULL principal — the removed (balance - gas) floor previously
// ORPHANED (allowance - spendable) of foundation principal to the grantee here.
func TestAudit_DeferredSweep_NoReslash_GasSpentDown_NoOrphan(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 0)                                       // DV=1000, DF=0
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(3)))) // gas spent down to 3
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	if _, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"}); err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour)) // no re-slash: Balance stays 1000
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(1000)) {
		t.Fatalf("returned=%s want 1000", got)
	}

	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want 1000 (full principal; gas floor previously orphaned 7)", pool)
	}
	if !liquid.Equal(math.NewInt(3)) {
		t.Fatalf("grantee liquid=%s want 3 (spent-down gas preserved as-is)", liquid)
	}
}

// MULTIPLE pending clawbacks maturing the same block, mixed outcomes. The single
// sweep pass must resolve each independently: grantee A re-slashed (1000 -> 700),
// grantee B full (500). Pool = 700 + 500; each grantee's own liquid byte-exact.
func TestAudit_DeferredSweep_MultiplePending_ResolvedIndependently(t *testing.T) {
	f := newFixture(t)
	f.sk.addValidator(f.valStr)
	completion := f.ctx.BlockTime().Add(21 * 24 * time.Hour)

	aBz := f.granteeBz // 0x11...
	aStr := f.granteeStr
	bBz := sdk.AccAddress(bytes.Repeat([]byte{0x77}, 20))
	bStr := bBz.String()

	// A: recorded 1000, entry re-slashed to 700 (InitialBalance 1000, Balance 700 — no
	// merge, so EntryInit == Amount and the proportional credit == the entry Balance),
	// holds 300 own liquid.
	f.sk.appendUBD(aBz, f.valStr, 100, completion, math.NewInt(1000))
	f.sk.reslashUBD(aBz, f.valStr, math.NewInt(700))
	f.bank.add(aBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(300))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     aStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "1000", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "1000",
	}); err != nil {
		t.Fatal(err)
	}
	// B: recorded 500, no re-slash (entry Balance 500), holds 40 own liquid.
	f.sk.appendUBD(bBz, f.valStr, 100, completion, math.NewInt(500))
	f.bank.add(bBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(40))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     bStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "500", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "500",
	}); err != nil {
		t.Fatal(err)
	}

	// One capture block during unbonding records both re-slash-aware balances.
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))

	// Maturity: return each entry's Balance (700 / 500) to its account.
	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	f.bank.add(aBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(aBz, f.valStr, at))))
	f.bank.add(bBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(bBz, f.valStr, at))))

	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	if !pool.Equal(math.NewInt(1200)) {
		t.Fatalf("pool=%s want 1200 (700 re-slashed + 500 full)", pool)
	}
	if la := f.bank.GetBalance(afterCtx, aBz, testDenom).Amount; !la.Equal(math.NewInt(300)) {
		t.Fatalf("grantee A liquid=%s want 300 byte-exact", la)
	}
	if lb := f.bank.GetBalance(afterCtx, bBz, testDenom).Amount; !lb.Equal(math.NewInt(40)) {
		t.Fatalf("grantee B liquid=%s want 40 byte-exact", lb)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared: %d", f.pendingCount())
	}
}
