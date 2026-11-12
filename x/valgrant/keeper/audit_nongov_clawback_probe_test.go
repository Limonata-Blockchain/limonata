package keeper

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// HIGH-D — the NON-GOVERNANCE clawback (admin-gated MsgClawback; the EVM
// precompile clawback(address) routes through the SAME msgServer.Clawback) must
// reclaim ONLY the foundation-granted LOCKED principal, exactly like the
// governance path.
//
// The retired cycle-6 blunt path force-undelegated EVERY delegation the grantee
// held (self-bond at the granted validator + every other-validator delegation),
// recorded each entry's FULL amount, and — with the SweepAmount cap dropped —
// the deferred sweep credited the pool Σ entries, seizing the grantee's OWN
// stake with NO slash needed. Cycle 7 routes MsgClawback through the surgical
// ClawbackGrantGov locked-share reclaim (entries are pure locked principal) AND
// restores the SweepAmount cap in SweepMaturedClawbacks as a safety belt.
//
// These probes drive msgServer.Clawback END-TO-END (msg -> surgical reclaim ->
// unbonding -> capture -> maturity -> deferred sweep) against the exact
// topologies from the cycle-6 finding. The sibling probe in
// precompiles/valgrant/clawback_surgical_test.go drives the same guarantee
// through the EVM precompile ABI surface.
// ===========================================================================

// adminAddr registers and returns a test admin address in Params.
func adminAddr(t *testing.T, f *fixture) string {
	t.Helper()
	admin := sdk.AccAddress(bytes.Repeat([]byte{0x44}, 20)).String()
	if err := f.k.SetParams(f.ctx, types.Params{Admin: admin}); err != nil {
		t.Fatal(err)
	}
	return admin
}

// (i) HIGH-D worked case, NO SLASH: locked grant 1000 bonded at the granted
// validator V-grant; the grantee separately self-bonds 500 of their OWN at a
// DIFFERENT validator V-other and holds a 10 gas allowance. The admin clawback
// must undelegate ONLY the 1000 locked shares at V-grant; at maturity the pool
// receives EXACTLY 1000 and the grantee's V-other self-bond + gas stay
// byte-exact.
//
// CYCLE-6 BUG: k.Clawback undelegated BOTH (entries 1000 + 500), and the
// uncapped sweep credited the pool 1500 — seizing the grantee's own 500.
func TestNonGov_MsgClawback_OtherValidatorSelfBond_NeverTouched_NoSlash(t *testing.T) {
	f := newFixture(t)
	admin := adminAddr(t, f)

	vGrant := f.valStr      // granted validator (grant.ValidatorOp)
	vOther := valoper(0x66) // the grantee's OWN self-bond validator

	// Realistic PLVA bucketing: grant 1000 fills DelegatedVesting, own 500 fills
	// DelegatedFree (buckets are account-global; the validator split lives in the
	// staking topology below).
	realisticGrantPLVA(t, f, 1000, 1000, 500)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(10)))) // gas
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000)) // the locked grant
	f.sk.delegate(f.granteeBz, vOther, math.NewInt(500))  // the grantee's OWN

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.Clawback(f.ctx, &types.MsgClawback{Admin: admin, Grantee: f.granteeStr})
	if err != nil {
		t.Fatalf("admin clawback failed: %v", err)
	}
	if resp.PendingAmount != "1000" || resp.SweptAmount != "0" {
		t.Fatalf("resp pending=%s swept=%s want 1000/0 (bonded locked principal only)", resp.PendingAmount, resp.SweptAmount)
	}

	// SURGICAL: the other-validator self-bond is NEVER force-undelegated.
	if got := f.sk.tokensOf(f.granteeBz, vOther); !got.Equal(math.NewInt(500)) {
		t.Fatalf("V-other self-bond=%s want 500 UNTOUCHED (cycle-6 force-undelegated it)", got)
	}
	if got := f.sk.tokensOf(f.granteeBz, vGrant); !got.IsZero() {
		t.Fatalf("V-grant residual=%s want 0 (locked shares fully reclaimed)", got)
	}
	// The pending record is PURE locked principal: ONE entry, at V-grant only.
	var pcs []types.PendingClawback
	f.k.IteratePendingClawbacks(f.ctx, func(pc types.PendingClawback) { pcs = append(pcs, pc) })
	if len(pcs) != 1 || len(pcs[0].Entries) != 1 {
		t.Fatalf("pendings=%d entries=%v want 1 pending with 1 entry (surgical)", len(pcs), pcs)
	}
	if pcs[0].Entries[0].Validator != vGrant || pcs[0].Entries[0].Amount != "1000" || pcs[0].SweepAmount != "1000" {
		t.Fatalf("entry=%+v sweepAmount=%s want V-grant/1000/1000", pcs[0].Entries[0], pcs[0].SweepAmount)
	}

	// Capture block mid-window, then maturity: x/staking returns the 1000.
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	if got := f.matureAndReturn(t, vGrant, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(1000)) {
		t.Fatalf("returned=%s want 1000", got)
	}
	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount; !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want EXACTLY 1000 (locked principal only; cycle-6 swept 1500)", pool)
	}
	if liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount; !liquid.Equal(math.NewInt(10)) {
		t.Fatalf("grantee liquid=%s want 10 byte-exact (gas untouched)", liquid)
	}
	if got := f.sk.tokensOf(f.granteeBz, vOther); !got.Equal(math.NewInt(500)) {
		t.Fatalf("V-other self-bond=%s want 500 byte-exact after sweep", got)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}

	// Idempotency on the admin surface: a second clawback is rejected.
	if _, err := srv.Clawback(f.ctx, &types.MsgClawback{Admin: admin, Grantee: f.granteeStr}); err == nil {
		t.Fatal("second admin clawback must be rejected (already revoked)")
	}
}

// (ii) COMMINGLED same-block self-bond undelegation + RE-SLASH through the
// NON-GOV path: identical to the proven gov merge probe, but driven via
// MsgClawback. Merged delegation 2000 (1000 grant + 1000 own) at V-grant; the
// admin clawback undelegates the 1000 locked shares; the grantee undelegates
// 500 of their OWN in the SAME block (x/staking AddEntry MERGES them, init
// 1500); a 40% re-slash shrinks the merged entry to 900. Pool must receive
// floor(1000*900/1500)=600 (the grant's pro-rata slashed value) and the grantee
// keeps their 300 own return + 10 gas + 500 remaining self-bond byte-exact.
func TestNonGov_MsgClawback_CommingledSameBlock_Reslash_ProportionalCredit(t *testing.T) {
	f := newFixture(t)
	admin := adminAddr(t, f)

	realisticGrantPLVA(t, f, 1000, 1000, 1000)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(10))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000)) // merged 1000 grant + 1000 own

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.Clawback(f.ctx, &types.MsgClawback{Admin: admin, Grantee: f.granteeStr})
	if err != nil {
		t.Fatalf("admin clawback failed: %v", err)
	}
	if resp.PendingAmount != "1000" {
		t.Fatalf("recorded reclaim=%s want 1000 (locked shares only, PRE-merge)", resp.PendingAmount)
	}

	// SAME BLOCK: grantee undelegates 500 own -> MERGES into the clawback entry.
	if _, _, err := f.sk.Undelegate(f.ctx, f.granteeBz, f.valBz, math.LegacyNewDec(500)); err != nil {
		t.Fatalf("grantee own-undelegate failed: %v", err)
	}
	// RE-SLASH 40% of the merged entry (base = InitialBalance 1500): 1500 -> 900.
	f.sk.slashUBDByFactor(f.granteeBz, f.valStr, pct(40))

	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(900)) {
		t.Fatalf("returned=%s want 900 (re-slashed merged entry)", got)
	}
	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount; !pool.Equal(math.NewInt(600)) {
		t.Fatalf("pool=%s want 600 (floor(1000*900/1500), the grant's pro-rata slashed value)", pool)
	}
	if liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount; !liquid.Equal(math.NewInt(310)) {
		t.Fatalf("grantee liquid=%s want 310 (10 gas + 300 own return) byte-exact", liquid)
	}
	if got := f.sk.tokensOf(f.granteeBz, f.valStr); !got.Equal(math.NewInt(500)) {
		t.Fatalf("remaining own self-bond=%s want 500 untouched", got)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
}

// (iii) BOOTSTRAP-SEEDING shape via the NON-GOV path: the grant never bonded
// (GrantedShares 0, principal fully in-account on the PLVA). The admin clawback
// must sweep EXACTLY the in-account locked 1000 and leave the grantee's own 500
// liquid + 10 gas byte-exact. (The retired blunt path swept
// min(lockedPrincipal, SPENDABLE balance) — from liquid — on this shape.)
func TestNonGov_MsgClawback_InAccountGrant_OwnLiquidPreserved(t *testing.T) {
	f := newFixture(t)
	admin := adminAddr(t, f)

	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000))))
	if err != nil {
		t.Fatal(err)
	}
	f.ak.SetAccount(f.ctx, plva)
	// balance = 1000 locked principal + 10 gas + 500 own liquid.
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1510))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active"})

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.Clawback(f.ctx, &types.MsgClawback{Admin: admin, Grantee: f.granteeStr})
	if err != nil {
		t.Fatalf("admin clawback failed: %v", err)
	}
	if resp.SweptAmount != "1000" || resp.PendingAmount != "0" {
		t.Fatalf("resp swept=%s pending=%s want 1000/0 (in-account locked only)", resp.SweptAmount, resp.PendingAmount)
	}
	if pool := f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount; !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want 1000", pool)
	}
	if liquid := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount; !liquid.Equal(math.NewInt(510)) {
		t.Fatalf("grantee liquid=%s want 510 byte-exact (10 gas + 500 own)", liquid)
	}
}

// (iv) ADMIN GATING: a non-admin signer (including the grantee) is rejected and
// the grant/state is untouched; an unconfigured admin ("") rejects everyone.
func TestNonGov_MsgClawback_AdminGated(t *testing.T) {
	f := newFixture(t)
	admin := adminAddr(t, f)
	_ = admin

	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	// The grantee (or any non-admin) cannot claw back.
	if _, err := srv.Clawback(f.ctx, &types.MsgClawback{Admin: f.granteeStr, Grantee: f.granteeStr}); err == nil || !strings.Contains(err.Error(), "not the valgrant admin") {
		t.Fatalf("non-admin clawback must be rejected, got err=%v", err)
	}
	if got := f.sk.tokensOf(f.granteeBz, f.valStr); !got.Equal(math.NewInt(1000)) {
		t.Fatalf("delegation=%s want 1000 untouched after rejected clawback", got)
	}
	if g, _ := f.k.GetGrant(f.ctx, f.granteeStr); g.Status != "active" {
		t.Fatalf("grant status=%s want active after rejected clawback", g.Status)
	}

	// Admin unset: everyone is rejected.
	if err := f.k.SetParams(f.ctx, types.Params{Admin: ""}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Clawback(f.ctx, &types.MsgClawback{Admin: f.granteeStr, Grantee: f.granteeStr}); err == nil {
		t.Fatal("clawback with unconfigured admin must be rejected")
	}
}

// ===========================================================================
// HIGH-D safety belt — the deferred sweep NEVER credits the pool more than the
// recorded locked principal (SweepAmount), even for a pending whose entries sum
// beyond it (the exact shape the retired blunt path produced: every delegation
// force-undelegated, Σ Entries > SweepAmount).
// ===========================================================================

// A legacy blunt-shaped pending: entries 1000 (grant, V1) + 500 (the grantee's
// OWN, V2), SweepAmount capped at the locked 1000. Both mature un-slashed and
// return 1500 to the account. The sweep must credit the pool EXACTLY 1000 and
// leave the grantee's 500 (their own return) + 25 baseline byte-exact.
// UNCAPPED (cycle 6) this swept 1500 — the HIGH-D seizure.
func TestSweep_SumExceedsSweepAmount_CapBinds(t *testing.T) {
	f := newFixture(t)
	v1 := f.valStr
	v2 := valoper(0x66)
	completion := f.ctx.BlockTime().Add(21 * 24 * time.Hour)

	// The blunt-path shape: BOTH the grant's 1000 and the grantee's own 500 were
	// force-undelegated; SweepAmount records the locked principal 1000 only.
	f.sk.appendUBD(f.granteeBz, v1, 100, completion, math.NewInt(1000))
	f.sk.appendUBD(f.granteeBz, v2, 100, completion, math.NewInt(500))
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(25))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee: f.granteeStr,
		Entries: []types.PendingClawbackEntry{
			{Validator: v1, Amount: "1000", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100},
			{Validator: v2, Amount: "500", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100},
		},
		SweepAmount: "1000",
	}); err != nil {
		t.Fatal(err)
	}

	// A capture block runs (ResolvedBalance/EntryInit recorded, no slash), then
	// both entries mature and return 1000 + 500 to the account.
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(f.granteeBz, v1, at))))
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(f.granteeBz, v2, at))))

	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount; !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want EXACTLY 1000 (Σ entries 1500 CAPPED at SweepAmount; uncapped cycle-6 seized 1500)", pool)
	}
	if liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount; !liquid.Equal(math.NewInt(525)) {
		t.Fatalf("grantee liquid=%s want 525 byte-exact (25 baseline + their own 500 return)", liquid)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
}

// The cap must never turn into a TOP-UP: when the re-slash-aware Σ of the
// entries is BELOW SweepAmount (a real re-slash shortfall), the sweep credits
// the smaller Σ — the cap is one-directional. Entry recorded 1000, re-slashed
// to 400 during unbonding; SweepAmount 1000. Pool gets EXACTLY 400 and the
// grantee's 30 own liquid stays byte-exact.
func TestSweep_CapIsOneDirectional_NeverTopsUp(t *testing.T) {
	f := newFixture(t)
	completion := f.ctx.BlockTime().Add(21 * 24 * time.Hour)

	f.sk.appendUBD(f.granteeBz, f.valStr, 100, completion, math.NewInt(1000))
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(30))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     f.granteeStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "1000", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "1000",
	}); err != nil {
		t.Fatal(err)
	}

	// Re-slash during the unbonding window: 1000 -> 400.
	f.sk.reslashUBD(f.granteeBz, f.valStr, math.NewInt(400))
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(f.granteeBz, f.valStr, at))))

	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount; !pool.Equal(math.NewInt(400)) {
		t.Fatalf("pool=%s want 400 (the re-slashed actual; the cap must never top up)", pool)
	}
	if liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount; !liquid.Equal(math.NewInt(30)) {
		t.Fatalf("grantee liquid=%s want 30 byte-exact", liquid)
	}
}
