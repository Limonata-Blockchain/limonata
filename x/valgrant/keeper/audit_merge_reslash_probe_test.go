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
// HIGH-C-MERGE — the deferred sweep credits the pool the grant's PROPORTIONAL
// share of a (possibly-merged) matured unbonding entry:
//
//	pool = floor(Amount * ResolvedBalance / EntryInit)
//
// x/staking UnbondingDelegation.AddEntry MERGES two undelegations from the same
// (delegator, validator) that land in the SAME block (identical CreationHeight AND
// CompletionTime) by SUMMING InitialBalance/Balance. When a grantee partially
// undelegates their OWN self-bond at grant.ValidatorOp in the EXACT block the gov
// clawback executes, the clawback's reclaim entry and the grantee's own entry MERGE:
// the tracked entry then holds grant-reclaim + grantee-own. A re-slash of that merged
// entry shrinks BOTH portions proportionally (SlashUnbondingDelegation slashes
// proportional to InitialBalance). Cycle-6 credited the merged Balance directly, seizing
// the grantee's own return; the proportional credit takes ONLY the grant's fair fraction
// (Amount/EntryInit), so the grantee always keeps ResolvedBalance - credit.
//
// These probes model the REAL AddEntry merge (mock appendUBD sums both balances on a
// same-(height,completion) append) and the REAL SlashUnbondingDelegation (mock
// slashUBDByFactor slashes truncate(factor*InitialBalance), flooring at Balance).
// ===========================================================================

// pct returns a LegacyDec percentage as a slash factor (e.g. pct(40) == 0.40).
func pct(p int64) math.LegacyDec { return math.LegacyNewDecWithPrec(p, 2) }

// (i) MERGE + RE-SLASH 40% — the MISSION's proven-failing case, END-TO-END through the
// real governance clawback. Commingled 2000 sh (1000 grant + 1000 own), GrantedShares
// 1000. The gov clawback undelegates the 1000 locked shares (entry InitialBalance 1000);
// the grantee then undelegates 500 of their OWN in the SAME block, MERGING into that
// entry (InitialBalance 1500). A 40% re-slash shrinks the merged entry to Balance 900.
//
// CORRECT: pool = floor(1000 * 900 / 1500) = 600 (the grant's pro-rata slashed value);
// the grantee keeps 300 of their own return (500 own slashed 40%) byte-exact — NOT
// seized — plus their 10 gas and their remaining 500 own self-bond.
// CYCLE-6 BUG: credited the merged Balance 900, seizing all 300 of the grantee's return.
func TestAudit_MergeReslash_GovClawback_ProportionalCredit(t *testing.T) {
	f := newFixture(t)
	realisticGrantPLVA(t, f, 1000, 1000, 1000) // DV=1000 (grant), DF=1000 (own)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(10))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000)) // merged 1000 grant + 1000 own

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("recorded reclaim = %s want 1000 (the grant's reclaim, PRE-merge)", resp.PrincipalPending)
	}

	// SAME BLOCK: the grantee undelegates 500 of their OWN self-bond at grant.ValidatorOp.
	// x/staking AddEntry MERGES it into the clawback's entry -> InitialBalance 1000 -> 1500.
	if _, _, err := f.sk.Undelegate(f.ctx, f.granteeBz, f.valBz, math.LegacyNewDec(500)); err != nil {
		t.Fatalf("grantee own-undelegate failed: %v", err)
	}
	// RE-SLASH 40% of the merged entry (slash base = InitialBalance 1500): Balance 1500 ->
	// 900 (grant 600 + grantee-own 300).
	f.sk.slashUBDByFactor(f.granteeBz, f.valStr, pct(40))

	// A capture block during unbonding records ResolvedBalance=900, EntryInit=1500.
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	// Maturity: the merged entry returns its Balance 900 to the grantee.
	if got := f.matureAndReturn(t, f.valStr, f.ctx.BlockTime().Add(22*24*time.Hour)); !got.Equal(math.NewInt(900)) {
		t.Fatalf("returned=%s want 900 (re-slashed merged entry)", got)
	}

	afterCtx := f.ctx.WithBlockTime(f.ctx.BlockTime().Add(22 * 24 * time.Hour))
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(600)) {
		t.Fatalf("pool=%s want 600 (floor(1000*900/1500) — the grant's proportional slashed value)", pool)
	}
	if !liquid.Equal(math.NewInt(310)) {
		t.Fatalf("grantee liquid=%s want 310 (10 gas + 300 own return; cycle-6 seized the 300)", liquid)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(500)) {
		t.Fatalf("remaining own self-bond=%s want 500 (untouched)", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
	if _, stillVesting := f.ak.GetAccount(afterCtx, f.granteeBz).(*vestingtypes.PermanentLockedAccount); stillVesting {
		t.Fatal("PLVA not unlocked after sweeping principal")
	}
}

// (ii) NO-MERGE RE-SLASH still EXACT (cycle-6 unchanged). A sole-grant entry
// (InitialBalance 1000 == Amount, no merge) re-slashed to Balance 700. The proportional
// credit floor(1000 * 700 / 1000) == 700 == the entry Balance — identical to the proven
// cycle-6 credit. The grantee's 250 own liquid is left byte-exact.
func TestAudit_MergeReslash_NoMerge_ReducesToCycle6(t *testing.T) {
	f := newFixture(t)
	f.sk.addValidator(f.valStr)
	completion := f.ctx.BlockTime().Add(21 * 24 * time.Hour)

	// Sole-grant entry: InitialBalance 1000, then re-slashed to Balance 700 (no merge).
	f.sk.appendUBD(f.granteeBz, f.valStr, 100, completion, math.NewInt(1000))
	f.sk.reslashUBD(f.granteeBz, f.valStr, math.NewInt(700))
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(250))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     f.granteeStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "1000", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "1000",
	}); err != nil {
		t.Fatal(err)
	}

	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(f.granteeBz, f.valStr, at))))

	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount
	liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount
	if !pool.Equal(math.NewInt(700)) {
		t.Fatalf("pool=%s want 700 (no merge: EntryInit==Amount => credit == entry Balance, cycle-6)", pool)
	}
	if !liquid.Equal(math.NewInt(250)) {
		t.Fatalf("grantee liquid=%s want 250 byte-exact (own liquid untouched)", liquid)
	}
}

// (iii) MERGED entry FULLY SLASHED to zero (double-sign tombstone during unbonding).
// Merged InitialBalance 1500 (1000 grant + 500 own), slashed 100% -> Balance 0.
// CompleteUnbonding returns NOTHING. The pool must be credited floor(1000*0/1500)=0 and
// NOTHING may be seized from the grantee's 40 own liquid.
func TestAudit_MergeReslash_MergedFullySlashed_CreditsZero(t *testing.T) {
	f := newFixture(t)
	f.sk.addValidator(f.valStr)
	completion := f.ctx.BlockTime().Add(21 * 24 * time.Hour)

	// MERGE: grant reclaim 1000 + grantee own 500 -> InitialBalance/Balance 1500.
	f.sk.appendUBD(f.granteeBz, f.valStr, 100, completion, math.NewInt(1000))
	f.sk.appendUBD(f.granteeBz, f.valStr, 100, completion, math.NewInt(500))
	// 100% slash -> Balance 0 (InitialBalance stays 1500).
	f.sk.slashUBDByFactor(f.granteeBz, f.valStr, math.LegacyOneDec())
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(40))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     f.granteeStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "1000", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "1000",
	}); err != nil {
		t.Fatal(err)
	}

	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))
	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	if got := f.sk.completeMaturedUBD(f.granteeBz, f.valStr, at); !got.IsZero() {
		t.Fatalf("returned=%s want 0 (fully slashed)", got)
	}

	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}
	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount; !pool.IsZero() {
		t.Fatalf("pool=%s want 0 (merged entry fully slashed; nothing returned)", pool)
	}
	if liquid := f.bank.GetBalance(afterCtx, f.granteeBz, testDenom).Amount; !liquid.Equal(math.NewInt(40)) {
		t.Fatalf("grantee liquid=%s want 40 byte-exact (nothing may be seized)", liquid)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared")
	}
}

// (iv) MULTIPLE MERGED pendings maturing the same block, resolved INDEPENDENTLY, each
// proportional to its OWN entry. A: merged 1500 (1000 grant + 500 own), slash 40% -> 900
// -> credit floor(1000*900/1500)=600, keeps 300 own. B: merged 800 (500 grant + 300
// own), slash 50% -> 400 -> credit floor(500*400/800)=250, keeps 150 own. Pool=850; each
// grantee's own return byte-exact.
func TestAudit_MergeReslash_MultipleMergedPendings_Independent(t *testing.T) {
	f := newFixture(t)
	f.sk.addValidator(f.valStr)
	completion := f.ctx.BlockTime().Add(21 * 24 * time.Hour)

	aBz := f.granteeBz
	aStr := f.granteeStr
	bBz := sdk.AccAddress(bytes.Repeat([]byte{0x77}, 20))
	bStr := bBz.String()

	// A: MERGE grant 1000 + own 500 -> init 1500; slash 40% -> Balance 900.
	f.sk.appendUBD(aBz, f.valStr, 100, completion, math.NewInt(1000))
	f.sk.appendUBD(aBz, f.valStr, 100, completion, math.NewInt(500))
	f.sk.slashUBDByFactor(aBz, f.valStr, pct(40))
	f.bank.add(aBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(5))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     aStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "1000", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "1000",
	}); err != nil {
		t.Fatal(err)
	}
	// B: MERGE grant 500 + own 300 -> init 800; slash 50% -> Balance 400.
	f.sk.appendUBD(bBz, f.valStr, 100, completion, math.NewInt(500))
	f.sk.appendUBD(bBz, f.valStr, 100, completion, math.NewInt(300))
	f.sk.slashUBDByFactor(bBz, f.valStr, pct(50))
	f.bank.add(bBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(7))))
	if err := f.k.SetPendingClawback(f.ctx, types.PendingClawback{
		Grantee:     bStr,
		Entries:     []types.PendingClawbackEntry{{Validator: f.valStr, Amount: "500", CompletionUnix: completion.Unix(), CompletionNanos: completion.UnixNano(), CreationHeight: 100}},
		SweepAmount: "500",
	}); err != nil {
		t.Fatal(err)
	}

	// One capture block records both entries' (Balance, InitialBalance).
	f.captureBlock(t, f.ctx.BlockTime().Add(24*time.Hour))

	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	f.bank.add(aBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(aBz, f.valStr, at))))
	f.bank.add(bBz, sdk.NewCoins(sdk.NewCoin(testDenom, f.sk.completeMaturedUBD(bBz, f.valStr, at))))

	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, testDenom).Amount; !pool.Equal(math.NewInt(850)) {
		t.Fatalf("pool=%s want 850 (600 + 250, each pro-rata to its own merged entry)", pool)
	}
	if la := f.bank.GetBalance(afterCtx, aBz, testDenom).Amount; !la.Equal(math.NewInt(305)) {
		t.Fatalf("grantee A liquid=%s want 305 (5 baseline + 300 own return)", la)
	}
	if lb := f.bank.GetBalance(afterCtx, bBz, testDenom).Amount; !lb.Equal(math.NewInt(157)) {
		t.Fatalf("grantee B liquid=%s want 157 (7 baseline + 150 own return)", lb)
	}
	if f.pendingCount() != 0 {
		t.Fatalf("pending not cleared: %d", f.pendingCount())
	}
}
