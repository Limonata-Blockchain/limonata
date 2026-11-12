package keeper

import (
	"testing"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// REGRESSION — SLASH + co-located (commingled) self-bond, LOCKED-ONLY reclaim.
//
// A validator operator's OWN self-bond and the foundation grant principal are
// BOTH delegations from the grantee account to grant.ValidatorOp (the grantee's
// own validator). In Cosmos SDK x/staking these MERGE into a single Delegation
// object (one (delegator,validator) key). To BE a validator the operator MUST
// self-bond, so this co-location is structurally guaranteed, not an edge case.
//
// The FIX reclaims ONLY the LOCKED (vesting) shares of the merged delegation —
// exactly min(DelegatedVesting, delegation.Shares). Because shares are
// slash-invariant (a slash shrinks the validator's TOKEN pool, never the share
// counts), DelegatedVesting keeps equal to the number of locked shares, so the
// reclaim takes the grant's PROPORTIONALLY-SLASHED fair value and leaves the
// grantee's own (free) self-bond shares byte-for-byte intact.
//
// These probes model the REAL on-chain state: an active grant is a
// PermanentLockedAccount whose DelegatedVesting records the locked principal
// that has been bonded, and the post-slash delegation has (shares != tokens).
// ===========================================================================

// makeGrantPLVA installs a PermanentLockedAccount for the grantee with
// OriginalVesting = origVesting and DelegatedVesting = delegatedVesting (the
// locked principal that has been bonded). LockedCoins (in-account, never-bonded
// locked principal) = origVesting - delegatedVesting.
func makeGrantPLVA(t *testing.T, f *fixture, origVesting, delegatedVesting int64) *vestingtypes.PermanentLockedAccount {
	t.Helper()
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(origVesting))))
	if err != nil {
		t.Fatal(err)
	}
	if delegatedVesting > 0 {
		plva.DelegatedVesting = sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(delegatedVesting)))
	}
	f.ak.SetAccount(f.ctx, plva)
	return plva
}

// PROBE A — CAP PATH (the audit's exact numbers). Grant 1000 fully bonded,
// grantee commingles 1000 of their OWN funds at the SAME (own) validator ->
// merged 2000 shares. A 40% slash -> 1200 live tokens (grant-fair 600,
// self-fair 600). The FIX undelegates exactly the 1000 LOCKED shares -> 600
// tokens (the grant's fair value); the 1000 own self-bond shares (600 tokens)
// and the liquid gas allowance are preserved byte-for-byte.
func TestClawbackGrant_ColocatedSelfBond_CapPath_LockedOnly(t *testing.T) {
	f := newFixture(t)
	makeGrantPLVA(t, f, 1000, 1000) // 1000 grant, all bonded -> in-account locked 0
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(50))))
	// GrantedShares=1000: the module recorded 1000 locked shares at grant.ValidatorOp.
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	// merged delegation 1000 grant + 1000 own = 2000 shares; 40% slash -> 1200 tokens.
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000))
	f.sk.slash(f.granteeBz, f.valStr, math.NewInt(1200))

	liquidBefore := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "abandoned-slashed"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	reclaimed := math.LegacyMustNewDecFromStr(resp.PrincipalPending).TruncateInt()
	remTokens := f.sk.tokensOf(f.granteeBz, f.valStr)
	remShares := f.sk.sharesOf(f.granteeBz, f.valStr)
	liquidAfter := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount

	t.Logf("merged 2000 sh / 1200 tok (40%% slash): reclaimed=%s remaining tok=%s sh=%s liquid=%s->%s",
		reclaimed, remTokens, remShares, liquidBefore, liquidAfter)

	if !reclaimed.Equal(math.NewInt(600)) {
		t.Fatalf("reclaimed=%s want 600 (grant FAIR slashed value ONLY)", reclaimed)
	}
	if !remTokens.Equal(math.NewInt(600)) {
		t.Fatalf("own self-bond seized: remaining tokens=%s want 600 (byte-exact)", remTokens)
	}
	if !remShares.Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("own self-bond shares changed: remaining shares=%s want 1000 (byte-exact)", remShares)
	}
	if resp.PrincipalReturned != "0" {
		t.Fatalf("principal_returned=%s want 0 (all locked bonded; nothing in-account)", resp.PrincipalReturned)
	}
	if !liquidAfter.Equal(liquidBefore) || !liquidAfter.Equal(math.NewInt(50)) {
		t.Fatalf("liquid seized: before=%s after=%s want 50/50 (byte-exact)", liquidBefore, liquidAfter)
	}
}

// PROBE B — the old WHOLE-DELEGATION FALLBACK path. Same co-location, harder
// slash so the merged delegation is worth LESS than nominal: 2000 shares slashed
// 70% -> 600 tokens (< 1000 nominal). The OLD code fell back to `del.Shares` and
// took the ENTIRE 600 (seizing the 300 self-bond). The FIX still undelegates only
// the 1000 LOCKED shares -> 300 tokens (grant fair); the 1000 own shares (300
// tokens) stay bonded byte-for-byte.
func TestClawbackGrant_ColocatedSelfBond_FallbackPath_LockedOnly(t *testing.T) {
	f := newFixture(t)
	makeGrantPLVA(t, f, 1000, 1000)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(50))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	// merged 2000 shares; 70% slash -> 600 tokens (grant-fair 300, self-fair 300).
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000))
	f.sk.slash(f.granteeBz, f.valStr, math.NewInt(600))

	liquidBefore := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "abandoned-slashed-hard"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	reclaimed := math.LegacyMustNewDecFromStr(resp.PrincipalPending).TruncateInt()
	remTokens := f.sk.tokensOf(f.granteeBz, f.valStr)
	remShares := f.sk.sharesOf(f.granteeBz, f.valStr)
	liquidAfter := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount

	t.Logf("merged 2000 sh / 600 tok (70%% slash): reclaimed=%s remaining tok=%s sh=%s liquid=%s->%s",
		reclaimed, remTokens, remShares, liquidBefore, liquidAfter)

	if !reclaimed.Equal(math.NewInt(300)) {
		t.Fatalf("reclaimed=%s want 300 (grant FAIR slashed value ONLY; NOT the whole 600)", reclaimed)
	}
	if !remTokens.Equal(math.NewInt(300)) {
		t.Fatalf("own self-bond seized (whole-delegation grab): remaining tokens=%s want 300", remTokens)
	}
	if !remShares.Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("own self-bond shares changed: remaining shares=%s want 1000", remShares)
	}
	if !liquidAfter.Equal(liquidBefore) || !liquidAfter.Equal(math.NewInt(50)) {
		t.Fatalf("liquid seized: before=%s after=%s want 50/50", liquidBefore, liquidAfter)
	}
}

// PROBE C — partially in-account grant + small co-located self-bond, NO slash.
// PLVA: OriginalVesting 1000, DelegatedVesting 300 -> 700 still-locked in-account.
// Merged delegation 400 = 300 grant + 100 own self-bond. The FIX undelegates the
// 300 LOCKED shares (leaving the 100 own bonded), sweeps the 700 in-account locked
// immediately, and — since ALL 700 in-account locked is swept — leaves NO grant
// principal permanently unlocked. Total reclaim = 700 + 300 = 1000; own self-bond
// (100) and gas (25) preserved.
func TestClawbackGrant_ColocatedSelfBond_InAccountPlusBonded_NoLeftover(t *testing.T) {
	f := newFixture(t)
	plva := makeGrantPLVA(t, f, 1000, 300)
	// bank holds the 700 in-account locked principal + 25 gas (spendable).
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(725))))
	// GrantedShares=300: 300 locked shares bonded at grant.ValidatorOp (700 in-account).
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "25", ValidatorOp: f.valStr, Status: "active", GrantedShares: "300", TrackedShares: "400"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(400)) // 300 grant + 100 own, rate 1

	inAccountLockedBefore := plva.LockedCoins(f.ctx.BlockTime()).AmountOf(testDenom)
	if !inAccountLockedBefore.Equal(math.NewInt(700)) {
		t.Fatalf("setup: in-account locked=%s want 700", inAccountLockedBefore)
	}

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	remTokens := f.sk.tokensOf(f.granteeBz, f.valStr)
	granteeBal := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	poolBal := f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount
	returned := math.LegacyMustNewDecFromStr(resp.PrincipalReturned).TruncateInt()
	pending := math.LegacyMustNewDecFromStr(resp.PrincipalPending).TruncateInt()

	t.Logf("returned(now)=%s pending(bonded)=%s remaining self-bond tok=%s grantee liquid=%s pool=%s",
		returned, pending, remTokens, granteeBal, poolBal)

	if !returned.Equal(math.NewInt(700)) {
		t.Fatalf("principal_returned=%s want 700 (in-account locked swept)", returned)
	}
	if !pending.Equal(math.NewInt(300)) {
		t.Fatalf("principal_pending=%s want 300 (locked bonded shares only)", pending)
	}
	if !remTokens.Equal(math.NewInt(100)) {
		t.Fatalf("own self-bond seized: remaining tokens=%s want 100", remTokens)
	}
	// gas preserved; the pool received exactly the 700 immediate principal.
	if !granteeBal.Equal(math.NewInt(25)) {
		t.Fatalf("grantee liquid=%s want 25 (gas preserved)", granteeBal)
	}
	if !poolBal.Equal(math.NewInt(700)) {
		t.Fatalf("pool balance=%s want 700 (immediate principal only)", poolBal)
	}
	// NO leftover: every in-account locked token was swept, so nothing is left
	// permanently unlocked on the (now BaseAccount) grantee.
	leftover := inAccountLockedBefore.Sub(returned)
	if !leftover.IsZero() {
		t.Fatalf("leftover in-account principal left unlocked = %s want 0", leftover)
	}
	acc := f.ak.GetAccount(f.ctx, f.granteeBz)
	if _, stillVesting := acc.(*vestingtypes.PermanentLockedAccount); stillVesting {
		t.Fatal("expected PLVA unlocked to BaseAccount after full in-account sweep")
	}
}
