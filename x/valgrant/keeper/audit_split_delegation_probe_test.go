package keeper

import (
	"testing"

	"cosmossdk.io/math"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// REGRESSION - HIGH-A-CROSS: per-validator granted-share ledger closes the
// MULTI-VALIDATOR / split / redelegate topology.
//
// The old reclaim keyed off the account-GLOBAL DelegatedVesting, which points at
// the wrong validator once the locked grant and the grantee's own self-bond live
// at DIFFERENT validators. The fix records the grant's shares PER-VALIDATOR
// (grant.GrantedShares, seeded by the module-performed delegation at issuance) and
// reclaims min(GrantedShares, live delegation shares) at grant.ValidatorOp, never
// the account-global aggregate.
//
// HIGH-ERODE (fixed 2026-08-15, hooks.go clamp): GrantedShares is now clamped DOWN
// to the live share count and never raised, so the erosion sequence - grantee
// self-bonds their own coins at ValidatorOp, then withdraws them - can no longer
// drive GrantedShares to zero and leave the clawback reclaiming nothing.
//
// The probes below assert the CURRENT, WEAKER promise on purpose: bounded loss
// (the grantee never loses more than the grant), NOT per-source tracing. Shares
// are fungible; a clawback may consume shares the grantee funded at ValidatorOp,
// and their own value is preserved in aggregate across validators. Redelegation
// out of ValidatorOp remains a partial evasion. Do not "restore" the old wording
// above these probes: it contradicts what they now verify.
//
// These probes drive the REAL reconcile via the mock's hook-firing helpers
// (redelegateHook / addDelegationHook invoke the actual AfterDelegationModified /
// BeforeDelegationRemoved code), so the ledger the clawback reads is authentic.
// ===========================================================================

// REGRESSION - SPLIT, NO SLASH (was: own self-bond fully SEIZED). The module
// delegated the grant to grant.ValidatorOp (vGrant); the grantee then redelegates
// the WHOLE grant to vOther and self-bonds their OWN funds at vGrant. The hook
// decremented GrantedShares to 0 as the grant left vGrant, so the clawback touches
// NOTHING at vGrant - the grantee's own self-bond is fully preserved and the grant
// (now at vOther) is left where it went (benign under-reclaim).
func TestSplitDelegation_OwnSelfBondNeverSeized_NoSlash(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr      // grant.ValidatorOp (0x22), sorts FIRST
	vOther := valoper(0x55) // a different validator, sorts LAST

	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000)) // module-placed grant at vGrant

	// Grantee redelegates the WHOLE grant vGrant -> vOther (hook: GrantedShares->0),
	// then self-bonds 1000 of their OWN funds at vGrant.
	f.sk.redelegateHook(f.ctx, f.granteeBz, vGrant, vOther, math.LegacyNewDec(1000))
	f.sk.addDelegationHook(f.ctx, f.granteeBz, vGrant, math.NewInt(1000))

	// Ledger followed the grant off vGrant.
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if parseDecOrZero(g.GrantedShares).IsPositive() {
		t.Fatalf("GrantedShares=%q want 0 (grant fully redelegated away from vGrant)", g.GrantedShares)
	}

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	ownAtGrantVal := f.sk.tokensOf(f.granteeBz, vGrant) // the grantee's OWN self-bond
	grantAtOther := f.sk.tokensOf(f.granteeBz, vOther)  // the grant, moved away
	t.Logf("split/no-slash FIXED: pending=%s  vGrant(OWN self-bond)=%s  vOther(grant)=%s",
		resp.PrincipalPending, ownAtGrantVal, grantAtOther)

	if resp.PrincipalPending != "0" || resp.PrincipalReturned != "0" {
		t.Fatalf("returned/pending=%q/%q want 0/0 (own self-bond must NOT be seized)", resp.PrincipalReturned, resp.PrincipalPending)
	}
	if !ownAtGrantVal.Equal(math.NewInt(1000)) {
		t.Fatalf("own self-bond at vGrant=%s want 1000 (fully preserved)", ownAtGrantVal)
	}
	if !grantAtOther.Equal(math.NewInt(1000)) {
		t.Fatalf("grant at vOther=%s want 1000 (untouched; reclaim never chases it)", grantAtOther)
	}
}

// REGRESSION - THE MISSION CASE: cross-validator commingle + PARTIAL redelegate +
// slash. Grant 1000 at vGrant; grantee commingles 500 of their OWN funds at vGrant
// (merged 1500); then redelegates 400 away to vOther; then vGrant is SLASHED 50%.
//
// ATTRIBUTION (HIGH-ERODE): an outflow from grant.ValidatorOp is charged to the
// grantee's FREE shares first, so the 400 that left are read as the grantee's own
// and GrantedShares stays 1000 (the clamp only bites when the live count falls
// below the grant). The clawback then reclaims the fair slashed value of the 1000
// locked shares (500 of the 550 live tokens) and the grantee keeps their own
// contribution in AGGREGATE VALUE across validators: 400 at vOther (moved out
// before the slash) + 50 at vGrant (their 100 remaining shares, halved by the
// slash) = 450, exactly the fair value of the 500 they put in.
//
// Before the HIGH-ERODE fix this test asserted the opposite policy (decrease
// charged to the GRANT first): GrantedShares fell to 600, the reclaim was 300 and
// the grantee kept 650 - i.e. 200 of foundation principal leaked to the grantee on
// every partial move. That grant-first rule is exactly what let a grantee zero
// their clawback exposure by cycling their own liquid (audit_erosion_probe_test.go),
// so the location-specific promise ("the grantee's own shares AT vGrant are never
// touched") has been replaced by the aggregate-value promise asserted here.
func TestSplitDelegation_PartialRedelegate_Slashed_OwnValuePreservedInAggregate(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr      // grant.ValidatorOp
	vOther := valoper(0x55) // redelegation destination

	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000)) // module-placed grant

	// Commingle 500 OWN self-bond at vGrant (merged 1500; GrantedShares stays 1000).
	f.sk.addDelegationHook(f.ctx, f.granteeBz, vGrant, math.NewInt(500))
	// Redelegate 400 vGrant -> vOther. Live shares here 1500 -> 1100, still above
	// the grant's 1000, so the clamp leaves GrantedShares at 1000.
	f.sk.redelegateHook(f.ctx, f.granteeBz, vGrant, vOther, math.LegacyNewDec(400))

	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if !parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("GrantedShares=%q want 1000 (1100 live shares still cover the whole grant)", g.GrantedShares)
	}

	// vGrant SLASHED 50%: 1100 shares now back only 550 tokens. Slashing leaves
	// share counts intact.
	f.sk.slash(f.granteeBz, vGrant, math.NewInt(550))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil-partial-redelegate"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	reclaimed := math.LegacyMustNewDecFromStr(resp.PrincipalPending).TruncateInt()
	ownSharesAfter := f.sk.sharesOf(f.granteeBz, vGrant)
	ownTokensAfter := f.sk.tokensOf(f.granteeBz, vGrant)
	grantAtOther := f.sk.tokensOf(f.granteeBz, vOther)
	t.Logf("mission case (free-first): reclaimed=%s  left at vGrant %s sh / %s tok  at vOther=%s",
		reclaimed, ownSharesAfter, ownTokensAfter, grantAtOther)

	// Reclaim = fair slashed value of the 1000 locked shares at rate 0.5.
	if !reclaimed.Equal(math.NewInt(500)) {
		t.Fatalf("reclaimed=%s want 500 (fair value of the 1000 locked shares at rate 0.5)", reclaimed)
	}
	// The grantee keeps 100 shares here (50 tokens after the slash)...
	if !ownSharesAfter.Equal(math.LegacyNewDec(100)) {
		t.Fatalf("shares left at vGrant=%s want 100", ownSharesAfter)
	}
	if !ownTokensAfter.Equal(math.NewInt(50)) {
		t.Fatalf("tokens left at vGrant=%s want 50", ownTokensAfter)
	}
	// ...plus the 400 they moved to vOther: 450 total, the fair value of the 500
	// they contributed (400 moved out pre-slash, 100 halved by the slash).
	if !grantAtOther.Equal(math.NewInt(400)) {
		t.Fatalf("tokens at vOther=%s want 400 (untouched by the clawback)", grantAtOther)
	}
	if got := ownTokensAfter.Add(grantAtOther); !got.Equal(math.NewInt(450)) {
		t.Fatalf("grantee own aggregate=%s want 450 (own 500 contribution, fairly slashed)", got)
	}
	// And the reclaim can never exceed the grant's own share count.
	if reclaimed.GT(math.NewInt(1000)) {
		t.Fatalf("reclaimed=%s exceeds the nominal grant (1000)", reclaimed)
	}
}

// REGRESSION - GRANT INTO A PRE-SLASHED VALIDATOR (was: foundation UNDER-reclaim).
// When the grant is delegated into a validator whose exchange rate is already
// below 1, the same locked principal mints MORE shares than tokens. Because the
// module records the ACTUAL minted SHARES (not the token count), GrantedShares is
// the full 2000 shares, so the clawback reclaims the WHOLE grant value - no
// under-reclaim / evasion.
func TestSplitDelegation_GrantIntoPreSlashedValidator_FullReclaim(t *testing.T) {
	f := newFixture(t)
	vGrant := f.valStr

	// The module delegated 1000 grant tokens into a rate-0.5 validator -> 2000 shares.
	// GrantedShares records the true 2000 shares (a token-based read would see 1000).
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "2000", TrackedShares: "2000"})
	f.sk.dels[string(f.granteeBz.Bytes())] = map[string]*mockDel{
		vGrant: {shares: math.LegacyNewDec(2000), tokens: math.NewInt(1000)},
	}

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}

	reclaimed := math.LegacyMustNewDecFromStr(resp.PrincipalPending).TruncateInt()
	remTokens := f.sk.tokensOf(f.granteeBz, vGrant)
	t.Logf("pre-slashed validator FIXED: grant worth 1000, reclaimed=%s, left with grantee=%s", reclaimed, remTokens)

	if !reclaimed.Equal(math.NewInt(1000)) {
		t.Fatalf("reclaimed=%s want 1000 (full grant value; no under-reclaim)", reclaimed)
	}
	if !remTokens.IsZero() {
		t.Fatalf("grant left with grantee=%s want 0 (fully reclaimed)", remTokens)
	}
}
