package keeper

import (
	"testing"
	"time"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/x/gassponsor/types"
)

// hasEvent reports whether an event of the given type was emitted on ctx.
func hasEvent(ctx sdk.Context, typ string) bool {
	for _, e := range ctx.EventManager().Events() {
		if e.Type == typ {
			return true
		}
	}
	return false
}

// --- Feature 1: dapp_daily_cap (per-(UTC-day, contract) sponsorship cap) ---

// TestWithinDappDailyCap covers the unlimited semantics ("0"/""/negative/unparseable) and the
// enforced boundary (spent+amt <= cap) independent of the store state.
func TestWithinDappDailyCap(t *testing.T) {
	to := common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")
	k := Keeper{storeService: newMem()}
	amt := I(t, "400")
	// With an empty store dappSpentToday == 0, so the boundary is purely amt <= cap.
	cases := []struct {
		cap  string
		want bool
	}{
		{"", true},     // empty -> unlimited
		{"0", true},    // zero -> unlimited
		{"-5", true},   // negative -> unlimited
		{"xxx", true},  // unparseable -> unlimited
		{"400", true},  // 0+400 == cap -> within
		{"401", true},  // 0+400 < cap -> within
		{"399", false}, // 0+400 > cap -> over
	}
	for _, c := range cases {
		got := k.withinDappDailyCap(sdk.Context{}, types.Params{DappDailyCap: c.cap}, 0, &to, amt)
		if got != c.want {
			t.Fatalf("cap=%q amt=%s: got %v want %v", c.cap, amt, got, c.want)
		}
	}
}

// TestIsSponsoredDappDailyCap proves the per-(day,contract) cap: successive under-cap txs are
// sponsored via the dApp path (true,true) and accumulate the counter; the tx that would cross
// the cap falls through (here to user-paid, since held=0 has no baseline/onboarding) leaving the
// counter unchanged and emitting gassponsor_dapp_daily_capped; and the counter resets at the UTC
// day rollover so sponsorship resumes.
func TestIsSponsoredDappDailyCap(t *testing.T) {
	to := common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")
	appAddr := "0x00000000000000000000000000000000deadbeef" // lower-hex
	sender := sdk.AccAddress([]byte("sender_address_00001"))

	k := Keeper{
		storeService: newMem(),
		contest:      mockContest{addr: appAddr, approved: true, vm: "evm"},
		bank:         &capBank{held: math.ZeroInt(), minted: math.ZeroInt()}, // held 0 -> no baseline, no onboarding (disabled)
	}
	p := types.Params{
		Enabled:         true,
		DappPerTxFeeCap: "0",    // per-tx cap unlimited -> only the daily cap is exercised
		DappDailyCap:    "1000", // 1000 aLIMO / (day,contract)
	}
	fee := func(a string) sdk.Coins { return sdk.NewCoins(sdk.NewCoin(types.FeeDenom, I(t, a))) }

	day0 := time.Unix(1_700_000_000, 0).UTC()
	ctxAt := func(tm time.Time) sdk.Context {
		ctx := testCtx().WithBlockTime(tm)
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		return ctx
	}

	// Tx1: spent 0, 0+400 <= 1000 -> dApp path, spent -> 400.
	ctx := ctxAt(day0)
	if s, v := k.IsSponsored(ctx, sender, &to, fee("400")); !s || !v {
		t.Fatalf("tx1: want sponsored=true viaApp=true, got %v %v", s, v)
	}
	if got := k.DappSpentToday(ctx, to); !got.Equal(I(t, "400")) {
		t.Fatalf("tx1: dapp_spent_today=%s want 400", got)
	}

	// Tx2: spent 400, 400+400 <= 1000 -> dApp path, spent -> 800.
	ctx = ctxAt(day0.Add(time.Second))
	if s, v := k.IsSponsored(ctx, sender, &to, fee("400")); !s || !v {
		t.Fatalf("tx2: want sponsored=true viaApp=true, got %v %v", s, v)
	}
	if got := k.DappSpentToday(ctx, to); !got.Equal(I(t, "800")) {
		t.Fatalf("tx2: dapp_spent_today=%s want 800", got)
	}

	// Tx3: spent 800, 800+400 = 1200 > 1000 -> fall through. held=0 has no baseline/onboarding,
	// so it lands on user-paid (false,false); the counter must NOT move and the breaker fires.
	ctx = ctxAt(day0.Add(2 * time.Second))
	if s, v := k.IsSponsored(ctx, sender, &to, fee("400")); s || v {
		t.Fatalf("tx3 (over daily cap): want sponsored=false viaApp=false, got %v %v", s, v)
	}
	if got := k.DappSpentToday(ctx, to); !got.Equal(I(t, "800")) {
		t.Fatalf("tx3: dapp_spent_today=%s want 800 (unchanged)", got)
	}
	if !hasEvent(ctx, "gassponsor_dapp_daily_capped") {
		t.Fatal("tx3: expected gassponsor_dapp_daily_capped event")
	}

	// Tx4: next UTC day -> counter resets, sponsorship resumes at spent 0 -> 400.
	ctx = ctxAt(day0.Add(24 * time.Hour))
	if got := k.DappSpentToday(ctx, to); !got.IsZero() {
		t.Fatalf("tx4 (new day): dapp_spent_today=%s want 0 (reset)", got)
	}
	if s, v := k.IsSponsored(ctx, sender, &to, fee("400")); !s || !v {
		t.Fatalf("tx4: want sponsored=true viaApp=true, got %v %v", s, v)
	}
	if got := k.DappSpentToday(ctx, to); !got.Equal(I(t, "400")) {
		t.Fatalf("tx4: dapp_spent_today=%s want 400 (fresh day)", got)
	}
}

// --- Feature 2: onboarding_daily_cap (global daily onboarding-grant budget) ---

// TestIsSponsoredOnboardingDailyCap proves the GLOBAL daily onboarding budget: distinct cold
// wallets are onboarded (true,false) until the day's granted total would exceed the cap, after
// which further cold wallets are DENIED (fall through to user-paid); the global counter resets
// at the UTC day rollover. A large OnboardingGrant keeps the per-account lifetime budget from
// binding so only the daily cap is under test.
func TestIsSponsoredOnboardingDailyCap(t *testing.T) {
	k := Keeper{
		storeService: newMem(),
		bank:         &capBank{held: math.ZeroInt(), minted: math.ZeroInt()}, // held 0 -> onboarding path
	}
	p := types.Params{
		Enabled:            true,
		OnboardingGrant:    "100000", // large lifetime budget -> never binds here
		OnboardingDailyCap: "1000",   // global 1000 aLIMO / day
	}
	fee := func(a string) sdk.Coins { return sdk.NewCoins(sdk.NewCoin(types.FeeDenom, I(t, a))) }
	acct := func(tag string) sdk.AccAddress {
		var b [20]byte
		copy(b[:], "acct_"+tag) // first bytes differ by tag; rest zero-padded -> distinct 20-byte addrs
		return sdk.AccAddress(b[:])
	}

	day0 := time.Unix(1_700_000_000, 0).UTC()
	ctxAt := func(tm time.Time) sdk.Context {
		ctx := testCtx().WithBlockTime(tm)
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		return ctx
	}

	// Tx1 (wallet A): granted 0, +400 <= 1000 -> onboard, granted -> 400.
	ctx := ctxAt(day0)
	if s, v := k.IsSponsored(ctx, acct("A"), nil, fee("400")); !s || v {
		t.Fatalf("tx1: want sponsored=true viaApp=false, got %v %v", s, v)
	}
	if got := k.GrantedToday(ctx); !got.Equal(I(t, "400")) {
		t.Fatalf("tx1: granted_today=%s want 400", got)
	}

	// Tx2 (wallet B): granted 400, +400 <= 1000 -> onboard, granted -> 800.
	ctx = ctxAt(day0.Add(time.Second))
	if s, v := k.IsSponsored(ctx, acct("B"), nil, fee("400")); !s || v {
		t.Fatalf("tx2: want sponsored=true viaApp=false, got %v %v", s, v)
	}
	if got := k.GrantedToday(ctx); !got.Equal(I(t, "800")) {
		t.Fatalf("tx2: granted_today=%s want 800", got)
	}

	// Tx3 (wallet C): granted 800, +400 = 1200 > 1000 -> DENY, fall through to user-paid.
	ctx = ctxAt(day0.Add(2 * time.Second))
	if s, v := k.IsSponsored(ctx, acct("C"), nil, fee("400")); s || v {
		t.Fatalf("tx3 (over daily cap): want sponsored=false viaApp=false, got %v %v", s, v)
	}
	if got := k.GrantedToday(ctx); !got.Equal(I(t, "800")) {
		t.Fatalf("tx3: granted_today=%s want 800 (unchanged)", got)
	}
	// The denied wallet must not have burned any of its lifetime onboarding budget either.
	if used := k.OnboardingUsed(ctx, acct("C")); !used.IsZero() {
		t.Fatalf("tx3: denied wallet must not debit lifetime onboarding, got used=%s", used)
	}

	// Tx4: next UTC day -> global counter resets, onboarding resumes.
	ctx = ctxAt(day0.Add(24 * time.Hour))
	if got := k.GrantedToday(ctx); !got.IsZero() {
		t.Fatalf("tx4 (new day): granted_today=%s want 0 (reset)", got)
	}
	if s, v := k.IsSponsored(ctx, acct("D"), nil, fee("400")); !s || v {
		t.Fatalf("tx4: want sponsored=true viaApp=false, got %v %v", s, v)
	}
	if got := k.GrantedToday(ctx); !got.Equal(I(t, "400")) {
		t.Fatalf("tx4: granted_today=%s want 400 (fresh day)", got)
	}
}

// TestOnboardingDailyCapUnlimited proves cap "0"/"" means unlimited (legacy behaviour): many
// distinct cold wallets all onboard regardless of the running global total.
func TestOnboardingDailyCapUnlimited(t *testing.T) {
	for _, capVal := range []string{"0", ""} {
		k := Keeper{
			storeService: newMem(),
			bank:         &capBank{held: math.ZeroInt(), minted: math.ZeroInt()},
		}
		p := types.Params{Enabled: true, OnboardingGrant: "100000", OnboardingDailyCap: capVal}
		ctx := testCtx()
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		fee := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, I(t, "400")))
		for i := 0; i < 5; i++ {
			var b [20]byte
			copy(b[:], "onboardcap_"+string(rune('0'+i)))
			acct := sdk.AccAddress(b[:])
			if s, v := k.IsSponsored(ctx, acct, nil, fee); !s || v {
				t.Fatalf("cap=%q tx%d: want sponsored=true viaApp=false, got %v %v", capVal, i, s, v)
			}
		}
		if got := k.GrantedToday(ctx); !got.Equal(I(t, "2000")) { // 5 * 400, no cap
			t.Fatalf("cap=%q: expected unlimited granted 2000, got %s", capVal, got)
		}
	}
}
