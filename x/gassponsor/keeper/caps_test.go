package keeper

import (
	"context"
	"testing"
	"time"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/ethereum/go-ethereum/common"

	contesttypes "github.com/cosmos/evm/x/contest/types"
	"github.com/cosmos/evm/x/gassponsor/types"
)

// memKV is a tiny in-memory KVStoreService/KVStore (keeper uses only Get/Set here).
type memKV struct{ m map[string][]byte }

func newMem() *memKV { return &memKV{m: map[string][]byte{}} }

func (s *memKV) OpenKVStore(context.Context) corestore.KVStore          { return s }
func (s *memKV) Get(k []byte) ([]byte, error)                           { return s.m[string(k)], nil }
func (s *memKV) Has(k []byte) (bool, error)                             { _, ok := s.m[string(k)]; return ok, nil }
func (s *memKV) Set(k, v []byte) error                                  { s.m[string(k)] = v; return nil }
func (s *memKV) Delete(k []byte) error                                  { delete(s.m, string(k)); return nil }
func (s *memKV) Iterator(_, _ []byte) (corestore.Iterator, error)        { panic("unused") }
func (s *memKV) ReverseIterator(_, _ []byte) (corestore.Iterator, error) { panic("unused") }

// mockContest is a ContestReader that returns a single approved app by address.
type mockContest struct {
	addr     string // lower-hex
	approved bool
	vm       string
}

func (m mockContest) GetShowcase(_ context.Context, addr string) (contesttypes.ShowcaseApp, bool) {
	if addr != m.addr {
		return contesttypes.ShowcaseApp{}, false
	}
	return contesttypes.ShowcaseApp{Address: m.addr, Approved: m.approved, VM: m.vm}, true
}

// capBank lets a test control both the sender's held balance (for effectiveAllowance) and
// the pool's balance (for the refill deficit), and records how much was minted.
type capBank struct {
	held   math.Int // returned by GetAllBalances for ANY address
	minted math.Int
}

func (b *capBank) GetAllBalances(_ context.Context, _ sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins(sdk.NewCoin(types.FeeDenom, b.held))
}
func (b *capBank) SendCoinsFromModuleToModule(_ context.Context, _, _ string, _ sdk.Coins) error {
	return nil
}
func (b *capBank) MintCoins(_ context.Context, _ string, amt sdk.Coins) error {
	b.minted = b.minted.Add(amt.AmountOf(types.FeeDenom))
	return nil
}

func I(t *testing.T, s string) math.Int {
	t.Helper()
	v, ok := math.NewIntFromString(s)
	if !ok {
		t.Fatalf("bad int %q", s)
	}
	return v
}

func testCtx() sdk.Context {
	return sdk.Context{}.
		WithBlockTime(time.Unix(1_700_000_000, 0).UTC()).
		WithEventManager(sdk.NewEventManager())
}

// --- Feature 1: dapp_per_tx_fee_cap ---

func TestWithinDappCap(t *testing.T) {
	k := Keeper{}
	amt := I(t, "1000")
	cases := []struct {
		cap  string
		want bool
	}{
		{"", true},      // empty -> unlimited
		{"0", true},     // zero -> unlimited
		{"-5", true},    // negative -> unlimited
		{"xxx", true},   // unparseable -> unlimited
		{"1000", true},  // fee == cap -> within
		{"1001", true},  // fee < cap -> within
		{"999", false},  // fee > cap -> over
	}
	for _, c := range cases {
		got := k.withinDappCap(types.Params{DappPerTxFeeCap: c.cap}, amt)
		if got != c.want {
			t.Fatalf("cap=%q amt=%s: got %v want %v", c.cap, amt, got, c.want)
		}
	}
}

// TestIsSponsoredDappCap proves: (a) fee within cap is sponsored via the dApp path
// (true,true) with NO baseline debit; (b) fee over cap falls through to baseline and,
// when baseline covers it, is sponsored via the baseline path (true,false) WITH a debit;
// (c) fee over cap with baseline too small is not sponsored at all (false,false).
func TestIsSponsoredDappCap(t *testing.T) {
	to := common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")
	appAddr := "0x00000000000000000000000000000000deadbeef" // lower-hex
	sender := sdk.AccAddress([]byte("sender_address_00001"))

	newK := func(held string) (Keeper, sdk.Context) {
		k := Keeper{
			storeService: newMem(),
			contest:      mockContest{addr: appAddr, approved: true, vm: "evm"},
			bank:         &capBank{held: I(t, held), minted: math.ZeroInt()},
		}
		p := types.Params{
			Enabled:         true,
			DappPerTxFeeCap: "1000000000000000000", // 1 LIMO cap
			BaselineDaily:   "10000000000000000000", // 10 LIMO baseline cap
			ColdStartDaily:  "0",
			BalanceDivisor:  "1",
		}
		ctx := testCtx()
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		return k, ctx
	}
	fee := func(a string) sdk.Coins { return sdk.NewCoins(sdk.NewCoin(types.FeeDenom, I(t, a))) }

	// (a) within cap -> dApp path, no baseline debit.
	k, ctx := newK("0")
	sponsored, viaApp := k.IsSponsored(ctx, sender, &to, fee("500000000000000000")) // 0.5 LIMO <= 1 LIMO
	if !sponsored || !viaApp {
		t.Fatalf("within cap: want sponsored=true viaApp=true, got %v %v", sponsored, viaApp)
	}
	if used := k.AllowanceUsed(ctx, sender); !used.IsZero() {
		t.Fatalf("within cap: dApp path must NOT debit baseline, got used=%s", used)
	}

	// (b) over cap, baseline covers -> falls through to baseline path (true,false), debited.
	k, ctx = newK("100000000000000000000") // holds 100 LIMO -> allowance capped at 10 LIMO baseline
	over := "2000000000000000000"          // 2 LIMO > 1 LIMO cap, but <= 10 LIMO baseline
	sponsored, viaApp = k.IsSponsored(ctx, sender, &to, fee(over))
	if !sponsored || viaApp {
		t.Fatalf("over cap w/ baseline: want sponsored=true viaApp=false, got %v %v", sponsored, viaApp)
	}
	if used := k.AllowanceUsed(ctx, sender); !used.Equal(I(t, over)) {
		t.Fatalf("over cap w/ baseline: expected baseline debit %s, got %s", over, used)
	}

	// (c) over cap, baseline too small -> not sponsored at all (user pays).
	k, ctx = newK("0") // no holdings, cold-start 0 -> zero allowance
	sponsored, viaApp = k.IsSponsored(ctx, sender, &to, fee(over))
	if sponsored || viaApp {
		t.Fatalf("over cap w/o baseline: want sponsored=false viaApp=false, got %v %v", sponsored, viaApp)
	}
}

// --- Feature 2: refill_daily_mint_cap ---

// TestRefillDailyMintCap proves the mint stops at the daily cap, emits gassponsor_refill_capped,
// and the counter resets at the UTC day rollover.
func TestRefillDailyMintCap(t *testing.T) {
	bank := &capBank{held: math.ZeroInt(), minted: math.ZeroInt()} // pool always reads 0 -> deficit = target
	k := Keeper{storeService: newMem(), bank: bank}
	p := types.Params{
		Enabled:            true,
		RefillEnabled:      true,
		MinPoolBalance:     "1000", // target; pool bal is 0, so deficit is 1000/block
		RefillDailyMintCap: "1500", // at most 1500 aLIMO minted per UTC day
	}

	day0 := time.Unix(1_700_000_000, 0).UTC() // some fixed day
	mkCtx := func(tm time.Time) sdk.Context {
		ctx := testCtx().WithBlockTime(tm)
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		return ctx
	}
	hasCapped := func(ctx sdk.Context) bool {
		for _, e := range ctx.EventManager().Events() {
			if e.Type == "gassponsor_refill_capped" {
				return true
			}
		}
		return false
	}

	// Block 1: deficit 1000, remaining 1500 -> mint 1000, no cap event.
	ctx := mkCtx(day0)
	if err := k.BeginBlock(ctx); err != nil {
		t.Fatal(err)
	}
	if got := k.MintedToday(ctx); !got.Equal(I(t, "1000")) {
		t.Fatalf("block1: minted_today=%s want 1000", got)
	}
	if hasCapped(ctx) {
		t.Fatal("block1: should not be capped yet")
	}

	// Block 2: deficit 1000, remaining 500 -> mint 500 (partial), cap event fires.
	ctx = mkCtx(day0.Add(time.Second))
	if err := k.BeginBlock(ctx); err != nil {
		t.Fatal(err)
	}
	if got := k.MintedToday(ctx); !got.Equal(I(t, "1500")) {
		t.Fatalf("block2: minted_today=%s want 1500 (cap)", got)
	}
	if !hasCapped(ctx) {
		t.Fatal("block2: expected gassponsor_refill_capped (partial mint)")
	}

	// Block 3: already at cap -> mint 0, cap event fires again.
	ctx = mkCtx(day0.Add(2 * time.Second))
	before := bank.minted
	if err := k.BeginBlock(ctx); err != nil {
		t.Fatal(err)
	}
	if !bank.minted.Equal(before) {
		t.Fatalf("block3: expected zero additional mint, minted went %s -> %s", before, bank.minted)
	}
	if got := k.MintedToday(ctx); !got.Equal(I(t, "1500")) {
		t.Fatalf("block3: minted_today=%s want 1500 (unchanged)", got)
	}
	if !hasCapped(ctx) {
		t.Fatal("block3: expected gassponsor_refill_capped (fully capped)")
	}

	// Block 4: next UTC day -> counter resets, mint resumes.
	ctx = mkCtx(day0.Add(24 * time.Hour))
	if err := k.BeginBlock(ctx); err != nil {
		t.Fatal(err)
	}
	if got := k.MintedToday(ctx); !got.Equal(I(t, "1000")) {
		t.Fatalf("block4 (new day): minted_today=%s want 1000 (reset)", got)
	}
	if hasCapped(ctx) {
		t.Fatal("block4: new day should not be capped")
	}
}

// TestRefillUnlimitedWhenCapZero proves "0"/empty cap means unlimited (legacy behaviour).
func TestRefillUnlimitedWhenCapZero(t *testing.T) {
	for _, capVal := range []string{"0", ""} {
		bank := &capBank{held: math.ZeroInt(), minted: math.ZeroInt()}
		k := Keeper{storeService: newMem(), bank: bank}
		p := types.Params{Enabled: true, RefillEnabled: true, MinPoolBalance: "1000000", RefillDailyMintCap: capVal}
		ctx := testCtx()
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5; i++ {
			if err := k.BeginBlock(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if !bank.minted.Equal(I(t, "5000000")) { // 5 blocks * 1,000,000 deficit, no cap
			t.Fatalf("cap=%q: expected unlimited mint 5000000, got %s", capVal, bank.minted)
		}
	}
}
