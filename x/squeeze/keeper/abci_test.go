package keeper_test

import (
	"context"
	"testing"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/evm/x/squeeze/keeper"
	"github.com/cosmos/evm/x/squeeze/types"
)

// memKV is a tiny in-memory KVStoreService/KVStore for the params blob.
type memKV struct{ m map[string][]byte }

func newMem() *memKV { return &memKV{m: map[string][]byte{}} }

func (s *memKV) OpenKVStore(context.Context) corestore.KVStore           { return s }
func (s *memKV) Get(k []byte) ([]byte, error)                            { return s.m[string(k)], nil }
func (s *memKV) Has(k []byte) (bool, error)                              { _, ok := s.m[string(k)]; return ok, nil }
func (s *memKV) Set(k, v []byte) error                                   { s.m[string(k)] = v; return nil }
func (s *memKV) Delete(k []byte) error                                   { delete(s.m, string(k)); return nil }
func (s *memKV) Iterator(_, _ []byte) (corestore.Iterator, error)        { panic("unused") }
func (s *memKV) ReverseIterator(_, _ []byte) (corestore.Iterator, error) { panic("unused") }

// fakeBank is an in-memory BankKeeper that tracks balances per module-account
// address and the total burned, so we can assert the Squeeze split exactly.
type fakeBank struct {
	bal    map[string]sdk.Coins
	burned sdk.Coins
}

func newFakeBank() *fakeBank { return &fakeBank{bal: map[string]sdk.Coins{}, burned: sdk.NewCoins()} }

func (f *fakeBank) GetAllBalances(_ context.Context, addr sdk.AccAddress) sdk.Coins {
	return f.bal[addr.String()]
}
func (f *fakeBank) SendCoinsFromModuleToModule(_ context.Context, from, to string, amt sdk.Coins) error {
	fa := authtypes.NewModuleAddress(from).String()
	ta := authtypes.NewModuleAddress(to).String()
	f.bal[fa] = f.bal[fa].Sub(amt...)
	f.bal[ta] = f.bal[ta].Add(amt...)
	return nil
}
func (f *fakeBank) BurnCoins(_ context.Context, mod string, amt sdk.Coins) error {
	a := authtypes.NewModuleAddress(mod).String()
	f.bal[a] = f.bal[a].Sub(amt...)
	f.burned = f.burned.Add(amt...)
	return nil
}

func amtOf(c sdk.Coins) int64 { return c.AmountOf(types.FeeDenom).Int64() }

func runSqueeze(t *testing.T, fee int64) (validator, burned, grant int64) {
	t.Helper()
	return runSqueezeParams(t, fee, nil)
}

// runSqueezeParams runs one split. If p is nil the keeper falls back to DefaultParams
// (20% burn / 20% grant / 60% validators); otherwise the given governable split is set.
func runSqueezeParams(t *testing.T, fee int64, p *types.Params) (validator, burned, grant int64) {
	t.Helper()
	fb := newFakeBank()
	feeColl := authtypes.NewModuleAddress(authtypes.FeeCollectorName).String()
	fb.bal[feeColl] = sdk.NewCoins(sdk.NewCoin(types.FeeDenom, math.NewInt(fee)))

	k := keeper.NewKeeper(newMem(), fb, authtypes.FeeCollectorName)
	if p != nil {
		if err := k.SetParams(sdk.Context{}, *p); err != nil {
			t.Fatalf("SetParams error: %v", err)
		}
	}
	if err := k.BeginBlock(sdk.Context{}); err != nil {
		t.Fatalf("BeginBlock error: %v", err)
	}
	validator = amtOf(fb.bal[feeColl]) // remainder left for x/distribution
	burned = amtOf(fb.burned)
	grant = amtOf(fb.bal[authtypes.NewModuleAddress(types.GasPoolName).String()])
	// the transient squeeze account must be empty
	if sq := amtOf(fb.bal[authtypes.NewModuleAddress(types.ModuleName).String()]); sq != 0 {
		t.Fatalf("squeeze module account not drained: %d", sq)
	}
	// conservation
	if validator+burned+grant != fee {
		t.Fatalf("conservation broken: %d+%d+%d != %d", validator, burned, grant, fee)
	}
	return
}

func TestSqueezeSplitExact(t *testing.T) {
	// DefaultParams: burn 20% / grant 20% / validators 60%.
	v, b, g := runSqueeze(t, 1000)
	if b != 200 || g != 200 || v != 600 {
		t.Fatalf("want 600/200/200, got validator=%d burn=%d grant=%d", v, b, g)
	}
}

func TestSqueezeSplitRoundingDustToValidator(t *testing.T) {
	// 1001 @ 20/20: burn=floor(200.2)=200, grant=floor(200.2)=200, remainder 601 (dust to validator)
	v, b, g := runSqueeze(t, 1001)
	if b != 200 || g != 200 || v != 601 {
		t.Fatalf("want 601/200/200, got validator=%d burn=%d grant=%d", v, b, g)
	}
}

func TestSqueezeZeroFeeNoop(t *testing.T) {
	v, b, g := runSqueeze(t, 0)
	if v != 0 || b != 0 || g != 0 {
		t.Fatalf("zero-fee block should be a no-op, got %d/%d/%d", v, b, g)
	}
}

// TestSqueezeGovernableSplit proves BeginBlock reads the split from params, not consts:
// a gov-set 40/10 split reproduces the OLD 50/40/10 behaviour on the same keeper.
func TestSqueezeGovernableSplit(t *testing.T) {
	p := types.Params{BurnBps: 4000, GrantBps: 1000} // legacy split
	v, b, g := runSqueezeParams(t, 1000, &p)
	if b != 400 || g != 100 || v != 500 {
		t.Fatalf("gov split 40/10: want 500/400/100, got validator=%d burn=%d grant=%d", v, b, g)
	}
}
