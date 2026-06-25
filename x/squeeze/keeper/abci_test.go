package keeper_test

import (
	"context"
	"testing"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/evm/x/squeeze/keeper"
	"github.com/cosmos/evm/x/squeeze/types"
)

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
	fb := newFakeBank()
	feeColl := authtypes.NewModuleAddress(authtypes.FeeCollectorName).String()
	fb.bal[feeColl] = sdk.NewCoins(sdk.NewCoin(types.FeeDenom, math.NewInt(fee)))

	k := keeper.NewKeeper(fb, authtypes.FeeCollectorName)
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
	v, b, g := runSqueeze(t, 1000)
	if b != 400 || g != 100 || v != 500 {
		t.Fatalf("want 500/400/100, got validator=%d burn=%d grant=%d", v, b, g)
	}
}

func TestSqueezeSplitRoundingDustToValidator(t *testing.T) {
	// 1001: burn=floor(40.04)=400, grant=floor(10.01)=100, remainder 501 (dust to validator)
	v, b, g := runSqueeze(t, 1001)
	if b != 400 || g != 100 || v != 501 {
		t.Fatalf("want 501/400/100, got validator=%d burn=%d grant=%d", v, b, g)
	}
}

func TestSqueezeZeroFeeNoop(t *testing.T) {
	v, b, g := runSqueeze(t, 0)
	if v != 0 || b != 0 || g != 0 {
		t.Fatalf("zero-fee block should be a no-op, got %d/%d/%d", v, b, g)
	}
}
