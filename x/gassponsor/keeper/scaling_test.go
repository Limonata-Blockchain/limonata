package keeper

import (
	"context"
	"testing"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/gassponsor/types"
)

// mockBank satisfies types.BankKeeper; only GetAllBalances is exercised here.
type mockBank struct{ coins sdk.Coins }

func (m mockBank) GetAllBalances(ctx context.Context, addr sdk.AccAddress) sdk.Coins { return m.coins }
func (m mockBank) SendCoinsFromModuleToModule(ctx context.Context, a, b string, amt sdk.Coins) error {
	return nil
}
func (m mockBank) MintCoins(ctx context.Context, name string, amt sdk.Coins) error { return nil }

// TestEffectiveAllowance proves the hybrid history-scaled allowance:
//
//	allowance = min(BaselineDaily, ColdStartDaily + heldLIMO / BalanceDivisor)
func TestEffectiveAllowance(t *testing.T) {
	addr := sdk.AccAddress([]byte("0123456789abcdef0123"))
	I := func(s string) math.Int {
		v, ok := math.NewIntFromString(s)
		if !ok {
			t.Fatalf("bad int %q", s)
		}
		return v
	}
	const baseline = "10000000000000000000" // 10 LIMO cap
	const cold = "100000000000000000"       // 0.1 LIMO cold-start

	cases := []struct {
		name    string
		balance string // aLIMO held
		cold    string
		divisor string
		want    string // aLIMO allowance
	}{
		{"dust account still gets the cold-start", "0", cold, "1", "100000000000000000"},
		{"5 LIMO held -> 5.1 (cold + 1:1 bonus)", "5000000000000000000", cold, "1", "5100000000000000000"},
		{"big holder capped at baseline", "50000000000000000000", cold, "1", baseline},
		{"divisor 10: 50 LIMO -> 5.1", "50000000000000000000", cold, "10", "5100000000000000000"},
		{"empty cold/divisor default to 0 and 1", "3000000000000000000", "", "", "3000000000000000000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			coins := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, I(c.balance)))
			k := Keeper{bank: mockBank{coins: coins}}
			p := types.Params{BaselineDaily: baseline, ColdStartDaily: c.cold, BalanceDivisor: c.divisor}
			got := k.effectiveAllowance(sdk.Context{}, p, addr)
			if !got.Equal(I(c.want)) {
				t.Fatalf("balance=%s cold=%q div=%q: got %s want %s", c.balance, c.cold, c.divisor, got, c.want)
			}
		})
	}
}
