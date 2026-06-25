package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// BurnPool permanently DESTROYS LIMO held by the valgrant reserve pool. The
// resolved coins are removed from the module account AND from total supply via
// bankKeeper.BurnCoins (the valgrant module account holds the Burner permission).
//
// amountStr is a decimal aLIMO amount. "0" or empty burns the ENTIRE current
// pool balance of the bond denom.
//
// Returns the amount actually burned. This is destructive and irreversible:
// reclaimed bootstrap capital removed this way can never return to any account.
func (k Keeper) BurnPool(ctx context.Context, amountStr string) (math.Int, error) {
	bondDenom, err := k.stakingKeeper.BondDenom(ctx)
	if err != nil {
		return math.ZeroInt(), err
	}

	// Resolve the module pool address + its current balance of the bond denom.
	poolAddr := k.accountKeeper.GetModuleAddress(types.ModuleName)
	if poolAddr == nil {
		return math.ZeroInt(), fmt.Errorf("valgrant module account not found")
	}
	poolBal := k.bankKeeper.GetBalance(ctx, poolAddr, bondDenom).Amount

	// Resolve the burn amount: 0/empty => the entire current pool balance.
	var burnAmt math.Int
	if amountStr == "" || amountStr == "0" {
		burnAmt = poolBal
	} else {
		amt, ok := math.NewIntFromString(amountStr)
		if !ok {
			return math.ZeroInt(), fmt.Errorf("invalid burn amount %q", amountStr)
		}
		if !amt.IsPositive() {
			return math.ZeroInt(), fmt.Errorf("burn amount must be positive, got %q", amountStr)
		}
		burnAmt = amt
	}

	if !burnAmt.IsPositive() {
		return math.ZeroInt(), fmt.Errorf("nothing to burn: valgrant pool balance is zero")
	}
	if burnAmt.GT(poolBal) {
		return math.ZeroInt(), fmt.Errorf("burn amount %s exceeds valgrant pool balance %s", burnAmt, poolBal)
	}

	coins := sdk.NewCoins(sdk.NewCoin(bondDenom, burnAmt))
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
		return math.ZeroInt(), fmt.Errorf("failed to burn valgrant pool coins: %w", err)
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent(
		"valgrant_pool_burned",
		sdk.NewAttribute("amount", coins.String()),
	))

	return burnAmt, nil
}
