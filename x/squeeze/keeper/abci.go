package keeper

import (
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/evm/x/squeeze/types"
)

// BeginBlock runs immediately BEFORE x/distribution. It reads the materialized
// fee_collector balance for FeeDenom and splits it using the GOVERNABLE params
// (params.BurnBps / params.GrantBps; default 20% / 20%):
//   - BurnBps  is burned (the only burn on the chain),
//   - GrantBps is recycled into the gas pool (gasless loop),
//   - the remainder (validator slice + integer rounding dust) is LEFT in
//     fee_collector so x/distribution allocates it normally (PoS correctness).
// Conservation holds every block: burn + grant + remainder == fee.
func (k Keeper) BeginBlock(ctx sdk.Context) error {
	feeCollectorAddr := authtypes.NewModuleAddress(k.feeCollectorName)
	amt := k.bankKeeper.GetAllBalances(ctx, feeCollectorAddr).AmountOf(types.FeeDenom)
	if !amt.IsPositive() {
		return nil
	}

	// Governable split (Validate guarantees burn+grant <= BpsDenom, so the remainder
	// left for x/distribution is always non-negative).
	p := k.GetParams(ctx)
	bpsDenom := math.NewInt(types.BpsDenom)
	burnAmt := amt.Mul(math.NewIntFromUint64(uint64(p.BurnBps))).Quo(bpsDenom)
	grantAmt := amt.Mul(math.NewIntFromUint64(uint64(p.GrantBps))).Quo(bpsDenom)
	moved := burnAmt.Add(grantAmt)
	if !moved.IsPositive() {
		return nil
	}

	// Pull the burn+grant slice out of fee_collector into this module account.
	if err := k.bankKeeper.SendCoinsFromModuleToModule(
		ctx, k.feeCollectorName, types.ModuleName,
		sdk.NewCoins(sdk.NewCoin(types.FeeDenom, moved)),
	); err != nil {
		return err
	}

	if burnAmt.IsPositive() {
		if err := k.bankKeeper.BurnCoins(
			ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin(types.FeeDenom, burnAmt)),
		); err != nil {
			return err
		}
	}

	if grantAmt.IsPositive() {
		if err := k.bankKeeper.SendCoinsFromModuleToModule(
			ctx, types.ModuleName, types.GasPoolName,
			sdk.NewCoins(sdk.NewCoin(types.FeeDenom, grantAmt)),
		); err != nil {
			return err
		}
	}

	// The remaining ~50% + dust stays in fee_collector for x/distribution.
	return nil
}
