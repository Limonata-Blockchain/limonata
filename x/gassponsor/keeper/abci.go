package keeper

import (
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/evm/x/gassponsor/types"
)

// BeginBlock runs AFTER x/squeeze (which recycles 10% of the prior block's
// fee_collector into the pool) and BEFORE x/distribution. For sponsored txs the pool
// paid the full fee while only ~10% recycles back, so it net-drains; refill by MINTING
// the deficit back up to MinPoolBalance. Refill-to-target self-heals rounding/dust and
// needs no perfectly accurate per-block tally. This is what makes the pool "infinite".
func (k Keeper) BeginBlock(ctx sdk.Context) error {
	p := k.GetParams(ctx)
	if !p.RefillEnabled {
		return nil
	}
	target, ok := math.NewIntFromString(p.MinPoolBalance)
	if !ok || !target.IsPositive() {
		return nil
	}
	poolAddr := authtypes.NewModuleAddress(types.GasPoolName)
	bal := k.bank.GetAllBalances(ctx, poolAddr).AmountOf(types.FeeDenom)
	if bal.GTE(target) {
		return nil
	}
	deficit := target.Sub(bal)
	coins := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, deficit))
	// gassponsor has Minter permission; mint to itself then move into the pool.
	if err := k.bank.MintCoins(ctx, types.ModuleName, coins); err != nil {
		return err
	}
	if err := k.bank.SendCoinsFromModuleToModule(ctx, types.ModuleName, types.GasPoolName, coins); err != nil {
		return err
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"gassponsor_refill",
		sdk.NewAttribute("minted", deficit.String()),
	))
	return nil
}
