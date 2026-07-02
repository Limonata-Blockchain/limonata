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

	// Global inflation circuit breaker: never mint more than RefillDailyMintCap aLIMO per UTC
	// day. Even a novel exploit that drains the pool cannot inflate supply past this per day.
	// Empty / "0" / non-positive cap => unlimited (legacy behaviour). day = unix/86400 mirrors
	// the per-account allowance bucket, so the counter self-resets at the day rollover.
	mintAmt := deficit
	day := uint64(ctx.BlockTime().UTC().Unix() / 86400)
	capped := false
	if cap, ok := math.NewIntFromString(p.RefillDailyMintCap); ok && cap.IsPositive() {
		mintedToday := k.mintedToday(ctx, day)
		remaining := cap.Sub(mintedToday)
		if !remaining.IsPositive() {
			// Already at/over the day's cap: mint nothing, signal the breaker tripped.
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"gassponsor_refill_capped",
				sdk.NewAttribute("deficit", deficit.String()),
				sdk.NewAttribute("minted_today", mintedToday.String()),
				sdk.NewAttribute("daily_cap", cap.String()),
			))
			return nil
		}
		if mintAmt.GT(remaining) {
			mintAmt = remaining
			capped = true
		}
	}

	coins := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, mintAmt))
	// gassponsor has Minter permission; mint to itself then move into the pool.
	if err := k.bank.MintCoins(ctx, types.ModuleName, coins); err != nil {
		return err
	}
	if err := k.bank.SendCoinsFromModuleToModule(ctx, types.ModuleName, types.GasPoolName, coins); err != nil {
		return err
	}
	k.setMintedToday(ctx, day, k.mintedToday(ctx, day).Add(mintAmt))
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"gassponsor_refill",
		sdk.NewAttribute("minted", mintAmt.String()),
	))
	if capped {
		// Minted only a partial deficit because the day's cap was hit this block.
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"gassponsor_refill_capped",
			sdk.NewAttribute("deficit", deficit.String()),
			sdk.NewAttribute("minted", mintAmt.String()),
			sdk.NewAttribute("daily_cap", p.RefillDailyMintCap),
		))
	}
	return nil
}
