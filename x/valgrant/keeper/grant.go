package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// IssueGrant creates a PermanentLockedAccount for a validator candidate, funds
// it with the locked principal + a liquid gas allowance, both sent FROM the
// valgrant module reserve pool. Source-grounded: NewBaseAccountWithAddress ->
// AccountKeeper.NewAccount -> NewPermanentLockedAccount(baseAcc, locked.Sort())
// -> SetAccount -> two SendCoinsFromModuleToAccount.
//
// Gotchas honored: EndTime is auto-0 (PermanentLockedAccount); coins are
// .Sort()ed; rejects if the account already exists or is blocked; the pool must
// hold locked+gas before the sends.
func (k Keeper) IssueGrant(
	ctx context.Context,
	granteeStr string,
	lockedCoins sdk.Coins,
	gasCoins sdk.Coins,
) error {
	// 1. decode grantee
	grantee, err := k.accountKeeper.AddressCodec().StringToBytes(granteeStr)
	if err != nil {
		return fmt.Errorf("invalid grantee address %q: %w", granteeStr, err)
	}

	// 2. validate amounts positive/sorted
	lockedCoins = lockedCoins.Sort()
	if !lockedCoins.IsValid() || !lockedCoins.IsAllPositive() {
		return fmt.Errorf("invalid locked amount: %s", lockedCoins)
	}
	if !gasCoins.IsZero() {
		gasCoins = gasCoins.Sort()
		if !gasCoins.IsValid() || !gasCoins.IsAllPositive() {
			return fmt.Errorf("invalid gas allowance: %s", gasCoins)
		}
	}

	// 3. reject if account already exists (must be fresh)
	if existing := k.accountKeeper.GetAccount(ctx, grantee); existing != nil {
		return fmt.Errorf("account %s already exists; grant requires a fresh account", granteeStr)
	}

	// 3b. reject blocked recipients
	if k.bankKeeper.BlockedAddr(grantee) {
		return fmt.Errorf("grantee address %s is blocked from receiving funds", granteeStr)
	}

	// 4. create base account with a fresh account number
	baseAcc := authtypes.NewBaseAccountWithAddress(grantee)
	baseAcc = k.accountKeeper.NewAccount(ctx, baseAcc).(*authtypes.BaseAccount)

	// 5. wrap in PermanentLockedAccount (EndTime auto 0; coins must be sorted)
	plva, err := vestingtypes.NewPermanentLockedAccount(baseAcc, lockedCoins)
	if err != nil {
		return fmt.Errorf("failed to create permanent locked account: %w", err)
	}

	// 6. store the vesting account
	k.accountKeeper.SetAccount(ctx, plva)

	// 7. send locked principal from the pool (immediately locked / OriginalVesting)
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, grantee, lockedCoins); err != nil {
		return fmt.Errorf("failed to send locked principal from pool: %w", err)
	}

	// 8. send liquid gas allowance from the pool (spendable)
	if !gasCoins.IsZero() {
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, grantee, gasCoins); err != nil {
			return fmt.Errorf("failed to send gas allowance from pool: %w", err)
		}
	}

	// 9. emit event
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent(
		"valgrant_issued",
		sdk.NewAttribute("grantee", granteeStr),
		sdk.NewAttribute("locked_amount", lockedCoins.String()),
		sdk.NewAttribute("gas_allowance", gasCoins.String()),
	))

	return nil
}
