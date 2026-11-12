package interfaces

import (
	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// NetCapChecker enforces the net-seller cap on NATIVE EVM value transfers (eth tx with
// `value`), which commit via UncheckedSetBalance and therefore bypass the x/bank
// SendRestriction. Implemented by x/netcap/keeper.Keeper. nil = disabled.
type NetCapChecker interface {
	CheckAndRecord(ctx sdk.Context, from, to sdk.AccAddress, amount sdkmath.Int) error
}
