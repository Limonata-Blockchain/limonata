package types

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AccountKeeper is the subset used to detect module-account destinations, which are
// exempt from the net-seller cap (sending to staking/gov/etc. is not a market sale).
type AccountKeeper interface {
	GetAccount(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
}
