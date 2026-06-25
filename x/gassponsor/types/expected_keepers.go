package types

import (
	context "context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	contesttypes "github.com/cosmos/evm/x/contest/types"
)

// ContestReader is the subset of the x/contest keeper used to decide whether a tx's
// target is an admin-approved dApp. Satisfied by contestkeeper.Keeper.
type ContestReader interface {
	GetShowcase(ctx context.Context, addr string) (contesttypes.ShowcaseApp, bool)
}

// BankKeeper is the subset of the bank keeper this module needs (pool moves + mint).
type BankKeeper interface {
	GetAllBalances(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SendCoinsFromModuleToModule(ctx context.Context, senderModule, recipientModule string, amt sdk.Coins) error
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
}
