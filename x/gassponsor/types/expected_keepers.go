package types

import (
	context "context"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	contesttypes "github.com/cosmos/evm/x/contest/types"
)

// ContestReader is the subset of the x/contest keeper used to decide whether a tx's
// target is an admin-approved dApp. Satisfied by contestkeeper.Keeper.
type ContestReader interface {
	GetShowcase(ctx context.Context, addr string) (contesttypes.ShowcaseApp, bool)
}

// SponsorPoolReader is the subset of the x/sponsorpool keeper gassponsor needs: if a tx's
// target contract has developer-funded escrow, Reserve debits it and returns true (the gas
// pool then pays the fee, made whole by the deposit). Satisfied by sponsorpoolkeeper.Keeper.
type SponsorPoolReader interface {
	Reserve(ctx context.Context, contract string, fee math.Int) bool
}

// BankKeeper is the subset of the bank keeper this module needs (pool moves + mint).
type BankKeeper interface {
	GetAllBalances(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SendCoinsFromModuleToModule(ctx context.Context, senderModule, recipientModule string, amt sdk.Coins) error
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
}
