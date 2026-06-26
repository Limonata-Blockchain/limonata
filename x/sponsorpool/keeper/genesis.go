package keeper

import (
	"context"

	"github.com/cosmos/evm/x/sponsorpool/types"
)

// InitGenesis sets the module params from genesis. Escrow balances are runtime state
// created by deposits, so there is nothing else to load.
func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	return k.SetParams(ctx, gs.Params)
}

// ExportGenesis returns the module params.
func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	return &types.GenesisState{Params: k.GetParams(ctx)}
}
