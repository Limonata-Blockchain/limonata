package keeper

import (
	"context"

	"github.com/cosmos/evm/x/netcap/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	return k.SetParams(ctx, gs.Params)
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	return &types.GenesisState{Params: k.GetParams(ctx)}
}
