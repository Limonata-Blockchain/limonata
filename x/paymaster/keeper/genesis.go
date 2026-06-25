package keeper

import (
	"context"

	"github.com/cosmos/evm/x/paymaster/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	return k.SetPolicies(ctx, gs.Policies)
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	ps, _ := k.GetPolicies(ctx)
	if ps == nil {
		ps = []types.Policy{}
	}
	return &types.GenesisState{Policies: ps}
}
