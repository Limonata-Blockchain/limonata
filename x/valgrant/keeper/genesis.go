package keeper

import (
	"context"

	"github.com/cosmos/evm/x/valgrant/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}
	for _, g := range gs.Grants {
		if err := k.SetGrant(ctx, g); err != nil {
			return err
		}
	}
	return nil
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx), Grants: []types.Grant{}}
	k.IterateGrants(ctx, func(g types.Grant) { gs.Grants = append(gs.Grants, g) })
	return gs
}
