package keeper

import (
	"context"

	"github.com/cosmos/evm/x/contest/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}
	for _, a := range gs.Showcase {
		if err := k.SetShowcase(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx), Showcase: []types.ShowcaseApp{}}
	k.IterateShowcase(ctx, func(a types.ShowcaseApp) { gs.Showcase = append(gs.Showcase, a) })
	return gs
}
