package keeper

import (
	"context"

	"github.com/cosmos/evm/x/encmempool/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}
	for _, c := range gs.Commits {
		if err := k.SetCommit(ctx, c); err != nil {
			return err
		}
	}
	for _, p := range gs.Pending {
		if err := k.SetPending(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx), Commits: []types.Commit{}, Pending: []types.PendingReveal{}}
	k.IterateCommits(ctx, func(c types.Commit) { gs.Commits = append(gs.Commits, c) })
	k.IteratePending(ctx, func(p types.PendingReveal) { gs.Pending = append(gs.Pending, p) })
	return gs
}
