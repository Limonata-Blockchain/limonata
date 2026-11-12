package keeper

import (
	"context"
	"fmt"

	"github.com/cosmos/evm/x/paymaster/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	// Un genesis incoherent doit REFUSER de demarrer, pas demarrer en silence:
	// ces params sont IRREVERSIBLES apres le bloc 1 (aucun MsgUpdateParams sur
	// plusieurs de ces modules). Seul x/encmempool validait jusqu'ici.
	if err := gs.Validate(); err != nil {
		return fmt.Errorf("%s: invalid genesis: %w", types.ModuleName, err)
	}
	return k.SetPolicies(ctx, gs.Policies)
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	ps, _ := k.GetPolicies(ctx)
	if ps == nil {
		ps = []types.Policy{}
	}
	return &types.GenesisState{Policies: ps}
}
