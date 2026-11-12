package keeper

import (
	"context"
	"fmt"

	"github.com/cosmos/evm/x/gassponsor/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	// Un genesis incoherent doit REFUSER de demarrer, pas demarrer en silence:
	// x/gassponsor a desormais un MsgUpdateParams reserve a la gouvernance, donc
	// ces params ne sont plus graves pour toujours; un genesis invalide reste
	// neanmoins un refus de demarrage, parce que la periode entre le bloc 1 et le
	// vote correctif n'est pas rattrapable - et ce module MINTE.
	if err := gs.Validate(); err != nil {
		return fmt.Errorf("%s: invalid genesis: %w", types.ModuleName, err)
	}
	return k.SetParams(ctx, gs.Params)
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	return &types.GenesisState{Params: k.GetParams(ctx)}
}
