package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/cosmos/evm/x/vpcap/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	// Un genesis incoherent doit REFUSER de demarrer, pas demarrer en silence:
	// ces params sont IRREVERSIBLES apres le bloc 1 pour les modules qui n'ont
	// pas de MsgUpdateParams. x/vpcap en a un depuis la parite mainnet (gov
	// seule), mais un genesis invalide reste un refus de demarrage: la periode
	// entre le bloc 1 et le vote correctif n'est pas rattrapable.
	if err := gs.Validate(); err != nil {
		return fmt.Errorf("%s: invalid genesis: %w", types.ModuleName, err)
	}
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}
	// Restore the last-sent map (0x02). Without this an export -> import would
	// restart with an empty diff base and leave departed validators in the
	// CometBFT set at their pre-cap power. See types.LastSentEntry.
	for i, e := range gs.LastSent {
		consAddr, err := hex.DecodeString(e.ConsAddr)
		if err != nil {
			return fmt.Errorf("%s: last_sent[%d]: cons_addr %q is not hex: %w", types.ModuleName, i, e.ConsAddr, err)
		}
		if err := k.SetLastSent(ctx, consAddr, LastSent{PubKey: e.PubKey, Power: e.Power}); err != nil {
			return err
		}
	}
	return nil
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx)}
	last, err := k.GetAllLastSent(ctx)
	if err != nil {
		// GetAllLastSent only fails if the store iterator cannot be opened, which
		// on an export means the export itself is broken. Surfacing a truncated
		// genesis silently is the worse outcome, so panic loudly.
		panic(fmt.Errorf("%s: cannot export last_sent: %w", types.ModuleName, err))
	}
	if len(last) == 0 {
		return gs
	}
	gs.LastSent = make([]types.LastSentEntry, 0, len(last))
	for consAddr, ls := range last {
		gs.LastSent = append(gs.LastSent, types.LastSentEntry{
			ConsAddr: hex.EncodeToString([]byte(consAddr)),
			PubKey:   ls.PubKey,
			Power:    ls.Power,
		})
	}
	// Map iteration order is random; a genesis export MUST be deterministic or two
	// nodes exporting the same state produce different files (and different hashes).
	sort.Slice(gs.LastSent, func(i, j int) bool { return gs.LastSent[i].ConsAddr < gs.LastSent[j].ConsAddr })
	return gs
}
