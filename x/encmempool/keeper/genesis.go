package keeper

import (
	"context"
	"fmt"

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
	// MED-4 AUDIT FIX: genesis carries only Params/Commits/Pending — NOT the DKG/threshold state
	// (EncTx, decryption shares, DkgRound records, ActiveThresholdKey, the epoch counters + ref-counts,
	// or the share-key cache). Exporting while ciphertexts are in flight would silently STRAND every one
	// of them (their stamped epoch key and shares vanish) and reset the DKG to epoch 0 on re-import.
	// Refuse the export LOUDLY instead of losing state: while the encrypted mempool holds un-matured
	// ciphertexts, only in-place upgrades (which keep the full KV store) are supported.
	if n := k.GetGlobalEncCount(ctx); n > 0 {
		panic(fmt.Sprintf(
			"encmempool: refusing ExportGenesis with %d in-flight encrypted ciphertext(s): genesis does not "+
				"carry DKG/threshold/enc state, so an export/import would strand them. Use an in-place upgrade, "+
				"or drain the encrypted mempool (let all ciphertexts mature) before exporting.", n))
	}
	gs := &types.GenesisState{Params: k.GetParams(ctx), Commits: []types.Commit{}, Pending: []types.PendingReveal{}}
	k.IterateCommits(ctx, func(c types.Commit) { gs.Commits = append(gs.Commits, c) })
	k.IteratePending(ctx, func(p types.PendingReveal) { gs.Pending = append(gs.Pending, p) })
	return gs
}
