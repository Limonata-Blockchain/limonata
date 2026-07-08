package keeper

import (
	"context"
	"encoding/json"

	"github.com/cosmos/evm/x/encmempool/types"
)

// InitGenesis restores the module state, INCLUDING the DKG / threshold-encryption state
// (round-8 #5) so a genesis-export migration does not strand in-flight ciphertexts or reset the
// DKG. The in-flight ref-counts are RECOMPUTED from the imported EncTx set (never imported) so
// they are always consistent with the ciphertexts actually in state.
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

	// --- DKG / threshold-encryption state ---
	st := k.store(ctx)
	if gs.EncSeq > 0 {
		_ = st.Set(types.EncSeqKey, u64(gs.EncSeq))
	}
	if gs.CurrentEpoch > 0 {
		k.SetCurrentEpoch(ctx, gs.CurrentEpoch)
	}
	if gs.ActiveEpoch > 0 {
		k.SetActiveEpoch(ctx, gs.ActiveEpoch)
	}
	for _, r := range gs.DkgRounds {
		if err := k.SetDkgRound(ctx, r); err != nil {
			return err
		}
	}
	for _, d := range gs.Dealings {
		if err := k.SetDealing(ctx, d); err != nil {
			return err
		}
	}
	for _, a := range gs.ActiveKeys {
		if err := k.SetActiveKey(ctx, a); err != nil {
			return err
		}
	}
	for _, kr := range gs.EncKeys {
		// Genesis is trusted: set the forward (operator->key) + reverse (key->owner) index directly,
		// skipping the PoP verification RecordEncPubKey does at ingest.
		_ = st.Set(encPubKeyKey(kr.Operator), append([]byte(nil), kr.Key...))
		_ = st.Set(encKeyOwnerKey(kr.Key), []byte(kr.Operator))
	}
	for _, s := range gs.EncShares {
		// round-11 #5 (SECURITY): NEVER trust a genesis-imported share's Verified flag. Recovery
		// skips the DLEQ re-check for Verified shares (round-9 #5), so an imported Verified=true over
		// a BAD share would enter the Lagrange combine unchecked and corrupt decryption. Force
		// Verified=false on import so the decrypt-path re-verifies every imported share from scratch;
		// a genuinely-good share re-verifies fine (a bounded per-block cost), a bad one is dropped.
		s.Verified = false
		if err := k.SetEncShare(ctx, s); err != nil {
			return err
		}
	}
	// EncTx + RECOMPUTED ref-counts: store each ciphertext raw (no re-seq), then rebuild the
	// global / per-submitter / per-epoch in-flight counters from the imported set. This is the
	// consistency guarantee: the counters can never be imported out of sync with the ciphertexts.
	for _, e := range gs.EncTxs {
		_ = st.Set(encTxKey(e.DecryptHeight, e.Seq), mustJSON(e))
		k.incGlobalEncCount(ctx)
		k.incSubmitterEncCount(ctx, e.Submitter)
		if e.Epoch > 0 {
			k.incEpochEncCount(ctx, e.Epoch)
		}
	}
	return nil
}

// ExportGenesis serializes the full module state, INCLUDING the DKG / threshold-encryption state
// (round-8 #5), so a genesis-export migration can restore it losslessly. Ref-counts are NOT
// exported - InitGenesis recomputes them from the EncTx set. Ephemeral / self-rebuilding state
// (share-key cache, negative caches, submit-rate, strand streaks, rotation cooldowns, complaints)
// is not exported; it rebuilds on its own after import.
func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{
		Params:       k.GetParams(ctx),
		Commits:      []types.Commit{},
		Pending:      []types.PendingReveal{},
		EncSeq:       k.readU64(ctx, types.EncSeqKey),
		CurrentEpoch: k.GetCurrentEpoch(ctx),
		ActiveEpoch:  k.GetActiveEpoch(ctx),
	}
	k.IterateCommits(ctx, func(c types.Commit) { gs.Commits = append(gs.Commits, c) })
	k.IteratePending(ctx, func(p types.PendingReveal) { gs.Pending = append(gs.Pending, p) })
	k.iterateAllEncTx(ctx, func(e types.EncTx) { gs.EncTxs = append(gs.EncTxs, e) })
	k.iterateAllEncShares(ctx, func(s types.EncShare) { gs.EncShares = append(gs.EncShares, s) })
	k.iterateDkgRounds(ctx, func(r types.DkgRound) { gs.DkgRounds = append(gs.DkgRounds, r) })
	k.iterateAllDealings(ctx, func(d types.Dealing) { gs.Dealings = append(gs.Dealings, d) })
	k.iterateActiveKeys(ctx, func(a types.ActiveThresholdKey) { gs.ActiveKeys = append(gs.ActiveKeys, a) })
	k.IterateEncPubKeys(ctx, func(op string, key []byte) {
		gs.EncKeys = append(gs.EncKeys, types.EncKeyReg{Operator: op, Key: key})
	})
	return gs
}

// --- genesis iterate-all helpers (unmarshal every JSON value under a prefix) ---

func (k Keeper) iterateRaw(ctx context.Context, prefix []byte, fn func(val []byte)) {
	it, err := k.store(ctx).Iterator(prefix, prefixEnd(prefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		fn(it.Value())
	}
}

func (k Keeper) iterateAllEncTx(ctx context.Context, fn func(types.EncTx)) {
	k.iterateRaw(ctx, types.EncTxPrefix, func(v []byte) {
		var e types.EncTx
		if json.Unmarshal(v, &e) == nil {
			fn(e)
		}
	})
}

func (k Keeper) iterateAllEncShares(ctx context.Context, fn func(types.EncShare)) {
	k.iterateRaw(ctx, types.EncSharePrefix, func(v []byte) {
		var s types.EncShare
		if json.Unmarshal(v, &s) == nil {
			fn(s)
		}
	})
}

func (k Keeper) iterateDkgRounds(ctx context.Context, fn func(types.DkgRound)) {
	k.iterateRaw(ctx, types.DkgRoundPrefix, func(v []byte) {
		var r types.DkgRound
		if json.Unmarshal(v, &r) == nil {
			fn(r)
		}
	})
}

func (k Keeper) iterateAllDealings(ctx context.Context, fn func(types.Dealing)) {
	k.iterateRaw(ctx, types.DkgDealPrefix, func(v []byte) {
		var d types.Dealing
		if json.Unmarshal(v, &d) == nil {
			fn(d)
		}
	})
}

func (k Keeper) iterateActiveKeys(ctx context.Context, fn func(types.ActiveThresholdKey)) {
	k.iterateRaw(ctx, types.ActiveKeyPrefix, func(v []byte) {
		var a types.ActiveThresholdKey
		if json.Unmarshal(v, &a) == nil {
			fn(a)
		}
	})
}
