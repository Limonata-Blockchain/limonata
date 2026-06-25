package keeper

import (
	"context"
	"encoding/binary"
	"encoding/json"

	corestore "cosmossdk.io/core/store"

	"github.com/cosmos/evm/x/encmempool/types"
)

// Keeper for x/encmempool. State is plain JSON-in-store (no proto), like x/contest.
type Keeper struct {
	storeService corestore.KVStoreService
}

func NewKeeper(ss corestore.KVStoreService) Keeper { return Keeper{storeService: ss} }

func (k Keeper) store(ctx context.Context) corestore.KVStore { return k.storeService.OpenKVStore(ctx) }

// --- params ---

func (k Keeper) SetParams(ctx context.Context, p types.Params) error {
	bz, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(types.ParamsKey, bz)
}

func (k Keeper) GetParams(ctx context.Context) types.Params {
	bz, err := k.store(ctx).Get(types.ParamsKey)
	if err != nil || bz == nil {
		return types.DefaultParams()
	}
	var p types.Params
	if json.Unmarshal(bz, &p) != nil {
		return types.DefaultParams()
	}
	return p
}

// --- monotonic seq counter (disambiguates multiple commits at the same height) ---

func (k Keeper) nextSeq(ctx context.Context) uint64 {
	st := k.store(ctx)
	bz, _ := st.Get(types.SeqKey)
	var cur uint64
	if len(bz) == 8 {
		cur = binary.BigEndian.Uint64(bz)
	}
	_ = st.Set(types.SeqKey, u64(cur+1))
	return cur
}

// --- commits ---

func (k Keeper) SetCommit(ctx context.Context, c types.Commit) error {
	bz, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(commitKey(c.Height, c.Sender, c.Seq), bz)
}

func (k Keeper) GetCommit(ctx context.Context, height uint64, sender string, seq uint64) (types.Commit, bool) {
	bz, err := k.store(ctx).Get(commitKey(height, sender, seq))
	if err != nil || bz == nil {
		return types.Commit{}, false
	}
	var c types.Commit
	if json.Unmarshal(bz, &c) != nil {
		return types.Commit{}, false
	}
	return c, true
}

func (k Keeper) DeleteCommit(ctx context.Context, height uint64, sender string, seq uint64) {
	_ = k.store(ctx).Delete(commitKey(height, sender, seq))
}

// --- pending reveals ---

func (k Keeper) SetPending(ctx context.Context, p types.PendingReveal) error {
	bz, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(pendingKey(p.CommitHeight, p.Sender, p.Seq), bz)
}

func (k Keeper) DeletePending(ctx context.Context, commitHeight uint64, sender string, seq uint64) {
	_ = k.store(ctx).Delete(pendingKey(commitHeight, sender, seq))
}

// --- iteration (genesis export + BeginBlock); keys are pre-sorted big-endian ---

func (k Keeper) IterateCommits(ctx context.Context, fn func(types.Commit)) {
	it, err := k.store(ctx).Iterator(types.CommitPrefix, prefixEnd(types.CommitPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var c types.Commit
		if json.Unmarshal(it.Value(), &c) == nil {
			fn(c)
		}
	}
}

func (k Keeper) IteratePending(ctx context.Context, fn func(types.PendingReveal)) {
	it, err := k.store(ctx).Iterator(types.PendingPrefix, prefixEnd(types.PendingPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var p types.PendingReveal
		if json.Unmarshal(it.Value(), &p) == nil {
			fn(p)
		}
	}
}

// --- key builders + helpers (big-endian height/seq for deterministic ordering) ---

func commitKey(height uint64, sender string, seq uint64) []byte {
	return concat(types.CommitPrefix, u64(height), []byte(sender), u64(seq))
}

func pendingKey(commitHeight uint64, sender string, seq uint64) []byte {
	return concat(types.PendingPrefix, u64(commitHeight), []byte(sender), u64(seq))
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func prefixEnd(p []byte) []byte {
	end := make([]byte, len(p))
	copy(end, p)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xFF {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}
