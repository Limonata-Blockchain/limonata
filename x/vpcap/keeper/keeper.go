package keeper

import (
	"context"
	"encoding/json"

	corestore "cosmossdk.io/core/store"

	"github.com/cosmos/evm/x/vpcap/types"
)

// Keeper for x/vpcap. State is plain JSON-in-store (no proto), mirroring
// x/valgrant. Holds a read-only staking reference to read the bonded set's
// consensus power each block.
type Keeper struct {
	storeService  corestore.KVStoreService
	stakingKeeper types.StakingKeeper
}

func NewKeeper(ss corestore.KVStoreService, sk types.StakingKeeper) Keeper {
	return Keeper{storeService: ss, stakingKeeper: sk}
}

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

// --- last-sent map: what vpcap last told CometBFT (consAddr -> {pubkey,power}).
// vpcap OWNS the full ValidatorUpdates set when enabled, so it must remember
// prior emissions to diff correctly and to zero out validators that left the
// bonded set. Stored per-consAddr (deterministic per-key writes).

// LastSent is the persisted record of the last update vpcap emitted for a
// validator. PubKey is the marshaled cmtprotocrypto.PublicKey (so a departed
// validator can be re-emitted with Power 0 without re-querying staking).
type LastSent struct {
	PubKey []byte `json:"pubkey"`
	Power  int64  `json:"power"`
}

func lastSentKey(consAddr []byte) []byte {
	out := make([]byte, 0, len(types.LastSentPrefix)+len(consAddr))
	out = append(out, types.LastSentPrefix...)
	out = append(out, consAddr...)
	return out
}

// GetAllLastSent returns the full last-sent map keyed by string(consAddr bytes).
func (k Keeper) GetAllLastSent(ctx context.Context) (map[string]LastSent, error) {
	res := map[string]LastSent{}
	it, err := k.store(ctx).Iterator(types.LastSentPrefix, prefixEnd(types.LastSentPrefix))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		consAddr := it.Key()[len(types.LastSentPrefix):]
		var ls LastSent
		if json.Unmarshal(it.Value(), &ls) == nil {
			res[string(consAddr)] = ls
		}
	}
	return res, nil
}

func (k Keeper) SetLastSent(ctx context.Context, consAddr []byte, ls LastSent) error {
	bz, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(lastSentKey(consAddr), bz)
}

func (k Keeper) DeleteLastSent(ctx context.Context, consAddr []byte) {
	_ = k.store(ctx).Delete(lastSentKey(consAddr))
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
	return nil // all 0xFF -> open-ended
}
