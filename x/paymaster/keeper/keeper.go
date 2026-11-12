package keeper

import (
	"context"
	"encoding/json"

	storetypes "cosmossdk.io/core/store"

	"github.com/cosmos/evm/x/paymaster/types"
)

// Keeper for x/paymaster. State is a single JSON-encoded []Policy (scaffold;
// a production version would use proto + per-policy keys + spend accounting).
type Keeper struct {
	storeService storetypes.KVStoreService
}

func NewKeeper(ss storetypes.KVStoreService) Keeper {
	return Keeper{storeService: ss}
}

func (k Keeper) SetPolicies(ctx context.Context, ps []types.Policy) error {
	bz, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	return k.storeService.OpenKVStore(ctx).Set(types.PoliciesKey, bz)
}

func (k Keeper) GetPolicies(ctx context.Context) ([]types.Policy, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.PoliciesKey)
	if err != nil || bz == nil {
		return nil, err
	}
	var ps []types.Policy
	if err := json.Unmarshal(bz, &ps); err != nil {
		return nil, err
	}
	return ps, nil
}
