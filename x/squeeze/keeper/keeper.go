package keeper

import (
	"context"
	"encoding/json"

	corestore "cosmossdk.io/core/store"

	"github.com/cosmos/evm/x/squeeze/types"
)

// Keeper for the squeeze fee module. As of v0.3.0 it is stateful: the fee-split ratios
// are governable Params (a JSON blob at types.ParamsKey), not compile-time constants.
// It moves coins via the bank keeper at BeginBlock.
type Keeper struct {
	storeService     corestore.KVStoreService
	bankKeeper       types.BankKeeper
	feeCollectorName string
}

// NewKeeper returns a squeeze keeper. feeCollectorName is authtypes.FeeCollectorName.
func NewKeeper(ss corestore.KVStoreService, bk types.BankKeeper, feeCollectorName string) Keeper {
	return Keeper{storeService: ss, bankKeeper: bk, feeCollectorName: feeCollectorName}
}

func (k Keeper) store(ctx context.Context) corestore.KVStore { return k.storeService.OpenKVStore(ctx) }

// --- params (JSON-in-store, mirrors x/gassponsor) ---

func (k Keeper) SetParams(ctx context.Context, p types.Params) error {
	bz, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(types.ParamsKey, bz)
}

// GetParams returns the stored fee-split params, falling back to DefaultParams
// (20% burn / 20% recycle / 60% validators) when unset or unreadable. The fallback keeps
// pre-genesis / pre-params chains and unit tests working without a params write.
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
