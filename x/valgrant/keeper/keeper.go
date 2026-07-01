package keeper

import (
	"context"
	"encoding/json"

	corestore "cosmossdk.io/core/store"

	"github.com/cosmos/evm/x/valgrant/types"
)

// Keeper for x/valgrant. State is plain JSON-in-store (no proto), mirroring
// x/contest. The keeper holds references to the auth/bank/staking keepers so
// it can create PermanentLockedAccounts, move pool funds, and force-undelegate.
type Keeper struct {
	storeService corestore.KVStoreService

	accountKeeper types.AccountKeeper
	bankKeeper    types.BankKeeper
	stakingKeeper types.StakingKeeper
}

// NewKeeper builds the x/valgrant keeper. Inject AccountKeeper, BankKeeper and
// StakingKeeper from app.go (see wiring). The admin is read from Params at
// runtime in the msg_server, mirroring x/contest.
func NewKeeper(
	ss corestore.KVStoreService,
	ak types.AccountKeeper,
	bk types.BankKeeper,
	sk types.StakingKeeper,
) Keeper {
	return Keeper{
		storeService:  ss,
		accountKeeper: ak,
		bankKeeper:    bk,
		stakingKeeper: sk,
	}
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

// --- KPI snapshot (latest decentralization metrics) ---

func (k Keeper) SetKPISnapshot(ctx context.Context, s types.KPISnapshot) error {
	bz, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(types.KPISnapshotKey, bz)
}

func (k Keeper) GetKPISnapshot(ctx context.Context) (types.KPISnapshot, bool) {
	bz, err := k.store(ctx).Get(types.KPISnapshotKey)
	if err != nil || bz == nil {
		return types.KPISnapshot{}, false
	}
	var s types.KPISnapshot
	if json.Unmarshal(bz, &s) != nil {
		return types.KPISnapshot{}, false
	}
	return s, true
}

// --- grant registry ---

func (k Keeper) SetGrant(ctx context.Context, g types.Grant) error {
	bz, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(grantKey(g.Grantee), bz)
}

func (k Keeper) DeleteGrant(ctx context.Context, grantee string) {
	_ = k.store(ctx).Delete(grantKey(grantee))
}

func (k Keeper) GetGrant(ctx context.Context, grantee string) (types.Grant, bool) {
	bz, err := k.store(ctx).Get(grantKey(grantee))
	if err != nil || bz == nil {
		return types.Grant{}, false
	}
	var g types.Grant
	if json.Unmarshal(bz, &g) != nil {
		return types.Grant{}, false
	}
	return g, true
}

func (k Keeper) IterateGrants(ctx context.Context, fn func(types.Grant)) {
	it, err := k.store(ctx).Iterator(types.GrantsPrefix, prefixEnd(types.GrantsPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var g types.Grant
		if json.Unmarshal(it.Value(), &g) == nil {
			fn(g)
		}
	}
}

// --- pending clawback registry (deferred sweep of bonded principal) ---

func (k Keeper) SetPendingClawback(ctx context.Context, pc types.PendingClawback) error {
	bz, err := json.Marshal(pc)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(pendingKey(pc.Grantee), bz)
}

func (k Keeper) DeletePendingClawback(ctx context.Context, grantee string) {
	_ = k.store(ctx).Delete(pendingKey(grantee))
}

func (k Keeper) IteratePendingClawbacks(ctx context.Context, fn func(types.PendingClawback)) {
	it, err := k.store(ctx).Iterator(types.PendingClawbackPref, prefixEnd(types.PendingClawbackPref))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var pc types.PendingClawback
		if json.Unmarshal(it.Value(), &pc) == nil {
			fn(pc)
		}
	}
}

// --- key builders + helpers (all allocate fresh slices) ---

func grantKey(grantee string) []byte   { return concat(types.GrantsPrefix, []byte(grantee)) }
func pendingKey(grantee string) []byte { return concat(types.PendingClawbackPref, []byte(grantee)) }

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
