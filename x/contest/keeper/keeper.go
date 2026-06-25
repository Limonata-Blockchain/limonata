package keeper

import (
	"context"
	"encoding/binary"
	"encoding/json"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"

	"github.com/cosmos/evm/x/contest/types"
)

// Keeper for x/contest. State is plain JSON-in-store (no proto), mirroring x/paymaster.
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

// --- showcase registry ---

func (k Keeper) SetShowcase(ctx context.Context, a types.ShowcaseApp) error {
	bz, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(showcaseKey(a.Address), bz)
}

func (k Keeper) DeleteShowcase(ctx context.Context, addr string) {
	_ = k.store(ctx).Delete(showcaseKey(addr))
}

func (k Keeper) GetShowcase(ctx context.Context, addr string) (types.ShowcaseApp, bool) {
	bz, err := k.store(ctx).Get(showcaseKey(addr))
	if err != nil || bz == nil {
		return types.ShowcaseApp{}, false
	}
	var a types.ShowcaseApp
	if json.Unmarshal(bz, &a) != nil {
		return types.ShowcaseApp{}, false
	}
	return a, true
}

func (k Keeper) IterateShowcase(ctx context.Context, fn func(types.ShowcaseApp)) {
	it, err := k.store(ctx).Iterator(types.ShowcasePrefix, prefixEnd(types.ShowcasePrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var a types.ShowcaseApp
		if json.Unmarshal(it.Value(), &a) == nil {
			fn(a)
		}
	}
}

// --- developer stats ---

func (k Keeper) getDev(ctx context.Context, dev string) types.DevStats {
	bz, _ := k.store(ctx).Get(devKey(dev))
	s := types.DevStats{GasSponsored: "0"}
	if bz != nil {
		_ = json.Unmarshal(bz, &s)
	}
	if s.GasSponsored == "" {
		s.GasSponsored = "0"
	}
	return s
}

func (k Keeper) setDev(ctx context.Context, dev string, s types.DevStats) {
	bz, _ := json.Marshal(s)
	_ = k.store(ctx).Set(devKey(dev), bz)
}

func (k Keeper) AddDevTxVolume(ctx context.Context, dev string, n uint64) {
	s := k.getDev(ctx, dev)
	s.TxVolume += n
	k.setDev(ctx, dev, s)
}

func (k Keeper) AddGasSponsored(ctx context.Context, dev string, amt math.Int) {
	s := k.getDev(ctx, dev)
	cur, ok := math.NewIntFromString(s.GasSponsored)
	if !ok || cur.IsNil() {
		cur = math.ZeroInt()
	}
	s.GasSponsored = cur.Add(amt).String()
	k.setDev(ctx, dev, s)
}

func (k Keeper) IterateDev(ctx context.Context, fn func(dev string, s types.DevStats)) {
	it, err := k.store(ctx).Iterator(types.DevStatsPrefix, prefixEnd(types.DevStatsPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		dev := string(it.Key()[len(types.DevStatsPrefix):])
		var s types.DevStats
		if json.Unmarshal(it.Value(), &s) == nil {
			fn(dev, s)
		}
	}
}

// --- tester points + daily unique-active markers ---

func (k Keeper) AddTesterPoints(ctx context.Context, tester string, pts uint64) {
	key := testerKey(tester)
	st := k.store(ctx)
	bz, _ := st.Get(key)
	cur := uint64(0)
	if len(bz) == 8 {
		cur = binary.BigEndian.Uint64(bz)
	}
	_ = st.Set(key, u64(cur+pts))
}

func (k Keeper) IterateTester(ctx context.Context, fn func(tester string, pts uint64)) {
	it, err := k.store(ctx).Iterator(types.TesterPointsPrefix, prefixEnd(types.TesterPointsPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		tester := string(it.Key()[len(types.TesterPointsPrefix):])
		if len(it.Value()) == 8 {
			fn(tester, binary.BigEndian.Uint64(it.Value()))
		}
	}
}

// MarkActiveToday records a tester as active on a showcase app for the given day (idempotent).
func (k Keeper) MarkActiveToday(ctx context.Context, day uint64, tester string) {
	key := dailyKey(day, tester)
	st := k.store(ctx)
	if ok, _ := st.Has(key); ok {
		return
	}
	_ = st.Set(key, []byte{0x01})
}

// --- snapshot flag ---

func (k Keeper) SnapshotDone(ctx context.Context) bool {
	bz, _ := k.store(ctx).Get(types.SnapshotDoneKey)
	return len(bz) == 1 && bz[0] == 0x01
}

func (k Keeper) setSnapshotDone(ctx context.Context) {
	_ = k.store(ctx).Set(types.SnapshotDoneKey, []byte{0x01})
}

// --- key builders + helpers (all allocate fresh slices) ---

func showcaseKey(addr string) []byte { return concat(types.ShowcasePrefix, []byte(addr)) }
func devKey(dev string) []byte       { return concat(types.DevStatsPrefix, []byte(dev)) }
func testerKey(t string) []byte      { return concat(types.TesterPointsPrefix, []byte(t)) }
func dailyKey(day uint64, t string) []byte {
	return concat(types.DailyUAWPrefix, u64(day), []byte(t))
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
	return nil // all 0xFF -> open-ended (iterate to end of domain)
}
