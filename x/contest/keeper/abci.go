package keeper

import (
	"context"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/contest/types"
)

// EndBlock rolls each prior day's unique-active markers into tester points, then
// freezes the leaderboard the instant block time crosses the configured snapshot.
func (k Keeper) EndBlock(ctx sdk.Context) error {
	if k.SnapshotDone(ctx) {
		return nil // frozen — record nothing further
	}
	p := k.GetParams(ctx)

	today := uint64(ctx.BlockTime().UTC().Unix() / 86400)
	k.rollupUAW(ctx, today, p.WeightUAW)

	if p.SnapshotUnix > 0 && ctx.BlockTime().UTC().Unix() >= p.SnapshotUnix {
		k.setSnapshotDone(ctx)
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"contest_snapshot",
			sdk.NewAttribute("height", strconv.FormatInt(ctx.BlockHeight(), 10)),
			sdk.NewAttribute("block_time", ctx.BlockTime().UTC().String()),
		))
		ctx.Logger().Info("CONTEST SNAPSHOT FROZEN — leaderboard is final; export the Genesis allocation map")
	}
	return nil
}

// rollupUAW credits each (day < today, tester) marker as WeightUAW tester points exactly
// once, then deletes it, so the daily set never double-counts and state stays bounded.
func (k Keeper) rollupUAW(ctx context.Context, today uint64, weight uint64) {
	st := k.store(ctx)
	start := concat(types.DailyUAWPrefix, u64(0))
	end := concat(types.DailyUAWPrefix, u64(today)) // [start, end) = all days strictly < today
	it, err := st.Iterator(start, end)
	if err != nil {
		return
	}
	var keys [][]byte
	var testers []string
	for ; it.Valid(); it.Next() {
		kk := append([]byte{}, it.Key()...)
		keys = append(keys, kk)
		testers = append(testers, string(kk[len(types.DailyUAWPrefix)+8:]))
	}
	it.Close()
	for i, kk := range keys {
		k.AddTesterPoints(ctx, testers[i], weight)
		_ = st.Delete(kk)
	}
}
