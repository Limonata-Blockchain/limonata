package keeper

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/cosmos/evm/x/contest/types"
)

func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	// Un genesis incoherent doit REFUSER de demarrer, pas demarrer en silence:
	// ces params sont IRREVERSIBLES apres le bloc 1 (aucun MsgUpdateParams sur
	// ce module).
	if err := gs.Validate(); err != nil {
		return fmt.Errorf("%s: invalid genesis: %w", types.ModuleName, err)
	}
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}
	for _, a := range gs.Showcase {
		if err := k.SetShowcase(ctx, a); err != nil {
			return err
		}
	}
	// 0x03 / 0x04 / 0x05 / 0x06: the accumulated leaderboard. This is the whole
	// point of the module - the allocation map the contest pays out from - and it
	// exists ONLY in these prefixes. An export that dropped them would restart the
	// chain with every score at zero.
	st := k.store(ctx)
	for _, d := range gs.DevStats {
		k.setDev(ctx, d.Dev, d.Stats)
	}
	for _, tp := range gs.TesterPoints {
		if err := st.Set(testerKey(tp.Tester), u64(tp.Points)); err != nil {
			return err
		}
	}
	for _, u := range gs.DailyUAW {
		if err := st.Set(dailyKey(u.Day, u.Tester), []byte{0x01}); err != nil {
			return err
		}
	}
	// SnapshotDone is a ONE-WAY latch. Restore it only when set: writing the flag
	// from a false value would be a no-op anyway, but making the asymmetry explicit
	// keeps the "never unfreeze a finished contest" property readable.
	if gs.SnapshotDone {
		k.setSnapshotDone(ctx)
	}
	return nil
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx), Showcase: []types.ShowcaseApp{}}
	k.IterateShowcase(ctx, func(a types.ShowcaseApp) { gs.Showcase = append(gs.Showcase, a) })
	k.IterateDev(ctx, func(dev string, s types.DevStats) {
		gs.DevStats = append(gs.DevStats, types.DevStatsEntry{Dev: dev, Stats: s})
	})
	k.IterateTester(ctx, func(tester string, pts uint64) {
		gs.TesterPoints = append(gs.TesterPoints, types.TesterPointsEntry{Tester: tester, Points: pts})
	})
	k.IterateDailyUAW(ctx, func(day uint64, tester string) {
		gs.DailyUAW = append(gs.DailyUAW, types.DailyUAWEntry{Day: day, Tester: tester})
	})
	gs.SnapshotDone = k.SnapshotDone(ctx)

	// Store iteration is key-ordered, so these are already deterministic; sort on the
	// EXPORTED fields so the order stays defined if the key encoding ever changes.
	sort.Slice(gs.DevStats, func(i, j int) bool { return gs.DevStats[i].Dev < gs.DevStats[j].Dev })
	sort.Slice(gs.TesterPoints, func(i, j int) bool { return gs.TesterPoints[i].Tester < gs.TesterPoints[j].Tester })
	sort.Slice(gs.DailyUAW, func(i, j int) bool {
		if gs.DailyUAW[i].Day != gs.DailyUAW[j].Day {
			return gs.DailyUAW[i].Day < gs.DailyUAW[j].Day
		}
		return gs.DailyUAW[i].Tester < gs.DailyUAW[j].Tester
	})
	return gs
}

// IterateDailyUAW walks the 0x05 markers (day, tester) that EndBlock has not yet
// rolled up into tester points.
func (k Keeper) IterateDailyUAW(ctx context.Context, fn func(day uint64, tester string)) {
	it, err := k.store(ctx).Iterator(types.DailyUAWPrefix, prefixEnd(types.DailyUAWPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		key := it.Key()[len(types.DailyUAWPrefix):]
		if len(key) < 8 {
			continue
		}
		fn(binary.BigEndian.Uint64(key[:8]), string(key[8:]))
	}
}
