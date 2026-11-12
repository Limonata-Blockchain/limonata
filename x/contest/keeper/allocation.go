package keeper

import (
	"context"
	"sort"

	"cosmossdk.io/math"

	"github.com/cosmos/evm/x/contest/types"
)

// Alloc is one line of the deterministic Genesis allocation map.
type Alloc struct {
	Address string   `json:"address"`
	Amount  math.Int `json:"amount"` // aLIMO
	Points  uint64   `json:"points"`
	Track   string   `json:"track"`
}

// distribute splits `budget` aLIMO across entries pro-rata to points, deterministically:
// floor each share, then assign the integer remainder to the highest-points address
// (ties broken by the sorted address order). Identical output on every node, every run.
func distribute(points map[string]uint64, budget math.Int, track string) []Alloc {
	addrs := make([]string, 0, len(points))
	var total uint64
	for a, p := range points {
		if p > 0 {
			addrs = append(addrs, a)
			total += p
		}
	}
	sort.Strings(addrs)
	if total == 0 || budget.IsNil() || !budget.IsPositive() {
		return nil
	}
	totalI := math.NewIntFromUint64(total)
	out := make([]Alloc, 0, len(addrs))
	running := math.ZeroInt()
	bestIdx, bestPts := -1, uint64(0)
	for i, a := range addrs {
		p := points[a]
		amt := budget.Mul(math.NewIntFromUint64(p)).Quo(totalI) // floor
		out = append(out, Alloc{Address: a, Amount: amt, Points: p, Track: track})
		running = running.Add(amt)
		if p > bestPts {
			bestPts = p
			bestIdx = i
		}
	}
	if rem := budget.Sub(running); rem.IsPositive() && bestIdx >= 0 {
		out[bestIdx].Amount = out[bestIdx].Amount.Add(rem)
	}
	return out
}

// ExportAllocation reads the (frozen) leaderboard and returns the full Genesis map.
// Call after the snapshot; computed off the persisted state so it is reproducible.
func (k Keeper) ExportAllocation(ctx context.Context) []Alloc {
	p := k.GetParams(ctx)

	devBudget, ok := math.NewIntFromString(p.DevTrackBudget)
	if !ok || devBudget.IsNil() {
		devBudget = math.ZeroInt()
	}
	testBudget, ok := math.NewIntFromString(p.TesterTrackBudget)
	if !ok || testBudget.IsNil() {
		testBudget = math.ZeroInt()
	}
	div, ok := math.NewIntFromString(p.GasSponsoredDivisor)
	if !ok || div.IsNil() || !div.IsPositive() {
		div = math.OneInt()
	}

	devPts := map[string]uint64{}
	k.IterateDev(ctx, func(dev string, s types.DevStats) {
		pts := s.TxVolume * p.WeightTxVolume
		if gas, ok := math.NewIntFromString(s.GasSponsored); ok && !gas.IsNil() && gas.IsPositive() {
			pts += gas.Quo(div).Uint64() * p.WeightGasSponsoredPer
		}
		devPts[dev] = pts
	})
	testPts := map[string]uint64{}
	k.IterateTester(ctx, func(t string, pts uint64) { testPts[t] = pts })

	out := distribute(devPts, devBudget, "developer")
	out = append(out, distribute(testPts, testBudget, "tester")...)
	return out
}
