package keeper_test

import (
	"fmt"
	"testing"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// FLIPPED cycle-3 M-1 probe. The original TestProbe_H3_MinStakeToReachThreshold searched
// arbitrary (including invalid, S<n) configs for the SMALLEST stake fraction that
// assembles t points, and found stake minorities (down to 13.28%) reconstructing — because
// nothing coupled the budget to the committee and the tie-break handed degenerate
// remainders to the lowest operator addresses.
//
// Post-fix the search is constrained to configs that can actually EXIST (Params.Validate +
// the runtime committee clamp enforce S >= MinShareBudgetPerMember*n at every round-open)
// and asserts the PROVEN bar: every reconstructing coalition holds STRICTLY more than the
// 1/3 Byzantine stake bound (the honest claim that replaced ">2/3": f >= (t-n+1)/S
// > 2/3 - 2n/S >= 5/12 at the enforced coupling — see keeper.stakeThreshold). The observed
// minimum is logged so the documented bar stays measurable.
func TestReg_M1_MinStakeToReachThreshold_AboveByzantineBound(t *testing.T) {
	type worst struct {
		desc              string
		n, S              int
		coalStake, allStk int64
		coalPts, thr      int
		stakeFrac         float64
	}
	var record *worst

	consider := func(desc string, n, S int, members []types.RoundMember, coalIdx []int) {
		out := keeper.AllocateEvalPoints(members, S, 1)
		inC := map[int]bool{}
		for _, i := range coalIdx {
			inC[i] = true
		}
		pts, tot := 0, 0
		for i, m := range out {
			np := len(m.OwnedEvalPoints())
			tot += np
			if inC[i] {
				pts += np
			}
		}
		thr := (2*tot)/3 - n + 1 // mirrors keeper.stakeThreshold (weighted)
		if pts < thr {
			return
		}
		var cs, all int64
		for i, m := range members {
			all += m.Weight.Int64()
			if inC[i] {
				cs += m.Weight.Int64()
			}
		}
		frac := float64(cs) / float64(all)
		if record == nil || frac < record.stakeFrac {
			record = &worst{desc, n, S, cs, all, pts, thr, frac}
		}
	}

	buildMembers := func(weights []int64) []types.RoundMember {
		return mkMembers(weights) // shared helper (operator-sorted, weighted)
	}

	// (1) Equal-stake prefix coalitions (tie-break exploitation attempt), valid budgets only.
	for _, n := range []int{4, 8, 16, 32, 64, 100, 128} {
		for _, S := range []int{8 * n, 16 * n, 256, 512, 1024, 2048} {
			if S < types.MinShareBudgetPerMember*n || S > 2048 {
				continue // unreachable configs (validation + runtime clamp forbid them)
			}
			w := make([]int64, n)
			for i := range w {
				w[i] = 1_000_000
			}
			members := buildMembers(w)
			for m := 1; m <= n; m++ {
				idx := make([]int, m)
				for i := range idx {
					idx[i] = i
				}
				out := keeper.AllocateEvalPoints(members, S, 1)
				pts := 0
				for i := 0; i < m; i++ {
					pts += len(out[i].OwnedEvalPoints())
				}
				if pts >= (2*S)/3-n+1 {
					consider(fmt.Sprintf("equal-stake prefix n=%d S=%d m=%d", n, S, m), n, S, members, idx)
					break
				}
			}
		}
	}

	// (2) "Boundary swarm": many equal small validators + a few whales; coalition = the swarm.
	for _, n := range []int{16, 32, 64, 128} {
		for _, S := range []int{8 * n, 16 * n} {
			if S > 2048 {
				continue
			}
			for _, swarm := range []int{n / 2, n/2 + 1, n - 3, n - 1} {
				if swarm < 1 || swarm >= n {
					continue
				}
				w := make([]int64, n)
				for i := 0; i < swarm; i++ {
					w[i] = 3
				}
				for i := swarm; i < n; i++ {
					w[i] = 100
				}
				idx := make([]int, swarm)
				for i := range idx {
					idx[i] = i
				}
				consider(fmt.Sprintf("swarm n=%d S=%d swarm=%d", n, S, swarm), n, S, buildMembers(w), idx)
			}
		}
	}

	// (3) Half-committee minorities with tuned remainders.
	for _, n := range []int{32, 64, 128} {
		S := 8 * n
		for _, A := range []int64{1, 2, 3, 5, 7, 11, 50, 99} {
			for _, B := range []int64{A + 1, A * 2, A * 3, 100, 101, 200} {
				if B <= A {
					continue
				}
				half := n / 2
				w := make([]int64, n)
				for i := 0; i < half; i++ {
					w[i] = A
				}
				for i := half; i < n; i++ {
					w[i] = B
				}
				idx := make([]int, half)
				for i := range idx {
					idx[i] = i
				}
				consider(fmt.Sprintf("half-minority n=%d S=%d A=%d B=%d", n, S, A, B), n, S, buildMembers(w), idx)
			}
		}
	}

	if record == nil {
		t.Fatal("sweep found NO reconstructing coalition at all — the search harness is broken")
	}
	t.Logf("lowest-stake reconstructing coalition (valid configs):\n  %s\n  n=%d S=%d coalPts=%d t=%d coalStake=%d/%d = %.4f",
		record.desc, record.n, record.S, record.coalPts, record.thr, record.coalStake, record.allStk, record.stakeFrac)
	if record.stakeFrac <= 1.0/3.0 {
		t.Errorf("M-1 REGRESSION: a coalition at/below the 1/3 Byzantine bound (%.4f) assembled t=%d points (%s)",
			record.stakeFrac, record.thr, record.desc)
	}
}
