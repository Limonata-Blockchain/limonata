// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"fmt"
	"math/big"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-6 EXTERNAL RE-AUDIT — STAKE-CAPTURE LENS (HIGH-3 family).
//
// ONE question, attacked from every angle a governance-passable config allows:
//   at ANY valid (S >= 8n, n <= 128) param config, can a coalition holding
//   <= 1/3 of the snapshotted committee stake ever reach t = floor(2S/3)-n+1
//   distinct Shamir evaluation points (on- OR off-chain)?  If yes, an anti-MEV
//   break: a Byzantine-bounded minority reconstructs the epoch decryption key.
//
// These probes are DELIBERATELY harder than the committed cycle-1..5 suite:
//   (P1) EXACT worst case: for small n, enumerate EVERY subset over curated
//        adversarial stake shapes and take the true max-points <=1/3 coalition;
//   (P2) the theoretical apportionment worst case (n-1 dust vs one 2/3 whale,
//        and balanced splits) at the S=8n BOUNDARY for all n up to the cap 128,
//        swept across epochs so the L-2 tie-break rotation cannot hide a break;
//   (P3) astronomically large + adversarially-tuned stakes (bigint path);
//   (P4) a knapsack-optimal <=1/3 coalition search on random shapes;
//   (P5) LIVE non-reconstructability through the REAL DKG + crypto at the
//        boundary — the coalition derives its real shares and fails to decrypt.
// All use the REAL keeper.AllocateEvalPoints; t is tNew, which is EXACT to the
// keeper's stakeThreshold whenever S >= 6n (always true here) and only ever
// LOWER than it in the degraded regime — so "points < tNew" is a CONSERVATIVE
// safety witness. TestC6_ThresholdMirrorsLiveRound cross-checks tNew against a
// real opened round's Threshold at several boundary sizes.
// ============================================================================

// allocPoints returns the eval-point count each member (index i in the input
// order) owns for the given integer weights, budget S, and epoch — via the REAL
// allocator. It also asserts the allocation is a valid partition of 1..S (no
// collisions, sum == S) so a phantom-extra-point bug would surface here.
func allocPoints(t *testing.T, weights []*big.Int, S int, epoch uint64) []int {
	t.Helper()
	ms := make([]types.RoundMember, len(weights))
	for i, w := range weights {
		ms[i] = types.RoundMember{
			Index:        uint64(i + 1),
			OperatorAddr: fmt.Sprintf("op%05d", i),
			Weight:       sdkmath.NewIntFromBigInt(w),
		}
	}
	out := keeper.AllocateEvalPoints(ms, S, epoch)
	pts := make([]int, len(weights))
	seen := make(map[uint64]bool, S)
	total := 0
	for i, m := range out {
		ep := m.OwnedEvalPoints()
		pts[i] = len(ep)
		total += len(ep)
		for _, p := range ep {
			if p < 1 || p > uint64(S) || seen[p] {
				t.Fatalf("allocation not a partition of 1..%d: bad/dup point %d (n=%d epoch=%d)", S, p, len(weights), epoch)
			}
			seen[p] = true
		}
	}
	if total != S {
		t.Fatalf("allocation lost/created points: sum=%d != S=%d (n=%d epoch=%d)", total, S, len(weights), epoch)
	}
	return pts
}

func bigs(vals ...int64) []*big.Int {
	out := make([]*big.Int, len(vals))
	for i, v := range vals {
		out[i] = big.NewInt(v)
	}
	return out
}

// ---------------------------------------------------------------------------
// (P1) EXACT worst case for small n: enumerate EVERY subset.
// For each curated adversarial stake shape, over every epoch seed, look at ALL
// 2^n coalitions; for any coalition holding <= 1/3 of total stake, its captured
// point count MUST be < t. Because this is exhaustive, it finds the literal
// worst-case coalition (not a heuristic), so any off-by-one in AllocateEvalPoints
// or the threshold at these sizes is caught with certainty.
// ---------------------------------------------------------------------------
func TestC6_StakeCapture_ExhaustiveSmallN(t *testing.T) {
	epochs := []uint64{0, 1, 2, 3, 7, 42, 1000003}
	minMargin := 1 << 30
	worst := ""

	for n := 2; n <= 14; n++ {
		// Curated adversarial shapes for this n (each is a []*big.Int of length n).
		shapes := curatedShapes(n)
		// Budgets: the boundary 8n (worst), a mid value, and the live default if valid.
		budgets := []int{8 * n, 8*n + 1, 12 * n}
		if 256 >= 8*n {
			budgets = append(budgets, 256)
		}
		for _, S := range budgets {
			if S > 2048 {
				continue
			}
			for _, w := range shapes {
				// total stake
				total := new(big.Int)
				for _, x := range w {
					total.Add(total, x)
				}
				if total.Sign() == 0 {
					continue
				}
				for _, ep := range epochs {
					pts := allocPoints(t, w, S, ep)
					tt := tNew(S, n)
					// Enumerate all subsets.
					for mask := 1; mask < (1 << n); mask++ {
						cstake := new(big.Int)
						cp := 0
						for i := 0; i < n; i++ {
							if mask&(1<<i) != 0 {
								cstake.Add(cstake, w[i])
								cp += pts[i]
							}
						}
						// stake fraction <= 1/3  <=>  3*cstake <= total
						if new(big.Int).Mul(cstake, big.NewInt(3)).Cmp(total) <= 0 {
							if cp >= tt {
								t.Fatalf("SAFETY BROKEN (exhaustive): n=%d S=%d epoch=%d shape=%v mask=%b "+
									"coalition stake %s/%s (<=1/3) holds %d >= t=%d points",
									n, S, ep, bigSlice(w), mask, cstake, total, cp, tt)
							}
							if m := tt - cp; m < minMargin {
								minMargin = m
								worst = fmt.Sprintf("n=%d S=%d epoch=%d cp=%d t=%d shape=%v", n, S, ep, cp, tt, bigSlice(w))
							}
						}
					}
				}
			}
		}
	}
	t.Logf("exhaustive small-n: min safety margin (t - maxPts over all <=1/3 coalitions) = %d points; tightest at %s",
		minMargin, worst)
	if minMargin < 1 {
		t.Fatalf("SAFETY margin collapsed to %d", minMargin)
	}
}

// curatedShapes returns adversarial integer stake vectors of length n that
// concentrate the apportionment worst cases: dust swarm vs whale, balanced
// exact-1/3 splits, geometric/whale ladders, powers of two, near-equal with a
// perturbation, and a single-whale-plus-dust shape.
func curatedShapes(n int) [][]*big.Int {
	var out [][]*big.Int
	add := func(vals ...int64) {
		if len(vals) == n {
			out = append(out, bigs(vals...))
		}
	}
	_ = add

	mk := func(f func(i int) int64) []*big.Int {
		v := make([]*big.Int, n)
		for i := 0; i < n; i++ {
			v[i] = big.NewInt(f(i))
		}
		return v
	}
	// dust swarm (n-1 dust @1) + whale @2(n-1): adversary dust is EXACTLY 1/3.
	out = append(out, mk(func(i int) int64 {
		if i == n-1 {
			return int64(2 * (n - 1))
		}
		return 1
	}))
	// same but whale slightly under 2/3 (adversary just OVER 1/3 — should NOT be
	// flagged <=1/3, but tests the boundary handling).
	out = append(out, mk(func(i int) int64 {
		if i == n-1 {
			return int64(2*(n-1)) - 1
		}
		return 1
	}))
	// balanced: half at 2*nh, half at 4*na (each half ~ exact thirds/two-thirds).
	na := n / 2
	nh := n - na
	if na >= 1 && nh >= 1 {
		out = append(out, mk(func(i int) int64 {
			if i < na {
				return int64(2 * nh)
			}
			return int64(4 * na)
		}))
	}
	// equal stake (remainder-seat tie-break stress).
	out = append(out, mk(func(int) int64 { return 1000 }))
	// geometric ladder 1,2,4,8,...
	out = append(out, mk(func(i int) int64 {
		if i > 40 {
			i = 40
		}
		return int64(1) << uint(i)
	}))
	// whale + all dust (whale ~ huge, dust 1) — whale alone is >2/3.
	out = append(out, mk(func(i int) int64 {
		if i == 0 {
			return int64(100 * n)
		}
		return 1
	}))
	// near-equal with one perturbed member.
	out = append(out, mk(func(i int) int64 {
		if i == 0 {
			return 101
		}
		return 100
	}))
	// two whales + dust (a 2-member coalition just under 1/3 stress).
	out = append(out, mk(func(i int) int64 {
		switch {
		case i == 0 || i == 1:
			return int64(n)
		default:
			return 1
		}
	}))
	// ONE positive whale + rest ZERO-weight (cycle-3 L-1 boundary): the weighted path
	// must give every zero-weight member NOTHING (owns no points), so a coalition of
	// zero-weight sybils holds 0 points. Total is positive => weighted path (not the
	// all-zero unweighted fallback).
	if n >= 2 {
		out = append(out, mk(func(i int) int64 {
			if i == 0 {
				return int64(1000 * n)
			}
			return 0
		}))
	}
	// TWO positive members + rest ZERO: the two share the whole budget; the zero-weight
	// remainder owns nothing (a seat-majority-of-zero-weight coalition holds 0 points).
	if n >= 3 {
		out = append(out, mk(func(i int) int64 {
			switch i {
			case 0:
				return 700
			case 1:
				return 300
			default:
				return 0
			}
		}))
	}
	return out
}

// ---------------------------------------------------------------------------
// (P2) BOUNDARY worst case across ALL n up to the cap, at S = 8n and 8n+small.
// Uses the two structurally-strongest <=1/3 coalitions (max-seat dust swarm and
// balanced half) — for large n we cannot enumerate 2^n, but these are the shapes
// that maximize remainder-seat capture and floor-sum respectively. Swept across
// epochs (tie-break rotation) and several budgets.
// ---------------------------------------------------------------------------
func TestC6_StakeCapture_BoundaryAllSizes(t *testing.T) {
	epochs := []uint64{0, 1, 5, 99, 1 << 40}
	minMargin := 1 << 30
	worst := ""
	for n := 2; n <= 128; n++ {
		budgets := []int{8 * n, 8*n + 1, 8*n + 2, 8*n + 7}
		if 256 >= 8*n {
			budgets = append(budgets, 256)
		}
		if 1024 >= 8*n {
			budgets = append(budgets, 1024)
		}
		for _, S := range budgets {
			if S > 2048 {
				continue
			}
			tt := tNew(S, n)
			for _, ep := range epochs {
				// (a) dust swarm: n-1 members @1 (adversary, EXACTLY 1/3), whale @2(n-1).
				w := make([]*big.Int, n)
				for i := 0; i < n-1; i++ {
					w[i] = big.NewInt(1)
				}
				w[n-1] = big.NewInt(int64(2 * (n - 1)))
				pts := allocPoints(t, w, S, ep)
				advPts := 0
				for i := 0; i < n-1; i++ {
					advPts += pts[i]
				}
				if advPts >= tt {
					t.Fatalf("SAFETY BROKEN (dust swarm): n=%d S=%d epoch=%d adv(1/3) holds %d >= t=%d", n, S, ep, advPts, tt)
				}
				if m := tt - advPts; m < minMargin {
					minMargin, worst = m, fmt.Sprintf("dust-swarm n=%d S=%d ep=%d adv=%d t=%d", n, S, ep, advPts, tt)
				}

				// (b) balanced: na members @2*nh (adversary EXACTLY 1/3), nh @4*na.
				na := n / 2
				nh := n - na
				if na >= 1 && nh >= 1 {
					w2 := make([]*big.Int, n)
					for i := 0; i < na; i++ {
						w2[i] = big.NewInt(int64(2 * nh))
					}
					for i := na; i < n; i++ {
						w2[i] = big.NewInt(int64(4 * na))
					}
					p2 := allocPoints(t, w2, S, ep)
					adv2 := 0
					for i := 0; i < na; i++ {
						adv2 += p2[i]
					}
					if adv2 >= tt {
						t.Fatalf("SAFETY BROKEN (balanced): n=%d S=%d epoch=%d adv(1/3) holds %d >= t=%d", n, S, ep, adv2, tt)
					}
					if m := tt - adv2; m < minMargin {
						minMargin, worst = m, fmt.Sprintf("balanced n=%d S=%d ep=%d adv=%d t=%d", n, S, ep, adv2, tt)
					}
				}
			}
		}
	}
	t.Logf("boundary all-sizes: min safety margin = %d points; tightest at %s", minMargin, worst)
	if minMargin < 1 {
		t.Fatalf("SAFETY margin collapsed to %d", minMargin)
	}
}

// ---------------------------------------------------------------------------
// (P3) BIGINT / extreme-magnitude stakes. A 1/3-stake coalition built from
// astronomically large and adversarially-close weights must still stay < t, and
// the allocation must remain a clean partition (bigint mul/quo/mod path).
// ---------------------------------------------------------------------------
func TestC6_StakeCapture_HugeStakeMagnitudes(t *testing.T) {
	huge, _ := new(big.Int).SetString("340282366920938463463374607431768211456", 10) // 2^128
	pow := func(k int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(k)) }

	for n := 2; n <= 64; n++ {
		S := 8 * n
		for _, ep := range []uint64{0, 1, 7} {
			// adversary: n-1 members each ~ huge (spread of magnitudes), summing to
			// EXACTLY half the whale so adversary is 1/3. Whale = 2 * advSum.
			w := make([]*big.Int, n)
			advSum := new(big.Int)
			for i := 0; i < n-1; i++ {
				// vary magnitude to exercise remainder distribution: huge*(i+1) + a small perturb
				wi := new(big.Int).Mul(huge, big.NewInt(int64(i+1)))
				wi.Add(wi, pow(i%97))
				w[i] = wi
				advSum.Add(advSum, wi)
			}
			w[n-1] = new(big.Int).Mul(advSum, big.NewInt(2)) // whale = 2/3
			pts := allocPoints(t, w, S, ep)
			advPts := 0
			for i := 0; i < n-1; i++ {
				advPts += pts[i]
			}
			total := new(big.Int).Add(advSum, w[n-1])
			// confirm adversary is <= 1/3
			if new(big.Int).Mul(advSum, big.NewInt(3)).Cmp(total) > 0 {
				t.Fatalf("test bug: adversary not <=1/3 at n=%d", n)
			}
			tt := tNew(S, n)
			if advPts >= tt {
				t.Fatalf("SAFETY BROKEN (huge stakes): n=%d S=%d epoch=%d adv(1/3) holds %d >= t=%d", n, S, ep, advPts, tt)
			}
		}
	}
	t.Log("huge-magnitude bigint stakes: no <=1/3 coalition reaches t across n in [2,64] at S=8n")
}

// ---------------------------------------------------------------------------
// (P4) KNAPSACK-optimal <=1/3 coalition over RANDOM shapes. For random stake
// vectors we compute (via 0/1 knapsack DP on the SMALL point domain S) the
// MAXIMUM points any subset can hold subject to stake <= floor(total/3). This is
// the true optimum for that shape (not a heuristic), and it must stay < t.
// DP is over points (<= S <= ~1024), value = min stake to reach that many points.
// ---------------------------------------------------------------------------
func TestC6_StakeCapture_KnapsackOptimalRandom(t *testing.T) {
	var seed uint64 = 0xC6C6C6C6C6C6C6C6
	minMargin := 1 << 30
	worst := ""
	iters := 0
	for n := 2; n <= 40; n++ {
		S := 8 * n // boundary
		for trial := 0; trial < 60; trial++ {
			w := make([]*big.Int, n)
			total := new(big.Int)
			for i := 0; i < n; i++ {
				// random magnitude classes: dust, mid, whale, huge
				var v int64
				switch splitmix64(&seed) % 4 {
				case 0:
					v = 1 + int64(splitmix64(&seed)%4)
				case 1:
					v = 1 + int64(splitmix64(&seed)%10_000)
				case 2:
					v = 1 + int64(splitmix64(&seed)%100_000_000)
				default:
					v = 1 + int64(splitmix64(&seed)%1_000_000_000_000)
				}
				w[i] = big.NewInt(v)
				total.Add(total, w[i])
			}
			ep := splitmix64(&seed)
			pts := allocPoints(t, w, S, ep)
			// cap = floor(total/3) — the max stake a <=1/3 coalition may hold.
			cap3 := new(big.Int).Div(total, big.NewInt(3))
			maxPts := knapsackMaxPoints(w, pts, cap3)
			tt := tNew(S, n)
			iters++
			if maxPts >= tt {
				t.Fatalf("SAFETY BROKEN (knapsack): n=%d S=%d epoch=%d weights=%v: optimal <=1/3 coalition holds %d >= t=%d",
					n, S, ep, bigSlice(w), maxPts, tt)
			}
			if m := tt - maxPts; m < minMargin {
				minMargin, worst = m, fmt.Sprintf("n=%d S=%d ep=%d optPts=%d t=%d", n, S, ep, maxPts, tt)
			}
		}
	}
	t.Logf("knapsack-optimal random (%d shapes): min margin = %d; tightest %s", iters, minMargin, worst)
	if minMargin < 1 {
		t.Fatalf("SAFETY margin collapsed to %d", minMargin)
	}
}

// knapsackMaxPoints returns the maximum total points achievable by any subset of
// members whose summed weight is <= cap. DP indexed by points [0..S]; dp[p] holds
// the MINIMUM total weight to achieve exactly p points (big.Int); a subset with p
// points is feasible iff dp[p] <= cap. 0/1 knapsack (each member used once).
func knapsackMaxPoints(w []*big.Int, pts []int, cap *big.Int) int {
	totalPts := 0
	for _, p := range pts {
		totalPts += p
	}
	const inf = -1 // sentinel for "unreachable" (nil big.Int)
	_ = inf
	dp := make([]*big.Int, totalPts+1)
	dp[0] = big.NewInt(0)
	for i := range w {
		pi := pts[i]
		if pi == 0 {
			// a zero-point member costs stake for nothing; including it only tightens
			// the budget, never helps maximize points — skip (it can never raise maxPts).
			continue
		}
		// iterate points descending so each member is used at most once
		for p := totalPts; p >= pi; p-- {
			if dp[p-pi] == nil {
				continue
			}
			cand := new(big.Int).Add(dp[p-pi], w[i])
			if dp[p] == nil || cand.Cmp(dp[p]) < 0 {
				dp[p] = cand
			}
		}
	}
	best := 0
	for p := totalPts; p >= 0; p-- {
		if dp[p] != nil && dp[p].Cmp(cap) <= 0 {
			best = p
			break
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// (P5) LIVE non-reconstructability at the S=8n boundary through the REAL DKG.
// Builds a transparent committee whose attacker coalition holds just under 1/3
// of committee stake at the tightest coupled budget, runs the full stake-weighted
// DKG, and proves the attacker — given ALL its real derived shares and ignoring
// every on-chain gate — holds < t points AND cannot decrypt, while the honest
// >2/3 set can. This exercises the real crypto (Feldman + Lagrange + ECIES), not
// just the point-count inequality.
// ---------------------------------------------------------------------------
func TestC6_StakeCapture_LiveBoundaryNonReconstruct(t *testing.T) {
	// n = 12 committee at the S = 8n = 96 boundary. Attacker: 8 members whose
	// combined stake is just under 1/3; honest: 4 members holding just over 2/3.
	// Attacker is a SEAT MAJORITY (8/12) but a STAKE MINORITY — the HIGH-3 shape,
	// squeezed to the coupling boundary and to just-under-1/3.
	stakes := map[string]int64{}
	// honest whales: 4 * 250 = 1000 (2/3 of 1500 - eps)
	for _, op := range []string{"honest_A", "honest_B", "honest_C", "honest_D"} {
		stakes[op] = 250
	}
	// attacker: 8 members summing to 499 (< 500 = 1/3 of 1499) -> just under 1/3.
	atk := []int64{63, 63, 63, 63, 62, 62, 62, 61} // sum 499
	for i, s := range atk {
		stakes[fmt.Sprintf("attacker_%d", i)] = s
	}
	c := runTransparentDKG(t, stakes, 96)

	attackers := opsWithPrefix(c, "attacker")
	honest := opsWithPrefix(c, "honest")
	as := c.coalitionStake(attackers)
	hs := c.coalitionStake(honest)
	total := as + hs
	if len(attackers) <= len(c.round.Members)/2 {
		t.Fatalf("precondition: attacker must be a SEAT majority, got %d/%d", len(attackers), len(c.round.Members))
	}
	if 3*as > total {
		t.Fatalf("precondition: attacker must be <= 1/3 stake, got %d/%d", as, total)
	}
	if 3*hs <= 2*total {
		t.Fatalf("precondition: honest must be > 2/3 stake, got %d/%d", hs, total)
	}

	plain := []byte("victim swap: 5000 ETH -> USDC, keep sealed until ordered")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}

	// (A) attacker (<=1/3 stake, seat majority) CANNOT reconstruct — real crypto.
	atkPts, atkRec := c.coalitionReconstructs(t, attackers, ct, plain)
	if atkPts >= int(c.ak.Threshold) {
		t.Fatalf("allocation failed at boundary: attacker holds %d >= t=%d points", atkPts, c.ak.Threshold)
	}
	if atkRec {
		t.Fatal("HIGH-3 REGRESSION at boundary: <=1/3-stake seat-majority reconstructed off-chain")
	}
	// The on-chain defense-in-depth gate must also reject them.
	present := map[uint64]bool{}
	for _, op := range attackers {
		present[types.MemberIndexByOperator(c.round.Members, op)] = true
	}
	if keeper.DecryptingSetMeetsStake(c.round.Members, present) {
		t.Fatal("defense-in-depth: <=1/3-stake attacker set must fail DecryptingSetMeetsStake")
	}

	// (B) honest > 2/3 set CAN reconstruct — liveness at the boundary preserved.
	hPts, hRec := c.coalitionReconstructs(t, honest, ct, plain)
	if hPts < int(c.ak.Threshold) || !hRec {
		t.Fatalf("liveness at boundary: honest >2/3 must reconstruct, got points=%d t=%d recovered=%v", hPts, c.ak.Threshold, hRec)
	}
	t.Logf("LIVE boundary S=96 n=12: attacker stake=%d/%d (<1/3, %d/%d seats) holds %d < t=%d, cannot decrypt; "+
		"honest %d/%d (>2/3) holds %d >= t and decrypts",
		as, total, len(attackers), len(c.round.Members), atkPts, c.ak.Threshold, hs, total, hPts)
}

// TestC6_ThresholdMirrorsLiveRound cross-checks that tNew (used by the analytic
// probes above) equals the REAL keeper.stakeThreshold as materialized in an
// opened round's Threshold, at several boundary committee sizes — so the analytic
// sweeps are testing the same t the chain uses.
func TestC6_ThresholdMirrorsLiveRound(t *testing.T) {
	for _, n := range []int{2, 3, 6, 12} {
		S := 8 * n
		stakes := map[string]int64{}
		for i := 0; i < n; i++ {
			stakes[fmt.Sprintf("op_%02d", i)] = int64(1000 + i) // distinct, all comparable
		}
		c := runTransparentDKG(t, stakes, uint32(S))
		got := int(c.round.Threshold)
		want := tNew(S, n)
		if got != want {
			t.Fatalf("threshold mismatch at n=%d S=%d: live round Threshold=%d but tNew=%d", n, S, got, want)
		}
		// And confirm the round actually opened at the full committee size (no clamp).
		if len(c.round.Members) != n {
			t.Fatalf("committee size drift at n=%d S=%d: got %d members", n, S, len(c.round.Members))
		}
	}
}

func bigSlice(w []*big.Int) []string {
	out := make([]string, len(w))
	for i, x := range w {
		s := x.String()
		if len(s) > 12 {
			s = s[:6] + ".." + s[len(s)-3:]
		}
		out[i] = s
	}
	return out
}
