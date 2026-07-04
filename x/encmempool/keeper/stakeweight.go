package keeper

import (
	"sort"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// HIGH-3: STAKE-WEIGHTED SECRET SHARING.
//
// The committee seats are stake-ranked, but a plain Shamir scheme gives every seat ONE
// share and sets the reconstruction threshold to a member COUNT — so a stake-MINORITY that
// holds a seat-MAJORITY holds >= t legitimate shares and can reconstruct the epoch secret
// OFF-CHAIN (an anti-MEV / front-running break that no on-chain gate can stop). This file
// bakes stake into the CRYPTOGRAPHY instead: each member is allocated a number of distinct
// Shamir evaluation points PROPORTIONAL to its stake, within a fixed total budget S, and the
// threshold is a FRACTION of S. Then any coalition that can assemble t points necessarily
// controls a stake-supermajority, so off-chain reconstruction requires the SAME stake the
// on-chain gate wanted — the capability now matches the crypto.
//
// DETERMINISM: allocation is a pure integer function of the snapshotted per-member stake and
// the budget (largest-remainder apportionment, ties broken by input order). No wall-clock, no
// float, no map iteration — every node allocates byte-identical EvalPoints, which is the #1
// fork-safety requirement (the allocation is stored in the DkgRound and hashed into decrypt
// share authorization).
// ============================================================================

// AllocateEvalPoints deterministically assigns each member a CONTIGUOUS block of Shamir
// evaluation points sized PROPORTIONAL to its stake Weight within the fixed budget S, via
// integer largest-remainder (Hamilton) apportionment. Members are consumed in the given order
// (callers pass them operator-sorted), and the whole committee's points form the contiguous
// domain 1..S' where S' = Σ allocated <= S. It returns a COPY with EvalPoints filled.
//
// POLICY (documented, deliberate):
//   - Faithful proportional apportionment with NO minimum floor and NO maximum cap. A member
//     whose exact quota rounds to 0 gets 0 points (it holds no decryption power that epoch —
//     correct: negligible stake => negligible capability). A whale holding a stake-supermajority
//     legitimately gets >= t points and can decrypt alone (that IS the honest-majority trust
//     assumption; capping it would only harm liveness). A forced min-1 floor is REJECTED because
//     it decouples a seat count from stake — a swarm of dust validators could then accumulate
//     seats out of proportion to stake and defeat the very bound this feature establishes.
//   - Largest-remainder keeps Σ = S exactly (so t-as-a-fraction-of-S is exact) and bounds each
//     member's allocation to ceil(quota) = its stake quota + at most one "remainder" seat; the
//     total rounding slop across any coalition is <= min(coalition_size, honest_size) <=
//     committee_size/2, which stays well under the S/3 margin (see stakeThreshold).
//
// Fallback: when no member carries a positive Weight (the legacy/declared path, which never
// records stake), each member is given the single point equal to its Index, reproducing the
// unweighted (one-share-per-member) scheme unchanged.
func AllocateEvalPoints(members []types.RoundMember, budget int) []types.RoundMember {
	out := make([]types.RoundMember, len(members))
	copy(out, members)

	// Total stake W = Σ w_i over positive weights.
	total := sdkmath.ZeroInt()
	for _, m := range out {
		if w := m.Weight; !w.IsNil() && w.IsPositive() {
			total = total.Add(w)
		}
	}
	if budget < 1 || !total.IsPositive() {
		// Unweighted / legacy fallback: one point per member, equal to its index.
		for i := range out {
			out[i].EvalPoints = []uint64{out[i].Index}
		}
		return out
	}

	S := sdkmath.NewInt(int64(budget))
	base := make([]int, len(out))        // floor(w_i * S / W)
	rem := make([]sdkmath.Int, len(out)) // (w_i * S) mod W (the fractional remainder, scaled by W)
	assigned := 0
	for i, m := range out {
		w := m.Weight
		if w.IsNil() || !w.IsPositive() {
			rem[i] = sdkmath.ZeroInt()
			continue
		}
		num := w.Mul(S)          // w_i * S (bigint: overflow-safe for any stake magnitude)
		q := num.Quo(total)      // floor
		base[i] = int(q.Int64()) // q <= S <= budget <= maxDkgShareBudget, fits int64
		rem[i] = num.Mod(total)
		assigned += base[i]
	}

	// Distribute the R = S - Σfloor leftover points to the members with the LARGEST remainders,
	// ties broken by input order (lower index first) — fully deterministic.
	remainderSeats := budget - assigned
	if remainderSeats > 0 {
		order := make([]int, len(out))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			return rem[order[a]].GT(rem[order[b]]) // larger remainder wins; stable => input order tie-break
		})
		for k := 0; k < remainderSeats && k < len(order); k++ {
			base[order[k]]++
		}
	}

	// Lay out contiguous eval-point blocks in the given (operator-sorted) order: 1..S'.
	next := uint64(1)
	for i := range out {
		a := base[i]
		if a <= 0 {
			out[i].EvalPoints = nil
			continue
		}
		pts := make([]uint64, a)
		for j := 0; j < a; j++ {
			pts[j] = next
			next++
		}
		out[i].EvalPoints = pts
	}
	return out
}

// stakeThreshold returns the reconstruction threshold t for a Shamir evaluation-point domain
// of size S: t = floor(2S/3) + 1, a STRICT BFT SUPERMAJORITY of the points.
//
// JUSTIFICATION (> 2S/3 chosen over > S/2): the points are allocated proportional to stake, so
// assembling t = floor(2S/3)+1 points requires > 2/3 of committee stake (minus bounded rounding
// slop). This ALIGNS the decryption bar with the chain's own 2/3 BFT honest-stake assumption:
//   - CONFIDENTIALITY (anti-MEV): any adversary within the Byzantine bound (<= 1/3 stake) holds
//     <= S/3 + slop points, which is < t, so it can NEVER reconstruct early — the strongest bar
//     consistent with the trust model. A > S/2 bar would let a mere >1/2 stake coalition front-run.
//   - LIVENESS: whenever the chain is live it already has > 2/3 honest online stake (block
//     production needs it), and that same supermajority holds >= t points, so decryption is live
//     exactly when the chain is. (A > S/2 bar would trade this stronger confidentiality for the
//     ability of any bare majority to decrypt — not worth it for a dormant-by-default feature.)
//
// Clamped to [1, S] (you can never need more points than exist).
func stakeThreshold(totalEvalPoints int) uint32 {
	if totalEvalPoints < 1 {
		return 1
	}
	t := (2*totalEvalPoints)/3 + 1
	if t > totalEvalPoints {
		t = totalEvalPoints
	}
	return uint32(t)
}
