// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// HIGH-3: STAKE-WEIGHTED SECRET SHARING (cycle-3 hardened).
//
// The committee seats are stake-ranked, but a plain Shamir scheme gives every seat ONE
// share and sets the reconstruction threshold to a member COUNT — so a stake-MINORITY that
// holds a seat-MAJORITY holds >= t legitimate shares and can reconstruct the epoch secret
// OFF-CHAIN (an anti-MEV / front-running break that no on-chain gate can stop). This file
// bakes stake into the CRYPTOGRAPHY instead: each member is allocated a number of distinct
// Shamir evaluation points PROPORTIONAL to its stake, within a fixed total budget S, and the
// threshold t is chosen from S and the committee size n so that (see stakeThreshold):
//
//	(SAFETY)   any coalition holding <= 1/3 of the snapshotted committee stake holds < t
//	           points — on AND off chain — whenever S >= 6n - 1 (validation enforces the
//	           stronger S >= MinShareBudgetPerMember*n = 8n);
//	(LIVENESS) any ONLINE set holding > 2/3 of the snapshotted committee stake holds >= t
//	           points, for ALL n and ALL stake distributions (no residual band).
//
// DETERMINISM: allocation is a pure integer function of the snapshotted per-member stake,
// the budget, and the epoch number (largest-remainder apportionment; remainder ties broken
// by stake desc, then an epoch-keyed hash of the operator — no wall-clock, no float, no map
// iteration). Every node allocates byte-identical EvalPoints, which is the #1 fork-safety
// requirement (the allocation is stored in the DkgRound and hashed into decrypt share
// authorization).
// ============================================================================

// AllocateEvalPoints deterministically assigns each member a CONTIGUOUS block of Shamir
// evaluation points sized PROPORTIONAL to its stake Weight within the fixed budget S, via
// integer largest-remainder (Hamilton) apportionment. Members are consumed in the given order
// (callers pass them operator-sorted), and the whole committee's points form the contiguous
// domain 1..S' where S' = Σ allocated <= S. Every member of a weighted committee is marked
// Weighted (including zero-allocation members — cycle-3 L-1: a zero-weight member OWNS
// NOTHING; it must never fall back to {Index}, which collided with a legitimately-owned
// point and deterministically stalled every finalize). epoch seeds the remainder-seat
// tie-break (cycle-3 L-2) so equal-remainder seats rotate per epoch instead of permanently
// following operator-address order (a grindable, vanity-address-capturable key). It returns
// a COPY with EvalPoints/Weighted filled.
//
// POLICY (documented, deliberate):
//   - Faithful proportional apportionment with NO minimum floor and NO maximum cap. A member
//     whose exact quota rounds to 0 gets 0 points (it holds no decryption power that epoch —
//     correct: negligible stake => negligible capability). A whale holding enough stake
//     legitimately gets >= t points and can decrypt alone (that IS the honest-majority trust
//     assumption; capping it would only harm liveness). A forced min-1 floor is REJECTED because
//     it decouples a seat count from stake — a swarm of dust validators could then accumulate
//     seats out of proportion to stake and defeat the very bound this feature establishes.
//   - Largest-remainder keeps Σ = S exactly (so a threshold expressed against S is exact) and
//     bounds every coalition C's allocation to (quota(C) - |C|, quota(C) + min(|C|, n-1)] —
//     the slop bounds stakeThreshold's safety/liveness proof is built on.
//   - Remainder-seat ties (equal fractional remainders) are broken by stake DESC first (more
//     stake => strictly-no-worse treatment), then by sha256(epoch || operator) ASC. The hash
//     key is deterministic and byte-identical across nodes (pure function of committed
//     inputs) but ROTATES with the epoch, so a vanity low-sorting operator address no longer
//     captures tie-broken remainder seats round after round (cycle-3 L-2).
//
// Fallback: when no member carries a positive Weight (the legacy/declared path, which never
// records stake), each member is given the single point equal to its Index, reproducing the
// unweighted (one-share-per-member) scheme unchanged (and Weighted stays false).
func AllocateEvalPoints(members []types.RoundMember, budget int, epoch uint64) []types.RoundMember {
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
			out[i].Weighted = false
		}
		return out
	}

	S := sdkmath.NewInt(int64(budget))
	base := make([]int, len(out))        // floor(w_i * S / W)
	rem := make([]sdkmath.Int, len(out)) // (w_i * S) mod W (the fractional remainder, scaled by W)
	assigned := 0
	for i, m := range out {
		out[i].Weighted = true // whole committee is stake-weighted, incl. zero-allocation members
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

	// Distribute the R = S - Σfloor leftover points to the members with the LARGEST remainders.
	// Ties: stake DESC, then sha256(epoch || operator) ASC — fully deterministic and identical
	// on every node, but epoch-rotating so the tie-break cannot be ground via a vanity operator
	// address (cycle-3 L-2; the previous input-order tie-break was operator-address ascending,
	// a permanently capturable key).
	remainderSeats := budget - assigned
	if remainderSeats > 0 {
		tie := make([][]byte, len(out))
		for i := range out {
			tie[i] = remainderTieKey(epoch, out[i].OperatorAddr)
		}
		order := make([]int, len(out))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			ia, ib := order[a], order[b]
			if !rem[ia].Equal(rem[ib]) {
				return rem[ia].GT(rem[ib]) // larger remainder wins (Hamilton core)
			}
			wa, wb := weightOrZero(out[ia].Weight), weightOrZero(out[ib].Weight)
			if !wa.Equal(wb) {
				return wa.GT(wb) // equal remainder: larger stake wins
			}
			return bytes.Compare(tie[ia], tie[ib]) < 0 // equal stake: epoch-keyed hash order
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

// remainderTieKey is the epoch-rotating deterministic tie-break key for remainder seats:
// sha256(domain-tag || epoch_be || operator). Pure function of committed inputs — byte-
// identical on every node — with no wall-clock, randomness, or map-order dependence.
func remainderTieKey(epoch uint64, operator string) []byte {
	h := sha256.New()
	h.Write([]byte("encmempool/dkg/remainder-seat-tiebreak/v1"))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	h.Write(e[:])
	h.Write([]byte(operator))
	return h.Sum(nil)
}

func weightOrZero(w sdkmath.Int) sdkmath.Int {
	if w.IsNil() {
		return sdkmath.ZeroInt()
	}
	return w
}

// stakeThreshold returns the reconstruction threshold t for a round with the given
// (already-allocated) members, plus whether the safety floor had to DEGRADE liveness
// because the S >= 6n - 1 coupling was violated (unreachable through validated params +
// the committee clamp; pure defense-in-depth).
//
// WEIGHTED committee (S = total eval points, n = committee size):
//
//	t = floor(2S/3) - n + 1
//
// WORST-CASE HAMILTON APPORTIONMENT BOUNDS (the whole proof rests on these two):
// for any coalition C with exact stake fraction f (of the snapshotted committee total),
// quota(C) = f*S, and largest-remainder gives every member floor(q_i) or floor(q_i)+1
// with exactly R = S - Σ_all floor(q_i) <= n-1 "+1" seats total, so
//
//	points(C) >= Σ_{i∈C} floor(q_i) >  f*S - |C|          (each floor loses < 1)
//	points(C) <= Σ_{i∈C} floor(q_i) + min(|C|, R)
//	          <= floor(f*S) + min(|C|, n-1)               (Σ floors <= floor of Σ)
//
// (SAFETY — confidentiality at the Byzantine bound) f <= 1/3 and |C| <= n-1 (some member
// holds the other >= 2/3) give points(C) <= floor(S/3) + n - 1. This is < t iff
// floor(2S/3) - floor(S/3) >= 2n - 1, which holds whenever S >= 6n - 1; the validated
// coupling S >= 8n (types.MinShareBudgetPerMember) therefore guarantees it with a margin
// of >= (2n+1)/3 points. So a <=1/3-stake coalition can NEVER assemble t points — on chain
// or off — closing HIGH-3 without the cycle-3 H-A config hole.
//
// (LIVENESS — the cycle-3 H-B fix) any ONLINE set O with stake fraction f > 2/3 satisfies
// points(O) > (2/3)S - |O| >= (2/3)S - n, and points are integers, so
// points(O) >= floor(2S/3) - n + 1 = t EXACTLY — for ALL n, ALL stake distributions, and
// ALL offline patterns whose online remainder still holds > 2/3 of the SNAPSHOTTED
// committee stake. There is NO residual liveness band: t is the LARGEST threshold with
// this guarantee, so the choice maximizes confidentiality subject to guaranteed liveness.
// (The previous t = floor(2S/3)+1 demanded points the rounding slop could deny an honest
// supermajority — a 66.7%..~72.9% dead band at S=256, n=16 — and the matured ciphertext
// was then silently dropped; see decryptMatured for the non-silent deferral counterpart.)
//
// (REAL DECRYPT BAR — cycle-3 M-1, stated honestly) the ">2/3 stake to decrypt" claim is
// NOT achievable together with guaranteed >2/3-liveness, because rounding slop is +-n
// points. The PROVEN bar: any coalition that reaches t points holds stake fraction
//
//	f >= (t - n + 1)/S = (floor(2S/3) - 2n + 2)/S  >  2/3 - 2n/S
//	  >= 2/3 - 2/MinShareBudgetPerMember = 5/12 (~41.7%) under the enforced S >= 8n,
//	  and ALWAYS > 1/3 (the safety inequality above);
//	  at the live defaults (S=256, n<=16) f >= 140/256 ~ 54.7%.
//
// Every "supermajority to decrypt" comment/doc claim is replaced by this bar. The on-chain
// combine additionally keeps the strict-stake-majority gate (DecryptingSetMeetsStake) as
// defense-in-depth; in worst-case rounding that gate can bind ABOVE the crypto bar for
// on-chain decryption, but it can never block the guaranteed liveness case (an online
// >2/3-stake set is also a strict majority).
//
// UNWEIGHTED committee (legacy/declared or the all-zero-weight fallback, S == n): the
// original count supermajority t = floor(2n/3) + 1, byte-identical to the pre-cycle-3
// behaviour.
//
// DEGRADED clamp (defense-in-depth only): if a weighted round somehow opens with
// S < 6n - 1 (impossible via Params.Validate + the TransparentMembers committee clamp),
// t is raised to the safety floor min(S, floor(S/3)+n+1) — CONFIDENTIALITY IS PREFERRED
// OVER LIVENESS on an invalid config — and the caller emits a loud event. Deterministic
// on every node either way; never a halt or fork.
func stakeThreshold(members []types.RoundMember) (t uint32, degraded bool) {
	S := types.TotalEvalPoints(members)
	n := len(members)
	if S < 1 {
		return 1, false
	}
	weighted := false
	for _, m := range members {
		if m.Weighted {
			weighted = true
			break
		}
	}
	if !weighted {
		// Unweighted (legacy / fallback) committee: original count supermajority.
		tt := (2*S)/3 + 1
		if tt > S {
			tt = S
		}
		return uint32(tt), false
	}
	tt := (2*S)/3 - n + 1
	if safetyFloor := S/3 + n + 1; tt < safetyFloor {
		// S < ~6n: no threshold satisfies both inequalities. Prefer safety.
		tt = safetyFloor
		degraded = true
	}
	if tt > S {
		tt = S
	}
	if tt < 1 {
		tt = 1
	}
	return uint32(tt), degraded
}
