// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

import (
	"bytes"
	"context"
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
// threshold t is chosen from S so that (see stakeThreshold):
//
//	(SAFETY)   a coalition needs > 2/3 of the evaluation-point domain to reconstruct.
//	           SubmitEncrypted additionally fails closed if apportionment gives any
//	           <=2/3-stake coalition enough points to meet that threshold.
//	(LIVENESS) an ONLINE set must own >= t points. This is intentionally stricter than
//	           the old liveness-maximizing threshold; privacy wins over decrypting with a
//	           sub-2/3 coalition.
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
//     bounds every coalition C's allocation to (quota(C) - |C|, quota(C) + min(|C|, n-1)].
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
// already-allocated members.
//
// WEIGHTED committee (S = total eval points): t = floor(2S/3)+1 (legacy, DkgStrictConcentration
// off) or floor(2S/3)+n (v0.3.6 two-clause guard, on). The old
// liveness-maximizing t = floor(2S/3)-n+1 let ~55% stake reconstruct at the default
// S=256,n=16 topology. That was not a 2/3 confidentiality threshold. This stricter
// threshold makes the crypto bar a strict >2/3 of evaluation points; SubmitEncrypted
// then fails closed for any active apportionment where a <=2/3-stake coalition can
// still own enough rounded points to reconstruct.
//
// UNWEIGHTED committee (legacy/declared or the all-zero-weight fallback, S == n): the
// original count supermajority t = floor(2n/3) + 1, byte-identical to the pre-cycle-3
// behaviour.
//
// The +n confidentiality raise and the coupled strand check are GATED on the
// DkgStrictConcentration param (v0.3.6). strict==false reproduces the EXACT legacy
// t = floor(2S/3)+1 (weighted and unweighted) byte-for-byte, which is mandatory: this
// result is written to committed state at every DKG finalization, and live chains
// finalized ~16 epochs under the old formula that must replay under the old formula.
func stakeThreshold(members []types.RoundMember, strict bool) (t uint32, degraded bool) {
	S := types.TotalEvalPoints(members)
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
		// Unweighted (legacy / fallback) committee: original count supermajority. UNCHANGED by the
		// two-clause fix in either gate state (the fix targets the weighted/stake topology only).
		tt := (2*S)/3 + 1
		if tt > S {
			tt = S
		}
		return uint32(tt), false
	}
	// LEGACY (strict==false): byte-identical to the pre-v0.3.6 behaviour, t = floor(2S/3)+1.
	tt := (2*S)/3 + 1
	if strict {
		// TWO-CLAUSE FIX, clause 1 (CONFIDENTIALITY). Weighted t = floor(2S/3) + n, where n is the
		// committee size (every member of a weighted round is Weighted, so n = len(members)).
		//
		// Why +n and not +1: largest-remainder apportionment bounds any coalition C's points to
		// pts(C) <= quota(C) + min(|C|, n-1). A <=2/3-stake coalition has quota(C) <= 2S/3, so
		//   pts(C) <= 2S/3 + (n-1) < floor(2S/3) + n = t.
		// Therefore NO <=2/3-stake coalition can ever reach t (strict), which is exactly the
		// confidentiality property the guard needs. The old t = floor(2S/3)+1 was BELOW the
		// worst-case rounding of a legitimate <=2/3 coalition, so the fail-closed admission guard
		// tripped on ~every realistic committee (0/1600 pass) — structurally unsatisfiable.
		//
		// CLAMP SAFETY: the enforced param coupling S >= minShareBudgetPerMember * committee-cap
		// (== 8) gives S >= 8n, so t = floor(2S/3) + n <= 2S/3 + S/8 = 0.7917S < S, meaning the
		// `tt > S` clamp below can NEVER bite for a validly-configured committee and so can never
		// silently void the < t proof above.
		tt = (2*S)/3 + len(members)
	}
	if tt > S {
		tt = S
	}
	if tt < 1 {
		tt = 1
	}
	return uint32(tt), false
}

// minShareBudgetPerMember mirrors types.MinShareBudgetPerMember (== 8), the enforced eval-point
// budget floor PER COMMITTEE SEAT. Param validation requires S >= this * the committee cap, so a
// weighted committee always satisfies S >= 8n. That coupling keeps clause-1's t = floor(2S/3)+n
// strictly below S (t <= 0.7917S), so the `tt > S` clamp can never bite and void the
// confidentiality proof. Bound to the canonical types constant so the two can never drift.
const minShareBudgetPerMember = types.MinShareBudgetPerMember

// CommitteeConcentrationBreached reports whether the active epoch fails the confidentiality topology:
// either one operator alone owns >= t points, or any coalition with <=2/3 of the snapshotted stake owns
// >= t points after apportionment. SubmitEncrypted uses this as a fail-closed gate.
//
// Deterministic: a pure function of the committed DkgRound + ActiveThresholdKey. Legacy/unweighted
// committees (Weighted==false, no recorded stake) are EXEMPT - they are not the stake-topology case
// this guards, and the trusted-setup epoch 0 never reaches here.
func (k Keeper) CommitteeConcentrationBreached(ctx context.Context, epoch uint64, strict bool) bool {
	if epoch == 0 {
		return false
	}
	ak, ok := k.GetActiveKey(ctx, epoch)
	if !ok || ak.Threshold == 0 {
		return false
	}
	round, ok := k.GetDkgRound(ctx, epoch)
	if !ok || len(round.Members) == 0 {
		return false
	}
	// clause 2 (STRAND / LIVENESS) is GATED on DkgStrictConcentration (v0.3.6). `strict` is passed
	// IN by the caller (the SubmitEncrypted handler already holds the loaded params) rather than
	// re-read here — a GetParams(ctx) at this point is a metered store read that v0.3.5 never
	// performed on this path, so it would raise gas_used for any historical SubmitEncrypted and
	// diverge the app hash (LastResultsHash) when a v0.3.6 binary replays those pre-upgrade blocks
	// from genesis. Threading the flag keeps this path byte-AND-gas-identical to v0.3.5 when
	// strict==false (legacy guard: 1a + 1b only), and adds the strand clause only once strict is on.
	// clause-1 raising t to floor(2S/3)+n necessarily LOWERS the single-operator strand bar to
	// S - t + 1. An operator that alone owns >= S-t+1 eval points holds enough that the remaining
	// t-1 < t points can never reconstruct without it — it can unilaterally withhold and FREEZE
	// decryption for the epoch. Shipping clause 1 without clause 2 would OPEN a feature a single
	// concentrated node could freeze for free, strictly worse than staying closed. S = eval-point domain.
	strandBar := 0
	if strict {
		S := types.TotalEvalPoints(round.Members)
		if S+1 > int(ak.Threshold) { // t <= S always holds; strandBar = S - t + 1 >= 1
			strandBar = S - int(ak.Threshold) + 1
		}
	}
	for _, m := range round.Members {
		if !m.Weighted {
			return false // unweighted (legacy) committee: not the stake-concentration case
		}
		owned := len(m.OwnedEvalPoints())
		if uint32(owned) >= ak.Threshold {
			return true // clause 1a: this operator alone holds >= t points -> decrypts alone (confidentiality)
		}
		if strandBar > 0 && owned >= strandBar {
			return true // clause 2: this operator alone holds >= S-t+1 points -> can freeze reconstruction (liveness)
		}
	}
	if k.coalitionBelowTwoThirdsCanDecrypt(round.Members, ak.Threshold) {
		return true // clause 1b: a <=2/3-stake coalition can reach t (confidentiality)
	}
	return false
}

func (k Keeper) coalitionBelowTwoThirdsCanDecrypt(members []types.RoundMember, threshold uint32) bool {
	if threshold == 0 {
		return false
	}
	totalStake := sdkmath.ZeroInt()
	S := 0
	for _, m := range members {
		if !m.Weighted {
			return false
		}
		totalStake = totalStake.Add(weightOrZero(m.Weight))
		S += len(m.OwnedEvalPoints())
	}
	if !totalStake.IsPositive() || S == 0 {
		return false
	}
	target := int(threshold)
	if target > S {
		return false
	}
	ok := make([]bool, S+1)
	dp := make([]sdkmath.Int, S+1) // minimum stake needed to own exactly this many capped points
	ok[0] = true
	dp[0] = sdkmath.ZeroInt()
	for _, m := range members {
		pts := len(m.OwnedEvalPoints())
		if pts == 0 {
			continue
		}
		w := weightOrZero(m.Weight)
		for have := S; have >= 0; have-- {
			if !ok[have] {
				continue
			}
			next := have + pts
			if next > S {
				next = S
			}
			cand := dp[have].Add(w)
			if !ok[next] || dp[next].GT(cand) {
				ok[next] = true
				dp[next] = cand
			}
		}
	}
	limit := totalStake.MulRaw(2)
	for pts := target; pts <= S; pts++ {
		if ok[pts] && !dp[pts].MulRaw(3).GT(limit) {
			return true
		}
	}
	return false
}
