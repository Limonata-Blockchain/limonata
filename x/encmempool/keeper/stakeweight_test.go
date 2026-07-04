package keeper_test

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// HIGH-3 (stake-weighted secret sharing) regression + property tests.
//
// The fix bakes stake into the CRYPTOGRAPHY: each committee member is allocated Shamir
// evaluation points PROPORTIONAL to its stake within a bounded budget S, and the threshold is
// t = floor(2S/3)+1 of them. So a coalition can reconstruct the epoch secret (on OR off chain)
// only if it holds >= t points, which requires a stake supermajority. These tests assert:
//   - a stake-MINORITY seat-MAJORITY holds < t points and CANNOT reconstruct off-chain (the flip);
//   - an honest stake-SUPERMAJORITY holds >= t points and CAN reconstruct (liveness preserved);
//   - allocation is deterministic from snapshotted stake (fork-safety);
//   - total allocated points <= S regardless of stake magnitude (bounded VE/dealing size).
// ============================================================================

// h3Committee is the resolved output of a full transparent stake-weighted DKG run.
type h3Committee struct {
	k        keeper.Keeper
	ctx      sdk.Context
	round    types.DkgRound
	ak       types.ActiveThresholdKey
	dealings map[uint64]types.Dealing
	byOp     map[string]member
}

// runTransparentDKG builds a transparent committee from the operator->stake map, runs the FULL
// stake-weighted in-node DKG through the real keeper (announce -> open -> deal -> finalize), and
// returns everything an attacker would need to attempt an off-chain reconstruction. budget sets
// DkgShareBudget (0 => the params default).
func runTransparentDKG(t *testing.T, stakes map[string]int64, budget uint32) h3Committee {
	t.Helper()
	ops := make([]string, 0, len(stakes))
	for op := range stakes {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	var vals []stakingtypes.Validator
	byOp := map[string]member{}
	for _, op := range ops {
		byOp[op] = newMember(op, "")
		vals = append(vals, bondedVal(op, stakes[op]))
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(0, 0)
	if budget != 0 {
		p.DkgShareBudget = budget
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	ann := make([]keeper.VEEntry, 0, len(ops))
	for _, op := range ops {
		ann = append(ann, keeper.VEEntry{Operator: op, VE: annVE(byOp[op])})
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok || round.Status != types.DkgStatusOpen {
		t.Fatalf("epoch 1 not opened: %+v", round)
	}
	entries := make([]keeper.VEEntry, 0, len(round.Members))
	for _, rm := range round.Members {
		entries = append(entries, buildDealingEntry(t, round, byOp[rm.OperatorAddr]))
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), entries)
	k.EndBlockDKG(ctx.WithBlockHeight(int64(round.ComplaintDeadline)))
	ak, ok := k.GetActiveKey(ctx, 1)
	if !ok {
		t.Fatal("no active key after finalize (honest supermajority must finalize)")
	}
	round, _ = k.GetDkgRound(ctx, 1)
	dealings := map[uint64]types.Dealing{}
	k.IterateDealings(ctx, 1, func(d types.Dealing) { dealings[d.DealerIndex] = d })
	return h3Committee{k: k, ctx: ctx, round: round, ak: ak, dealings: dealings, byOp: byOp}
}

func (c h3Committee) memberPoints(op string) []uint64 {
	for _, m := range c.round.Members {
		if m.OperatorAddr == op {
			return m.OwnedEvalPoints()
		}
	}
	return nil
}

func (c h3Committee) coalitionStake(ops []string) int64 {
	total := int64(0)
	for _, op := range ops {
		for _, m := range c.round.Members {
			if m.OperatorAddr == op && !m.Weight.IsNil() {
				total += m.Weight.Int64()
			}
		}
	}
	return total
}

// coalitionReconstructs runs the FULL off-chain attack for a set of operators: each member
// derives its REAL Shamir shares at its owned eval points, and the coalition tries to recover the
// epoch secret and decrypt ct — via BOTH the enforced RecoverVerified path and the raw Lagrange
// path (an attacker who ignores every on-chain gate). Returns (# eval points held, whether the
// exact plaintext was recovered).
func (c h3Committee) coalitionReconstructs(t *testing.T, ops []string, ct *threshold.Ciphertext, plain []byte) (points int, recovered bool) {
	t.Helper()
	commitments, err := dkg.ParseCommitmentPoints(c.ak.PublicCommitments)
	if err != nil {
		t.Fatalf("parse commitments: %v", err)
	}
	var partials []dkg.VerifiedShare
	var raw []*threshold.DecryptShare
	for _, op := range ops {
		m := c.byOp[op]
		shares, err := dkgnode.DeriveShares(c.memberPoints(op), m.priv, c.ak.Qual, c.dealings)
		if err != nil {
			t.Fatalf("member %s derive shares: %v", op, err)
		}
		for _, sh := range shares {
			ds, proof, err := dkg.ProveDecryptShare(sh, ct)
			if err != nil {
				t.Fatalf("prove share: %v", err)
			}
			partials = append(partials, dkg.VerifiedShare{Share: ds, Proof: proof})
			raw = append(raw, ds)
			points++
		}
	}
	tt := int(c.ak.Threshold)
	if shared, err := dkg.RecoverVerified(commitments, ct.A, tt, partials); err == nil {
		if pt, derr := threshold.Decrypt(shared, ct); derr == nil && bytes.Equal(pt, plain) {
			return points, true
		}
	}
	// Raw Lagrange over WHATEVER points the coalition holds (the true off-chain attack). With
	// < t points this interpolates the wrong polynomial and the AES-GCM open fails.
	if len(raw) > 0 {
		if shared, err := threshold.Recover(raw); err == nil {
			if pt, derr := threshold.Decrypt(shared, ct); derr == nil && bytes.Equal(pt, plain) {
				return points, true
			}
		}
	}
	return points, false
}

func opsWithPrefix(c h3Committee, prefix string) []string {
	var out []string
	for _, m := range c.round.Members {
		if strings.HasPrefix(m.OperatorAddr, prefix) {
			out = append(out, m.OperatorAddr)
		}
	}
	sort.Strings(out)
	return out
}

// TestReg_H3_StakeMinoritySeatMajorityCannotReconstructOffChain is the CORE flip. A committee of
// 3 honest whales (1000 each) + 9 attacker mid validators (200 each): the attacker is a SEAT
// MAJORITY (9 of 12) but a STAKE MINORITY (1800 < 3000). Under stake-weighted sharing it holds
// only ~9 of S=24 eval points, which is < t=17, so — GIVEN ALL ITS REAL SHARES — it cannot
// reconstruct the epoch secret off-chain. (Pre-fix, its 9 seats == 9 Shamir shares >= the count
// threshold and it decrypted; that probe is now this regression, asserting the opposite.)
func TestReg_H3_StakeMinoritySeatMajorityCannotReconstructOffChain(t *testing.T) {
	stakes := map[string]int64{"honest_A": 1000, "honest_B": 1000, "honest_C": 1000}
	for i := 0; i < 9; i++ {
		stakes["attacker_"+string(rune('a'+i))] = 200
	}
	c := runTransparentDKG(t, stakes, 24)

	attackers := opsWithPrefix(c, "attacker")
	honest := opsWithPrefix(c, "honest")
	seatMajority := len(attackers) > len(c.round.Members)/2
	stakeMinority := c.coalitionStake(attackers) < c.coalitionStake(honest)
	if !seatMajority || !stakeMinority {
		t.Fatalf("precondition: attacker must be seat-majority (%d/%d) AND stake-minority (%d<%d)",
			len(attackers), len(c.round.Members), c.coalitionStake(attackers), c.coalitionStake(honest))
	}

	plain := []byte("SWAP 1000 ETH -> USDC at block N (front-run me)")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	pts, recovered := c.coalitionReconstructs(t, attackers, ct, plain)
	if pts >= int(c.ak.Threshold) {
		t.Fatalf("allocation failed: attacker holds %d >= t=%d eval points", pts, c.ak.Threshold)
	}
	if recovered {
		t.Fatal("HIGH-3 REGRESSION: stake-minority seat-majority reconstructed the secret off-chain")
	}

	// The on-chain stake gate (now defense-in-depth) still rejects the same member set.
	present := map[uint64]bool{}
	for _, op := range attackers {
		present[types.MemberIndexByOperator(c.round.Members, op)] = true
	}
	if keeper.DecryptingSetMeetsStake(c.round.Members, present) {
		t.Fatal("defense-in-depth: the stake-minority member set must still fail DecryptingSetMeetsStake")
	}
	t.Logf("attacker seat-majority (%d/%d seats, stake %d/%d) holds only %d < t=%d eval points; "+
		"off-chain reconstruction is cryptographically impossible",
		len(attackers), len(c.round.Members), c.coalitionStake(attackers),
		c.coalitionStake(attackers)+c.coalitionStake(honest), pts, c.ak.Threshold)
}

// TestReg_H3_HonestSupermajorityReconstructs is the LIVENESS counterpart: an honest stake
// SUPERMAJORITY (5 whales @ 1000 = 98% vs a lone 100-stake straggler) holds >= t eval points, so
// it CAN recover the epoch secret and decrypt — the fix must not break the honest path.
func TestReg_H3_HonestSupermajorityReconstructs(t *testing.T) {
	stakes := map[string]int64{"straggler": 100}
	for _, op := range []string{"honest_A", "honest_B", "honest_C", "honest_D", "honest_E"} {
		stakes[op] = 1000
	}
	c := runTransparentDKG(t, stakes, 24)

	honest := opsWithPrefix(c, "honest")
	plain := []byte("honest supermajority decrypts at maturity")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	pts, recovered := c.coalitionReconstructs(t, honest, ct, plain)
	if pts < int(c.ak.Threshold) {
		t.Fatalf("liveness: honest supermajority holds only %d < t=%d eval points", pts, c.ak.Threshold)
	}
	if !recovered {
		t.Fatal("liveness BROKEN: honest stake-supermajority failed to reconstruct the secret")
	}
	t.Logf("honest stake-supermajority holds %d >= t=%d eval points and decrypted successfully",
		pts, c.ak.Threshold)
}

// TestReg_H3_AllocationDeterministic asserts two independent nodes allocate BYTE-IDENTICAL eval
// points from the same snapshotted stake — the fork-safety requirement (the allocation is stored
// in the DkgRound and authorizes decrypt shares, so any divergence forks the chain).
func TestReg_H3_AllocationDeterministic(t *testing.T) {
	ms := map[string]member{
		"opA": newMember("opA", ""), "opB": newMember("opB", ""),
		"opC": newMember("opC", ""), "opD": newMember("opD", ""),
	}
	stake := map[string]int64{"opA": 500, "opB": 300, "opC": 137, "opD": 63}
	var vals []stakingtypes.Validator
	for op, s := range stake {
		vals = append(vals, bondedVal(op, s))
	}
	p := transparentParams(0, 0)
	// Two independent keepers over the SAME committed staking state, each with the enc keys
	// announced (a member is only committee-eligible once it has registered an enc key).
	kA, ctxA := newKeeperSK(t, 1, &mockStaking{vals: vals})
	kB, ctxB := newKeeperSK(t, 1, &mockStaking{vals: vals})
	for op, m := range ms {
		kA.RecordEncPubKey(ctxA, op, m.pub, encPoP(m))
		kB.RecordEncPubKey(ctxB, op, m.pub, encPoP(m))
	}
	membersA := kA.ActiveMembers(ctxA, p)
	membersB := kB.ActiveMembers(ctxB, p)
	if len(membersA) != len(membersB) || len(membersA) == 0 {
		t.Fatalf("member count mismatch: %d vs %d", len(membersA), len(membersB))
	}
	for i := range membersA {
		if membersA[i].OperatorAddr != membersB[i].OperatorAddr {
			t.Fatalf("member[%d] operator diverged: %q vs %q", i, membersA[i].OperatorAddr, membersB[i].OperatorAddr)
		}
		if !equalU64(membersA[i].EvalPoints, membersB[i].EvalPoints) {
			t.Fatalf("member %s eval points diverged: %v vs %v",
				membersA[i].OperatorAddr, membersA[i].EvalPoints, membersB[i].EvalPoints)
		}
	}
	// And the domain is exactly the budget S, contiguous 1..S.
	if got := types.TotalEvalPoints(membersA); got != p.EffectiveShareBudget() {
		t.Fatalf("total eval points %d != budget %d", got, p.EffectiveShareBudget())
	}
}

// TestReg_H3_AllocationBounded asserts the total allocated eval points never exceeds the budget S
// regardless of stake magnitude (bounded VE/dealing size), using astronomically large stakes.
func TestReg_H3_AllocationBounded(t *testing.T) {
	huge, _ := sdkmath.NewIntFromString("340282366920938463463374607431768211456") // 2^128
	members := []types.RoundMember{
		{Index: 1, OperatorAddr: "opA", Weight: huge},
		{Index: 2, OperatorAddr: "opB", Weight: huge.MulRaw(7)},
		{Index: 3, OperatorAddr: "opC", Weight: sdkmath.OneInt()},
		{Index: 4, OperatorAddr: "opD", Weight: huge.MulRaw(3)},
	}
	for _, S := range []int{1, 3, 7, 24, 256, 4096} {
		out := keeper.AllocateEvalPoints(members, S)
		total := types.TotalEvalPoints(out)
		if total > S {
			t.Fatalf("budget %d: total eval points %d exceeds S", S, total)
		}
		// Points must be the distinct contiguous domain 1..total (no collisions across members).
		seen := map[uint64]bool{}
		for _, m := range out {
			for _, pt := range m.EvalPoints {
				if pt < 1 || pt > uint64(S) || seen[pt] {
					t.Fatalf("budget %d: bad/duplicate eval point %d", S, pt)
				}
				seen[pt] = true
			}
		}
	}
}

// TestReg_H3_AllocationProportionalAndFloor sanity-checks the largest-remainder policy: a member
// with ~0 stake fraction can get 0 points (its capability tracks its stake), the whole budget is
// consumed, and a whale gets the lion's share.
func TestReg_H3_AllocationProportionalAndFloor(t *testing.T) {
	members := []types.RoundMember{
		{Index: 1, OperatorAddr: "whale", Weight: sdkmath.NewInt(1000)},
		{Index: 2, OperatorAddr: "dust1", Weight: sdkmath.NewInt(1)},
		{Index: 3, OperatorAddr: "dust2", Weight: sdkmath.NewInt(1)},
	}
	out := keeper.AllocateEvalPoints(members, 24)
	if types.TotalEvalPoints(out) != 24 {
		t.Fatalf("budget must be fully consumed, got %d", types.TotalEvalPoints(out))
	}
	if len(out[0].EvalPoints) < 20 {
		t.Fatalf("whale (99.8%% stake) must dominate the budget, got %d points", len(out[0].EvalPoints))
	}
	// Unweighted fallback: zero weights => one point per member equal to its index.
	zero := []types.RoundMember{{Index: 1}, {Index: 2}, {Index: 3}}
	z := keeper.AllocateEvalPoints(zero, 24)
	for i, m := range z {
		if len(m.EvalPoints) != 1 || m.EvalPoints[0] != uint64(i+1) {
			t.Fatalf("unweighted fallback must give member %d the single point %d, got %v", i+1, i+1, m.EvalPoints)
		}
	}
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
