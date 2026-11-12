// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

// CYCLE-7 ADVERSARIAL AUDIT — lens: STAKE-DRIFT / REKEY (black-box, through the REAL
// EndBlockDKG — the same determinism surface a live node runs).
//
// Answers: (Q1) is the residual drift bound guaranteed at all configs? (Q2) is the
// cadence/bps trigger deterministic (no fork)? (Q3) weaponizable into a rekey-storm DoS
// despite the dampener? plus the overflow finding's live consequence.

import (
	"math/big"
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

func bigPow10(n int64) sdkmath.Int {
	return sdkmath.NewIntFromBigInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(n), nil))
}
func bondedValBig(op string, tokens sdkmath.Int) stakingtypes.Validator {
	return stakingtypes.Validator{OperatorAddress: op, Tokens: tokens, Status: stakingtypes.Bonded}
}

// TestC7_BB_OverflowRecoveredNoHaltNoRekey drives EndBlockDKG on a committee whose stake
// exceeds the sdkmath.Int 256-bit envelope. The drift metric PANICS (overflow), but:
//   - EndBlockDKG's defense-in-depth recover contains it: NO halt, deterministic event;
//   - the panic event fires EVERY block (consensus-log spam);
//   - the stake-drift rekey the operator ENABLED silently NEVER fires (feature dead — the
//     snapshot coupling erodes unbounded exactly as if it were off);
//   - two nodes stay byte-identical (no fork).
func TestC7_BB_OverflowRecoveredNoHaltNoRekey(t *testing.T) {
	big40 := bigPow10(40)
	mkSK := func() *mockStaking {
		return &mockStaking{vals: []stakingtypes.Validator{
			bondedValBig("opA", big40), bondedValBig("opB", big40), bondedValBig("opC", big40),
		}}
	}
	skA, skB := mkSK(), mkSK()
	ms := []member{newMember("opA", ""), newMember("opB", ""), newMember("opC", "")}

	p := transparentParams(2, 0)
	p.DkgMaxEpochBlocks = 0       // cadence OFF so the bps path (the metric) is exercised
	p.DkgRekeyOnStakeDriftBps = 1 // drift rekey ENABLED (operator turned it on)
	p.DkgMinRekeyGap = 0          // no gap dampening in the way

	kA, ctxA := activeRoundFixtureSK(t, skA, ms, p)
	kB, ctxB := activeRoundFixtureSK(t, skB, ms, p)

	// A big re-delegation that (if the metric worked) would be a large drift => should rekey.
	reDelegateBig(skA, "opA", big40.MulRaw(3))
	reDelegateBig(skB, "opA", big40.MulRaw(3))

	halted := false
	for h := int64(10); h < 25; h++ {
		bA := ctxA.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		bB := ctxB.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		func() {
			defer func() {
				if r := recover(); r != nil {
					halted = true // EndBlockDKG itself panicked OUT (recover failed) => a real halt
				}
			}()
			kA.EndBlockDKG(bA)
			kB.EndBlockDKG(bB)
		}()
		if halted {
			t.Fatalf("HALT: EndBlockDKG panicked out of its recover at height %d", h)
		}
		// The overflow must be contained as the deterministic panic event...
		if countEvents(bA, "encmempool_dkg_endblock_panic") == 0 {
			t.Fatalf("height %d: expected recovered panic event (overflow), none emitted", h)
		}
		// ...and the rekey the operator enabled must NOT have fired (feature silently dead).
		if kA.GetCurrentEpoch(ctxA) != 1 {
			t.Fatalf("height %d: unexpected rekey to epoch %d (metric was supposed to panic)", h, kA.GetCurrentEpoch(ctxA))
		}
		// No fork.
		if dA, dB := dkgDigest(kA, ctxA), dkgDigest(kB, ctxB); dA != dB {
			t.Fatalf("FORK at height %d under overflow: A=%s B=%s", h, dA, dB)
		}
	}
	t.Log("CONFIRMED: overflow-magnitude stake => drift metric panics EVERY block, recovered (no halt/fork), " +
		"but the enabled stake-drift rekey NEVER fires (feature silently dead) + per-block panic-event spam.")
}

// TestC7_BB_StormGapZero_RateBoundedByFinalizeWindow (Q3): even with the dampener DISABLED
// (DkgMinRekeyGap=0) and drift always "due", the rekey rate is still floored by the round
// finalize latency (an Open round returns early), and round/key state stays O(1) — i.e. the
// worst-case storm is bounded even without the gap. Two nodes stay byte-identical.
func TestC7_BB_StormGapZero_RateBoundedByFinalizeWindow(t *testing.T) {
	const H = 120
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	memByOp := map[string]member{}
	for _, m := range mem {
		memByOp[m.op] = m
	}
	sk := &mockStaking{vals: []stakingtypes.Validator{
		bondedVal("op1", 100), bondedVal("op2", 100), bondedVal("op3", 100),
	}}
	mkP := func() types.Params {
		p := transparentParams(2, 3)
		p.DkgShareBudget = 32
		p.DkgDealWindow = 2
		p.DkgComplaintWindow = 2
		p.DkgRetryBackoff = 1
		p.DkgRekeyOnStakeDriftBps = 1 // any drift => due
		p.DkgMinRekeyGap = 0          // DAMPENER OFF — worst case
		return p
	}
	kA, ctxA := newKeeperSK(t, 1, sk)
	kB, ctxB := newKeeperSK(t, 1, sk)
	for _, k := range []struct {
		k keeper.Keeper
		c sdk.Context
	}{{kA, ctxA}, {kB, ctxB}} {
		if err := k.k.SetParams(k.c, mkP()); err != nil {
			t.Fatal(err)
		}
		for _, m := range mem {
			k.k.RecordEncPubKey(k.c, m.op, m.pub, encPoP(m))
		}
	}
	feed := func(h int) {
		cur := kA.GetCurrentEpoch(ctxA)
		if cur == 0 {
			return
		}
		r, ok := kA.GetDkgRound(ctxA, cur)
		if !ok || r.Status != types.DkgStatusOpen || uint64(h) > r.DealDeadline {
			return
		}
		var e []keeper.VEEntry
		for _, rm := range r.Members {
			e = append(e, buildDealingEntry(t, r, memByOp[rm.OperatorAddr]))
		}
		kA.ConsumeVoteExtensions(ctxA.WithBlockHeight(int64(h)), e)
		kB.ConsumeVoteExtensions(ctxB.WithBlockHeight(int64(h)), e)
	}
	rekeys := 0
	prev := uint64(0)
	for h := 1; h <= H; h++ {
		addOrSetVal(sk, "op1", 100+int64(h)*11) // continuous drift
		feed(h)
		bA := ctxA.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		bB := ctxB.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		kA.EndBlockDKG(bA)
		kB.EndBlockDKG(bB)
		if dA, dB := dkgDigest(kA, ctxA), dkgDigest(kB, ctxB); dA != dB {
			t.Fatalf("FORK at height %d: A=%s B=%s", h, dA, dB)
		}
		if ep := kA.GetCurrentEpoch(ctxA); ep != prev {
			rekeys++
			prev = ep
		}
		if r := kA.CountDkgRounds(ctxA); r > 5 {
			t.Fatalf("height %d: round state grew to %d (storm-unbounded)", h, r)
		}
		if kk := kA.CountActiveKeys(ctxA); kk > 4 {
			t.Fatalf("height %d: key state grew to %d (storm-unbounded)", h, kk)
		}
	}
	// Finalize window = deal(2)+complaint(2) => a rekey can occur at most ~1 per (window+1)=5 blocks
	// even with the gap OFF. Assert the rate is floored by that, not one-per-block.
	maxByFinalize := H/4 + 3
	if rekeys > maxByFinalize {
		t.Fatalf("gap=0 storm rekeyed %d times over %d heights — NOT floored by the finalize window (<=%d)", rekeys, H, maxByFinalize)
	}
	if rekeys < 3 {
		t.Fatalf("storm did not drive repeated re-genesis (%d) — test is vacuous", rekeys)
	}
	t.Logf("gap=0 storm: %d rekeys over %d heights (finalize window floors the rate to <=%d); state O(1); no fork.", rekeys, H, maxByFinalize)
}

// TestC7_BB_CadenceBelowFinalizeWindow drives the pathological config DkgMaxEpochBlocks <
// the finalize window with the dampener OFF: the committee re-genesises as fast as rounds can
// finalize. Proves it does NOT grow state without bound and there is ALWAYS a serving key
// (the superseded epoch keeps serving until the next finalizes), deterministically.
func TestC7_BB_CadenceBelowFinalizeWindow(t *testing.T) {
	const H = 120
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	memByOp := map[string]member{}
	for _, m := range mem {
		memByOp[m.op] = m
	}
	sk := &mockStaking{vals: []stakingtypes.Validator{
		bondedVal("op1", 100), bondedVal("op2", 100), bondedVal("op3", 100),
	}}
	p := transparentParams(2, 3)
	p.DkgShareBudget = 32
	p.DkgDealWindow = 3
	p.DkgComplaintWindow = 3 // finalize window ~6
	p.DkgMaxEpochBlocks = 1  // cadence FAR below the finalize window
	p.DkgMinRekeyGap = 0
	k, ctx := newKeeperSK(t, 1, sk)
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, m := range mem {
		k.RecordEncPubKey(ctx, m.op, m.pub, encPoP(m))
	}
	feed := func(h int) {
		cur := k.GetCurrentEpoch(ctx)
		if cur == 0 {
			return
		}
		r, ok := k.GetDkgRound(ctx, cur)
		if !ok || r.Status != types.DkgStatusOpen || uint64(h) > r.DealDeadline {
			return
		}
		var e []keeper.VEEntry
		for _, rm := range r.Members {
			e = append(e, buildDealingEntry(t, r, memByOp[rm.OperatorAddr]))
		}
		k.ConsumeVoteExtensions(ctx.WithBlockHeight(int64(h)), e)
	}
	everActive := false
	for h := 1; h <= H; h++ {
		feed(h)
		bctx := ctx.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		k.EndBlockDKG(bctx)
		if k.GetActiveEpoch(ctx) > 0 {
			everActive = true
			// Once a key has served, there must ALWAYS be a serving key from here on.
			if _, ok := k.GetActiveKey(ctx, k.GetActiveEpoch(ctx)); !ok {
				t.Fatalf("height %d: active epoch pointer with no key (serving gap)", h)
			}
		}
		if r := k.CountDkgRounds(ctx); r > 5 {
			t.Fatalf("height %d: cadence-storm grew round state to %d", h, r)
		}
		if kk := k.CountActiveKeys(ctx); kk > 4 {
			t.Fatalf("height %d: cadence-storm grew key state to %d", h, kk)
		}
	}
	if !everActive {
		t.Fatal("cadence-storm never installed a key — test vacuous")
	}
	t.Log("cadence < finalize window: continuous re-genesis stays O(1) state with a continuously-serving key.")
}

// TestC7_BB_LargeCommittee_WhaleDust_Deterministic (Q2): a LARGE committee (near the cap) with a
// whale + dust + near-1/3 distribution, driven through EndBlockDKG on TWO nodes whose staking
// iterator yields the SAME validators in DIFFERENT order, plus a stake storm. The cadence/bps
// drift decision and all DKG state must be byte-identical at every height (no fork).
func TestC7_BB_LargeCommittee_WhaleDust_Deterministic(t *testing.T) {
	const n = 20
	const H = 90
	mem := make([]member, n)
	forward := make([]stakingtypes.Validator, n)
	for i := 0; i < n; i++ {
		op := opName(i)
		mem[i] = newMember(op, "")
		var tok int64
		switch {
		case i == 0:
			tok = 1_000_000 // whale
		case i < 7:
			tok = 320_000 // ~near-1/3 as a bloc
		default:
			tok = 1 // dust
		}
		forward[i] = bondedVal(op, tok)
	}
	memByOp := map[string]member{}
	for _, m := range mem {
		memByOp[m.op] = m
	}
	// Node A sees forward order; node B sees reverse order (same content) — iterator-order independence.
	reverse := make([]stakingtypes.Validator, n)
	for i := range forward {
		reverse[n-1-i] = forward[i]
	}
	skA := &mockStaking{vals: append([]stakingtypes.Validator(nil), forward...)}
	skB := &mockStaking{vals: append([]stakingtypes.Validator(nil), reverse...)}

	mkP := func() types.Params {
		p := transparentParams(2, uint32(n))
		p.DkgShareBudget = budgetForN(n) // S >= 8n
		p.DkgDealWindow = 1
		p.DkgComplaintWindow = 1
		p.DkgRetryBackoff = 1
		p.DkgMaxEpochBlocks = 7         // cadence
		p.DkgRekeyOnStakeDriftBps = 250 // and a drift trigger
		p.DkgMinRekeyGap = 5
		return p
	}
	kA, ctxA := newKeeperSK(t, 1, skA)
	kB, ctxB := newKeeperSK(t, 1, skB)
	for _, kc := range []struct {
		k keeper.Keeper
		c sdk.Context
	}{{kA, ctxA}, {kB, ctxB}} {
		if err := kc.k.SetParams(kc.c, mkP()); err != nil {
			t.Fatal(err)
		}
		for _, m := range mem {
			kc.k.RecordEncPubKey(kc.c, m.op, m.pub, encPoP(m))
		}
	}
	feed := func(h int) {
		cur := kA.GetCurrentEpoch(ctxA)
		if cur == 0 {
			return
		}
		r, ok := kA.GetDkgRound(ctxA, cur)
		if !ok || r.Status != types.DkgStatusOpen || uint64(h) > r.DealDeadline {
			return
		}
		var e []keeper.VEEntry
		for _, rm := range r.Members {
			e = append(e, buildDealingEntry(t, r, memByOp[rm.OperatorAddr]))
		}
		kA.ConsumeVoteExtensions(ctxA.WithBlockHeight(int64(h)), e)
		kB.ConsumeVoteExtensions(ctxB.WithBlockHeight(int64(h)), e)
	}
	for h := 1; h <= H; h++ {
		// Storm the whale + a near-1/3 member up and down (drift), keeping the operator SET fixed.
		setBoth(skA, skB, opName(0), 1_000_000+int64(h*h)*97)
		setBoth(skA, skB, opName(3), 320_000+int64(h)*211)
		feed(h)
		bA := ctxA.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		bB := ctxB.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		kA.EndBlockDKG(bA)
		kB.EndBlockDKG(bB)
		if dA, dB := dkgDigest(kA, ctxA), dkgDigest(kB, ctxB); dA != dB {
			t.Fatalf("FORK at height %d (large whale/dust committee, reversed iterator):\n A=%s\n B=%s", h, dA, dB)
		}
	}
	t.Log("large whale+dust+near-1/3 committee, reversed staking-iterator on node B, cadence+drift storm: 0 divergence.")
}

// ---- helpers ----

func opName(i int) string {
	return "op" + string(rune('A'+i/26)) + string(rune('a'+i%26))
}
func budgetForN(n int) uint32 {
	b := 8 * n
	if b < 8*16 {
		b = 8 * 16 // >= default committee cap coupling
	}
	return uint32(b)
}
func reDelegateBig(sk *mockStaking, op string, tokens sdkmath.Int) {
	for i := range sk.vals {
		if sk.vals[i].OperatorAddress == op {
			sk.vals[i] = bondedValBig(op, tokens)
			return
		}
	}
}
func setBoth(a, b *mockStaking, op string, tok int64) {
	addOrSetVal(a, op, tok)
	addOrSetVal(b, op, tok)
}

// activeRoundFixtureSK mirrors activeRoundFixture but takes an explicit (possibly big-stake)
// staking mock, so the overflow probe can snapshot a >256-bit committee total.
func activeRoundFixtureSK(t *testing.T, sk *mockStaking, members []member, p types.Params) (keeper.Keeper, sdk.Context) {
	t.Helper()
	k, ctx := newKeeperSK(t, 1, sk)
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if !k.RecordEncPubKey(ctx, m.op, m.pub, encPoP(m)) {
			t.Fatalf("enc key registration failed for %s", m.op)
		}
	}
	snap := k.ActiveMembers(ctx, p)
	allocated := keeper.AllocateEvalPoints(snap, p.EffectiveShareBudget(), 1)
	round := types.DkgRound{
		Epoch: 1, OpenHeight: 1, DealDeadline: 3, ComplaintDeadline: 5,
		Members: allocated, MembersHash: keeper.MembersHash(snap), Status: types.DkgStatusActive, Attempt: 1,
	}
	if err := k.SetDkgRound(ctx, round); err != nil {
		t.Fatal(err)
	}
	k.SetCurrentEpoch(ctx, 1)
	k.SetActiveEpoch(ctx, 1)
	k.SetLastRekeyHeight(ctx, 1)
	return k, ctx
}
