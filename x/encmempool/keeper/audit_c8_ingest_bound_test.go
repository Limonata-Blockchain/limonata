// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-8 FIX VERIFICATION — the ingest DLEQ-verify work is HARD-BOUNDED.
//
// Cycle-7 moved dkg.VerifyDecryptShare (an O(t) elliptic-curve op) onto the PreBlock consensus
// path (ConsumeVoteExtensions -> IngestDecryptShareFromVE) with NO count cap, opening two DoS:
//   HIGH-A (halt-class): one member packs a 1-MiB extension with thousands of shares -> thousands
//     of O(t) verifications every block -> consensus stall.
//   HIGH-B (<=1/3-stake compute DoS): a REJECTED chaff share is never stored, so first-wins never
//     suppressed it and the identical chaff was re-verified from scratch every block.
//
// Cycle-8 (ingestDecryptSharesBounded) caps the block's total DLEQ verification regardless of attacker
// input, via: (0, cycle-9) a bounded oldest-first PROCESSED-ciphertext set that classifies out chaff
// aimed at non-processed/stranded/nonexistent ciphertexts; (1) per-VE share-count cap == VoteExtShareCap;
// (2) within-block eval-point dedup; (3, cycle-9) per-(operator,CIPHERTEXT) verify budget == the
// operator's owned eval-point count; (4) a global O(cap * S) ceiling. Together they bound block verify
// work to O(maxVerifyCiphertextsPerBlock * S). These probes drive each control and assert the bound holds
// WITHOUT weakening the cycle-7 drop-DoS fix (chaff still rejected, honest defers + heals) or fork-safety.
//
// MEASUREMENT: every share that reaches the O(t) DLEQ verify either STORES (verify passed) or emits
// exactly one encmempool_dkg_ve_share_rejected event (verify failed). A share dropped by the per-VE
// clamp, the within-block dedup, the per-operator budget, or the global ceiling does NEITHER. So the
// number of DLEQ verifications performed in a block == (stored delta) + (# rejected events). That is
// the quantity the attacker must not be able to inflate past O(S).
// ============================================================================

// c8Verifications returns the number of DLEQ verifications a single ConsumeVoteExtensions performed:
// (shares newly stored) + (chaff rejected). storedBefore is CollectShares' length before the consume.
func c8Verifications(t *testing.T, c h3Committee, ing sdk.Context, e types.EncTx, storedBefore int) int {
	t.Helper()
	storedAfter := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq))
	return (storedAfter - storedBefore) + countEvents(ing, "encmempool_dkg_ve_share_rejected")
}

// c8ChaffAcross builds structurally-authorized chaff at EVERY eval point `op` owns, for each
// ciphertext in `es`, repeated `repeats` times — the padding a Byzantine member sprays. D is a valid
// compressed point and the proof is the C=Z=0 zero proof (it PARSES, so each share drives the full
// O(t) SharePubKey + VerifyDecryptShare path before failing — the worst-case verify cost).
func c8ChaffAcross(t *testing.T, c h3Committee, es []types.EncTx, op string, repeats int) []types.VoteExtShare {
	t.Helper()
	var out []types.VoteExtShare
	for _, e := range es {
		for r := 0; r < repeats; r++ {
			for _, p := range c.memberPoints(op) {
				out = append(out, types.VoteExtShare{
					Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: p,
					D: randValidPoint(t), Proof: zeroProof64(),
				})
			}
		}
	}
	return out
}

// TestC8_PerOperatorCap_ExcessDroppedBeforeVerify: an operator submitting MANY MORE shares than the
// points it owns has the excess DROPPED before per-share verification. The attacker owns 8 points and
// sprays them ×20 (160 chaff shares) at ONE ciphertext; the within-block eval-point dedup collapses
// the 160 to its 8 distinct owned slots, so exactly 8 DLEQ verifications run (not 160), none store.
func TestC8_PerOperatorCap_ExcessDroppedBeforeVerify(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("attacker")) // 8
	ctx := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("per-op-cap"))
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1)

	const repeats = 20
	chaff := c8ChaffAcross(t, c, []types.EncTx{e}, "attacker", repeats) // 8*20 = 160 shares
	if len(chaff) != owned*repeats {
		t.Fatalf("precondition: expected %d chaff shares, built %d", owned*repeats, len(chaff))
	}

	ing := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "attacker", VE: types.VoteExtension{Shares: chaff}},
	})

	if v := c8Verifications(t, c, ing, e, 0); v != owned {
		t.Fatalf("per-operator cap: %d chaff shares must cost at most %d verifications (owned points), got %d", len(chaff), owned, v)
	}
	if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 0 {
		t.Fatalf("all chaff must be rejected — nothing stored; got %d", n)
	}
	t.Logf("CLOSED (per-op cap): %d submitted shares -> exactly %d DLEQ verifications (owned points), 0 stored", len(chaff), owned)
}

// TestC9_PerCiphertextBudget_ScalesWithRealCiphertextsNotRepeats: the CYCLE-9 granularity fix. The
// verify budget is per (operator, CIPHERTEXT) == owned points, so an operator serving N distinct real
// ciphertexts of an epoch may verify owned points FOR EACH — owned*N, not the cycle-8 owned-for-the-
// whole-epoch. That is the honest-liveness necessity (an honest member owes owned-points shares PER
// ciphertext). The bound stays hard: PADDING at a ciphertext (repeats of the same owned points) is
// deduped to owned, so verifications track the count of DISTINCT REAL ciphertexts — which control 0
// caps at maxVerifyCiphertextsPerBlock — NOT the raw chaff magnitude. Here the attacker sprays its 8
// owned points across 12 real ciphertexts; repeats do not inflate the cost past owned*12.
func TestC9_PerCiphertextBudget_ScalesWithRealCiphertextsNotRepeats(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("attacker")) // 8
	ctx := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	s := c.k.GetParams(c.ctx).EffectiveShareBudget() // 32

	const nct = 12
	var es []types.EncTx
	for i := 0; i < nct; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("multi-ct"))
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
	}

	// repeats 1 and 2 both stay under the per-VE cap (12*2*8=192 <= 256), so the ONLY variable is the
	// padding magnitude — which the within-block dedup collapses. Verifications must be owned*nct in BOTH.
	for _, repeats := range []int{1, 2} {
		branch, _ := ctx.CacheContext()
		ing := branch.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
		chaff := c8ChaffAcross(t, c, es, "attacker", repeats)
		c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
			{Operator: "attacker", VE: types.VoteExtension{Shares: chaff}},
		})
		rej := countEvents(ing, "encmempool_dkg_ve_share_rejected") // all chaff -> nothing stores
		if rej != owned*nct {
			t.Fatalf("per-(operator,ciphertext) budget: %d chaff shares across %d ciphertexts (repeats=%d) must cost exactly owned*nct=%d verifications, got %d", len(chaff), nct, repeats, owned*nct, rej)
		}
		// Attacker-scaling ceiling: never exceeds the O(cap * S) block bound regardless of ciphertext count.
		if rej > keeper.MaxVerifyCiphertextsPerBlock*s {
			t.Fatalf("O(cap*S) REGRESSION: %d verifications exceed cap*S=%d", rej, keeper.MaxVerifyCiphertextsPerBlock*s)
		}
	}
	t.Logf("CYCLE-9: %d real ciphertexts * %d owned points = %d verifications/block (per-ciphertext budget), invariant to padding repeats, bounded by cap*S=%d", nct, owned, owned*nct, keeper.MaxVerifyCiphertextsPerBlock*s)
}

// TestC9_ChaffSpammer_BoundedPerBlock_ByCapTimesS is the money probe for HIGH-A/HIGH-B under the
// cycle-9 per-ciphertext budget: the number of DLEQ verifications an attacker can force per block is
// bounded by owned_points * min(distinct real ciphertexts, maxVerifyCiphertextsPerBlock) and NEVER
// exceeds the global O(cap * S) ceiling — so it cannot scale with the raw chaff magnitude (repeats)
// and re-sending the same chaff every block cannot escalate. Unlike cycle-8 the cost DOES track the
// number of distinct real ciphertexts (that is the honest-liveness necessity), but that count is
// itself hard-capped by control 0, keeping the block work O(cap * S).
func TestC9_ChaffSpammer_BoundedPerBlock_ByCapTimesS(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("attacker"))
	s := c.k.GetParams(c.ctx).EffectiveShareBudget() // 32
	ceiling := keeper.MaxVerifyCiphertextsPerBlock * s
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())

	// A pool of 30 real ciphertexts so the attacker can fan out across many + repeat.
	var es []types.EncTx
	for i := 0; i < 30; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("spam"))
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
	}

	// (a) NO-CLAMP EXACT case: with repeats=1 every ciphertext's 8 owned points fit under the per-VE cap
	// (30*8=240 <= 256), so verifications are EXACTLY owned*floodCts — the per-ciphertext budget, proving
	// the honest-liveness scaling. (b) UPPER-BOUND case: whatever the flood magnitude (repeats), the cost
	// never exceeds owned*min(floodCts,cap) and never the O(cap*S) ceiling — proving attacker-boundedness.
	for _, floodCts := range []int{1, 5, 15, 30} {
		for _, repeats := range []int{1, 10, 40} {
			branch, _ := base.CacheContext()
			ing := branch.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
			chaff := c8ChaffAcross(t, c, es[:floodCts], "attacker", repeats)
			c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
				{Operator: "attacker", VE: types.VoteExtension{Shares: chaff}},
			})
			rej := countEvents(ing, "encmempool_dkg_ve_share_rejected")
			upper := owned * floodCts // floodCts <= 30 < cap, so min(floodCts,cap)=floodCts
			if rej > upper {
				t.Fatalf("per-ciphertext budget breach: %d chaff shares forced %d verifications > owned*floodCts=%d", len(chaff), rej, upper)
			}
			if rej > ceiling {
				t.Fatalf("O(cap*S) REGRESSION: %d chaff shares forced %d verifications > cap*S ceiling %d", len(chaff), rej, ceiling)
			}
			if repeats == 1 && rej != owned*floodCts {
				t.Fatalf("no-clamp per-ciphertext budget: expected exactly owned*floodCts=%d verifications, got %d", owned*floodCts, rej)
			}
		}
	}

	// HIGH-B: re-sending the SAME fat chaff every block cannot escalate — a FIXED per-block cost.
	chaff := c8ChaffAcross(t, c, es, "attacker", 1) // 30 cts * 8 pts = 240 distinct slots, re-sent verbatim
	var prev = -1
	for h := int64(12); h <= 17; h++ {
		branch, _ := base.CacheContext()
		ing := branch.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
			{Operator: "attacker", VE: types.VoteExtension{Shares: chaff}},
		})
		rej := countEvents(ing, "encmempool_dkg_ve_share_rejected")
		if rej > ceiling {
			t.Fatalf("HIGH-B REGRESSION @h%d: re-sent chaff exceeded cap*S ceiling %d, got %d", h, ceiling, rej)
		}
		if prev >= 0 && rej != prev {
			t.Fatalf("HIGH-B REGRESSION @h%d: re-sent chaff must cost a FIXED count/block, got %d then %d", h, prev, rej)
		}
		prev = rej
	}
	t.Logf("CLOSED (HIGH-A+B, cycle-9): attacker verifications bounded by owned*min(cts,cap)=<=%d and the O(cap*S) ceiling %d, fixed at %d/block when re-sent", owned*keeper.MaxVerifyCiphertextsPerBlock, ceiling, prev)
}

// TestC8_PerVECap_ClampsOversizedExtension drives control (1): a single extension carrying MORE than
// VoteExtShareCap shares is clamped (loud event) and the tail is dropped BEFORE any per-share work,
// so even a maximally-padded extension cannot exceed the bound.
func TestC8_PerVECap_ClampsOversizedExtension(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("attacker"))
	shareCap := c.k.GetParams(c.ctx).VoteExtShareCap() // 256
	ctx := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("per-ve-cap"))
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1)

	// Build MORE than shareCap chaff shares in ONE extension (8 owned points * 40 = 320 > 256).
	chaff := c8ChaffAcross(t, c, []types.EncTx{e}, "attacker", 40)
	if len(chaff) <= shareCap {
		t.Fatalf("precondition: need > shareCap(%d) shares to exercise the clamp, built %d", shareCap, len(chaff))
	}

	ing := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "attacker", VE: types.VoteExtension{Shares: chaff}},
	})
	if !hasEvent(ing, "encmempool_dkg_ve_shares_clamped") {
		t.Fatal("an extension with > VoteExtShareCap shares must emit encmempool_dkg_ve_shares_clamped")
	}
	if v := c8Verifications(t, c, ing, e, 0); v != owned {
		t.Fatalf("clamp + dedup + per-op budget must bound a %d-share extension to %d verifications, got %d", len(chaff), owned, v)
	}
	t.Logf("CLOSED (per-VE cap): a %d-share extension clamped to %d, then bounded to %d verifications", len(chaff), shareCap, owned)
}

// TestC8_BoundPreservesCycle7Fix_NoHonestStarve is the belt-and-suspenders regression: the cycle-8
// verify bound must NOT starve honest shares nor re-open the cycle-7 drop DoS. Honest A+B submit their
// 16 REAL shares through the SAME block as an attacker's 8 chaff; the bound must verify+store ALL 16
// honest (they are within each honest operator's own budget), reject the 8 chaff, DEFER the short
// ciphertext (not hard-drop), and then heal from a late honest_C share.
func TestC8_BoundPreservesCycle7Fix_NoHonestStarve(t *testing.T) {
	c := c7Committee(t)
	plain := []byte("bound must not starve honest shares")
	ctx := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1) // matures @12

	ing := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	// Attacker sorts FIRST (name-min) AND sprays a fat repeated flood; the bound must still let the
	// honest operators (sorted after) verify their full share sets — no global-budget monopoly.
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "attacker", VE: types.VoteExtension{Shares: c8ChaffAcross(t, c, []types.EncTx{e}, "attacker", 30)}},
		{Operator: "honest_A", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_A")}},
		{Operator: "honest_B", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_B")}},
	})

	stored := c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)
	if len(stored) != 16 {
		t.Fatalf("STARVE: the bound must still store all 16 honest shares despite an attacker-first flood, got %d", len(stored))
	}
	if rej := countEvents(ing, "encmempool_dkg_ve_share_rejected"); rej != len(c.memberPoints("attacker")) {
		t.Fatalf("expected exactly %d chaff rejections (attacker's owned points), got %d", len(c.memberPoints("attacker")), rej)
	}
	// Total block verifications = 16 honest + 8 chaff = 24, comfortably under the O(S) ceiling.
	if v := c8Verifications(t, c, ing, e, 0); v != 24 {
		t.Fatalf("expected 24 verifications (16 honest stored + 8 chaff rejected), got %d", v)
	}

	// The short (16 < t=18) ciphertext must DEFER, never hard-drop.
	b12 := c.ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if hasEvent(b12, "encmempool_decrypt_failed") {
		t.Fatal("cycle-7 REGRESSION: bounded chaff forced a HARD DROP instead of a grace defer")
	}
	if !hasEvent(b12, "encmempool_decrypt_missed") {
		t.Fatal("matured-but-short ciphertext must DEFER")
	}

	// HEAL: honest_C's late shares land within grace -> decrypts next block (the bound verifies them).
	heal := b12.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(heal, []keeper.VEEntry{
		{Operator: "honest_C", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_C")}},
	})
	if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 24 {
		t.Fatalf("after heal VE expected 24 verified shares (16+8), got %d", n)
	}
	b13 := c.ctx.WithBlockHeight(13).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b13); err != nil {
		t.Fatal(err)
	}
	if got, ok := decryptedLen(b13); !ok || got != len(plain) {
		t.Fatalf("late honest share within grace must HEAL+decrypt under the cycle-8 bound; ok=%v", ok)
	}
	t.Log("CLOSED: the cycle-8 verify bound stores all honest shares, rejects chaff, defers the short ciphertext, and heals — cycle-7 fix preserved")
}

// TestC8_Bound_OrderIndependent is the fork-safety probe: the bounded consume must be a PURE function
// of committed state + the canonical entries, so two nodes seeing the same VE entries in DIFFERENT
// orders (over identical committed state) write byte-identical stored share sets. We spray an
// attacker flood + honest shares and consume two orderings into two CacheContext branches.
func TestC8_Bound_OrderIndependent(t *testing.T) {
	c := c7Committee(t)
	base := c.ctx.WithBlockHeight(30).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("bound-order-independence"))
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(base, "user", 30, 2, ct.A, ct.Nonce, ct.Body, 1)

	byName := map[string]keeper.VEEntry{
		"attacker": {Operator: "attacker", VE: types.VoteExtension{Shares: c8ChaffAcross(t, c, []types.EncTx{e}, "attacker", 25)}},
		"honest_A": {Operator: "honest_A", VE: types.VoteExtension{Shares: veSharesFor(t, c, base, e, ct, "honest_A")}},
		"honest_B": {Operator: "honest_B", VE: types.VoteExtension{Shares: veSharesFor(t, c, base, e, ct, "honest_B")}},
	}
	order := func(names ...string) []keeper.VEEntry {
		out := make([]keeper.VEEntry, 0, len(names))
		for _, n := range names {
			out = append(out, byName[n])
		}
		return out
	}
	consumeOn := func(entries []keeper.VEEntry) []types.EncShare {
		branch, _ := base.CacheContext()
		c.k.ConsumeVoteExtensions(branch.WithBlockHeight(32).WithEventManager(sdk.NewEventManager()), entries)
		got := c.k.CollectShares(branch, e.DecryptHeight, e.Seq)
		sortShares(got)
		return got
	}

	a := consumeOn(order("attacker", "honest_A", "honest_B"))
	b := consumeOn(order("honest_B", "attacker", "honest_A"))
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("expected 16 verified shares each order under the bound, got %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Index != b[i].Index {
			t.Fatalf("FORK: bounded stored share set differs by input order at %d: idx %d vs %d", i, a[i].Index, b[i].Index)
		}
	}
	t.Log("bounded consume is order-independent: identical stored share set across two vote orderings (chaff rejected in both)")
}
