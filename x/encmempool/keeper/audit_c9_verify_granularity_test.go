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
// CYCLE-9 VERIFY-BUDGET GRANULARITY — dedicated probes.
//
// Cycle-8 keyed the ingest verify budget per (operator, EPOCH) at owned-points. That throttled an
// honest member serving MANY in-flight ciphertexts of one epoch to ONE ciphertext's worth of shares
// per block and hard-dropped the rest past the 32-block grace (a decryption share is per-CIPHERTEXT,
// so a member owes owned-points shares PER ciphertext). Cycle-9 re-keys the budget per (operator,
// CIPHERTEXT) at owned-points, bounds the number of DISTINCT budgeted ciphertexts to
// maxVerifyCiphertextsPerBlock via a cheap oldest-first PROCESSED set, and floors the block at an
// O(cap * S) ceiling. These probes assert all three required guarantees:
//   (i)   honest liveness restored: a member serving C-many in-flight cts of one epoch ingests ALL its
//         legitimate shares in one block, none throttled/dropped.
//   (ii)  compute-DoS still closed: a max-spray attacker cannot force > O(cap * S) verifications/block,
//         and CANNOT inflate work with chaff aimed at non-processed / nonexistent ciphertexts.
//   (iii) cycle-7 drop-DoS preserved: chaff is DLEQ-rejected (no count inflation), the short ciphertext
//         defers within grace and heals — now across MULTIPLE ciphertexts under the per-ciphertext budget.
// ============================================================================

// TestC9Probe_HonestManyCiphertextsOneEpoch_AllIngestOneBlock is guarantee (i): a SINGLE honest member
// serves complete valid share sets for C=30 in-flight ciphertexts of one epoch in ONE block; the per-
// (operator,ciphertext) budget ingests every one of its 30*8 = 240 legitimate shares — none throttled.
// Under cycle-8's per-(operator,epoch) budget only 8 (one ciphertext's worth) would have stored.
func TestC9Probe_HonestManyCiphertextsOneEpoch_AllIngestOneBlock(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("honest_A")) // 8
	const C = 30                             // 30*8 = 240 shares <= per-VE cap 256, and 30 <= cap(128)

	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	var es []types.EncTx
	var cts []*threshold.Ciphertext
	for i := 0; i < C; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
		cts = append(cts, ct)
	}

	// One honest member's ONE extension carries owned-points shares for ALL C ciphertexts, oldest-first.
	var shares []types.VoteExtShare
	for i := range es {
		shares = append(shares, veSharesFor(t, c, base, es[i], cts[i], "honest_A")...)
	}
	if len(shares) != C*owned {
		t.Fatalf("precondition: honest_A should serve %d shares (owned per ct), built %d", C*owned, len(shares))
	}

	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "honest_A", VE: types.VoteExtension{Shares: shares}},
	})

	// EVERY ciphertext must hold this member's full owned-points share set — nothing throttled/dropped.
	for i, e := range es {
		if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != owned {
			t.Fatalf("cycle-9 (i): ciphertext %d must ingest all %d of honest_A's shares in one block, got %d", i, owned, n)
		}
	}
	if rej := countEvents(ing, "encmempool_dkg_ve_share_rejected"); rej != 0 {
		t.Fatalf("no honest share should be rejected, got %d", rej)
	}
	if hasEvent(ing, "encmempool_dkg_ve_verify_bounded") {
		t.Fatal("cycle-9 (i): an honest member serving <= cap ciphertexts must NOT hit the global ceiling")
	}
	t.Logf("CYCLE-9 (i) RESTORED: honest_A's %d shares across %d ciphertexts ALL ingested in one block (cycle-8 would store only %d)", C*owned, C, owned)
}

// TestC9Probe_MaxSprayAttacker_CannotInflateWithNonProcessedChaff is guarantee (ii): a max-spray
// attacker's forced verifications are bounded by O(cap * S) AND cannot be inflated by chaff aimed at
// nonexistent / out-of-window ciphertexts — those are cheaply classified out BEFORE any verify budget.
func TestC9Probe_MaxSprayAttacker_CannotInflateWithNonProcessedChaff(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("attacker")) // 8
	s := c.k.GetParams(c.ctx).EffectiveShareBudget()
	ceiling := keeper.MaxVerifyCiphertextsPerBlock * s
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())

	// 10 real ciphertexts of the epoch (10*8 = 80 chaff slots, well under the per-VE cap 256 so the
	// clamp never confounds the ghost-inflation comparison).
	var es []types.EncTx
	for i := 0; i < 10; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("real"))
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
	}
	// The attacker's baseline flood: chaff at its owned points across the 10 real cts.
	realChaff := c8ChaffAcross(t, c, es, "attacker", 1) // 10*8 = 80 distinct slots

	consume := func(extra []types.VoteExtShare) int {
		branch, _ := base.CacheContext()
		ing := branch.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
		c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
			{Operator: "attacker", VE: types.VoteExtension{Shares: append(append([]types.VoteExtShare(nil), realChaff...), extra...)}},
		})
		return countEvents(ing, "encmempool_dkg_ve_share_rejected") // all chaff => verifications == rejects
	}

	baseVerifs := consume(nil)
	if baseVerifs != owned*len(es) {
		t.Fatalf("precondition: real-ct flood should cost owned*cts=%d verifications, got %d", owned*len(es), baseVerifs)
	}
	if baseVerifs > ceiling {
		t.Fatalf("O(cap*S) REGRESSION: %d verifications exceed cap*S ceiling %d", baseVerifs, ceiling)
	}

	// NONEXISTENT-ciphertext chaff: fabricate shares at (decryptHeight,seq) never submitted (10 ghost cts
	// * 8 = 80 shares; 80+80 = 160 < 256 so no clamp). They must be classified out BEFORE any
	// budget/verify, so they add ZERO verifications on top of the real flood.
	var ghost []types.VoteExtShare
	for seq := uint64(50000); seq < 50010; seq++ {
		ghost = append(ghost, c8ChaffAcross(t, c, []types.EncTx{{Epoch: 1, DecryptHeight: 12, Seq: seq}}, "attacker", 1)...)
	}
	withGhost := consume(ghost)
	if withGhost != baseVerifs {
		t.Fatalf("cycle-9 (ii): %d nonexistent-ciphertext chaff shares inflated verifications from %d to %d — cheap pre-classification breached", len(ghost), baseVerifs, withGhost)
	}
	t.Logf("CYCLE-9 (ii) HOLDS: attacker verifications = %d (<= cap*S=%d); +%d nonexistent-ct chaff shares added ZERO verifications — work is not attacker-inflatable", baseVerifs, ceiling, len(ghost))
}

// TestC9Probe_ProcessedSetCap_BeyondWindowChaffClassifiedOut is the direct guarantee (ii) mechanism
// test: with MORE than maxVerifyCiphertextsPerBlock real in-flight ciphertexts, chaff aimed at a
// ciphertext BEYOND the oldest-maxVerifyCiphertextsPerBlock processed window is dropped by the O(1)
// processed-set lookup — consuming NO verify budget — while chaff at an in-window ciphertext is verified.
func TestC9Probe_ProcessedSetCap_BeyondWindowChaffClassifiedOut(t *testing.T) {
	c := c7Committee(t)
	owned := len(c.memberPoints("attacker"))
	ctCap := keeper.MaxVerifyCiphertextsPerBlock // 128
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())

	// Submit ctCap+2 real ciphertexts, all same decrypt height, ascending seq => the oldest `ctCap` are
	// the processed window; the last two are BEYOND it.
	var es []types.EncTx
	for i := 0; i < ctCap+2; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("fill"))
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
	}

	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	// Chaff ONLY at the two beyond-window ciphertexts (es[ctCap], es[ctCap+1]) — real cts, attacker-owned
	// points, valid slots — but outside the oldest-ctCap processed set.
	beyond := c8ChaffAcross(t, c, []types.EncTx{es[ctCap], es[ctCap+1]}, "attacker", 1)
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "attacker", VE: types.VoteExtension{Shares: beyond}},
	})
	if rej := countEvents(ing, "encmempool_dkg_ve_share_rejected"); rej != 0 {
		t.Fatalf("cycle-9 (ii): chaff at ciphertexts beyond the oldest-%d window must consume 0 verify budget, got %d verifications", ctCap, rej)
	}

	// Control: chaff at an IN-window ciphertext (the oldest) IS verified (and rejected as chaff).
	ing2 := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	inWindow := c8ChaffAcross(t, c, []types.EncTx{es[0]}, "attacker", 1)
	c.k.ConsumeVoteExtensions(ing2, []keeper.VEEntry{
		{Operator: "attacker", VE: types.VoteExtension{Shares: inWindow}},
	})
	if rej := countEvents(ing2, "encmempool_dkg_ve_share_rejected"); rej != owned {
		t.Fatalf("control: chaff at an in-window ciphertext must be verified (%d), got %d", owned, rej)
	}
	t.Logf("CYCLE-9 (ii) MECHANISM: chaff at ciphertexts beyond the oldest-%d processed window cost 0 verifications; in-window chaff cost %d — the processed-set cap bounds distinct budgeted ciphertexts", ctCap, owned)
}

// TestC9Probe_DropDoSPreserved_MultiCiphertext_DefersAndHeals is guarantee (iii): the cycle-7 "chaff
// rejected -> defer -> heal" behaviour survives the per-ciphertext budget across MULTIPLE ciphertexts.
// TWO ciphertexts mature short (honest_A+honest_B = 16 < t=18 each) while the attacker sprays chaff at
// its own points on BOTH; every honest share stores, all chaff is rejected, BOTH defer (not drop), and
// BOTH heal from a late honest_C share within grace.
func TestC9Probe_DropDoSPreserved_MultiCiphertext_DefersAndHeals(t *testing.T) {
	c := c7Committee(t)
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	p1, p2 := []byte("multi-ct defer/heal #1"), []byte("multi-ct defer/heal #2")
	ct1, err := threshold.Encrypt(c.ak.Pub, p1)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := threshold.Encrypt(c.ak.Pub, p2)
	if err != nil {
		t.Fatal(err)
	}
	e1 := c.k.SubmitEncTx(base, "user", 10, 2, ct1.A, ct1.Nonce, ct1.Body, 1) // matures @12
	e2 := c.k.SubmitEncTx(base, "user", 10, 2, ct2.A, ct2.Nonce, ct2.Body, 1) // matures @12

	// Block 11: honest_A+honest_B serve real shares for BOTH cts; attacker sprays chaff at its points on BOTH.
	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	honest := func(op string) []types.VoteExtShare {
		return append(veSharesFor(t, c, base, e1, ct1, op), veSharesFor(t, c, base, e2, ct2, op)...)
	}
	attackerChaff := append(c8ChaffAcross(t, c, []types.EncTx{e1}, "attacker", 5), c8ChaffAcross(t, c, []types.EncTx{e2}, "attacker", 5)...)
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "attacker", VE: types.VoteExtension{Shares: attackerChaff}},
		{Operator: "honest_A", VE: types.VoteExtension{Shares: honest("honest_A")}},
		{Operator: "honest_B", VE: types.VoteExtension{Shares: honest("honest_B")}},
	})

	// Each ct holds exactly the 16 verified honest shares; the attacker's chaff (8 owned points/ct,
	// deduped over the 5 repeats) is rejected on BOTH cts => 16 reject events total, none stored.
	for _, e := range []types.EncTx{e1, e2} {
		if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 16 {
			t.Fatalf("cycle-9 (iii): each ct must store 16 verified honest shares (chaff rejected), got %d", n)
		}
	}
	if rej := countEvents(ing, "encmempool_dkg_ve_share_rejected"); rej != 2*len(c.memberPoints("attacker")) {
		t.Fatalf("cycle-9 (iii): expected %d chaff rejections (attacker owned points on 2 cts), got %d", 2*len(c.memberPoints("attacker")), rej)
	}

	// Block 12: BOTH mature short (16 < 18) => DEFER, never hard-drop.
	b12 := base.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if hasEvent(b12, "encmempool_decrypt_failed") {
		t.Fatal("cycle-7 REGRESSION: chaff forced a HARD DROP instead of a grace defer")
	}
	if n := countEvents(b12, "encmempool_decrypt_missed"); n != 2 {
		t.Fatalf("both matured-but-short ciphertexts must DEFER (2 missed events), got %d", n)
	}

	// Block 12 (heal): honest_C's late shares for BOTH land within grace => both decrypt next block.
	heal := base.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(heal, []keeper.VEEntry{
		{Operator: "honest_C", VE: types.VoteExtension{Shares: honest("honest_C")}},
	})
	for _, e := range []types.EncTx{e1, e2} {
		if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 24 {
			t.Fatalf("after heal each ct expected 24 verified shares (16+8 honest_C), got %d", n)
		}
	}
	b13 := base.WithBlockHeight(13).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b13); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(b13, "encmempool_decrypted"); n != 2 {
		t.Fatalf("cycle-9 (iii): both healed ciphertexts must decrypt (2 events), got %d", n)
	}
	t.Log("CYCLE-9 (iii) PRESERVED: across 2 ciphertexts the per-ciphertext budget stored all honest shares, rejected all chaff, deferred BOTH short cts, and healed BOTH within grace — cycle-7 drop-DoS fix intact")
}

// TestC9Probe_MultiCiphertextBound_OrderIndependent is the fork-safety probe for the new per-
// (operator,ciphertext) budget + processed set: over identical committed state, two nodes seeing the
// SAME vote entries in DIFFERENT orders must write byte-identical stored share sets for EVERY
// ciphertext. The processed set is a pure committed-state read and the budget maps iterate the
// canonical (operator-sorted) entries, so the outcome is order-independent across MULTIPLE ciphertexts.
func TestC9Probe_MultiCiphertextBound_OrderIndependent(t *testing.T) {
	c := c7Committee(t)
	base := c.ctx.WithBlockHeight(30).WithEventManager(sdk.NewEventManager())

	const C = 3
	var es []types.EncTx
	var cts []*threshold.Ciphertext
	for i := 0; i < C; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte{byte('x' + i)})
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 30, 2, ct.A, ct.Nonce, ct.Body, 1))
		cts = append(cts, ct)
	}

	honestAll := func(op string) []types.VoteExtShare {
		var out []types.VoteExtShare
		for i := range es {
			out = append(out, veSharesFor(t, c, base, es[i], cts[i], op)...)
		}
		return out
	}
	chaffAll := func(op string) []types.VoteExtShare { return c8ChaffAcross(t, c, es, op, 4) }
	byName := map[string]keeper.VEEntry{
		"attacker": {Operator: "attacker", VE: types.VoteExtension{Shares: chaffAll("attacker")}},
		"honest_A": {Operator: "honest_A", VE: types.VoteExtension{Shares: honestAll("honest_A")}},
		"honest_B": {Operator: "honest_B", VE: types.VoteExtension{Shares: honestAll("honest_B")}},
	}
	order := func(names ...string) []keeper.VEEntry {
		out := make([]keeper.VEEntry, 0, len(names))
		for _, n := range names {
			out = append(out, byName[n])
		}
		return out
	}
	consumeOn := func(entries []keeper.VEEntry) [][]types.EncShare {
		branch, _ := base.CacheContext()
		c.k.ConsumeVoteExtensions(branch.WithBlockHeight(31).WithEventManager(sdk.NewEventManager()), entries)
		out := make([][]types.EncShare, C)
		for i, e := range es {
			got := c.k.CollectShares(branch, e.DecryptHeight, e.Seq)
			sortShares(got)
			out[i] = got
		}
		return out
	}

	a := consumeOn(order("attacker", "honest_A", "honest_B"))
	b := consumeOn(order("honest_B", "attacker", "honest_A"))
	for i := 0; i < C; i++ {
		if len(a[i]) != 16 || len(b[i]) != 16 {
			t.Fatalf("ct %d: expected 16 verified honest shares each order, got %d and %d", i, len(a[i]), len(b[i]))
		}
		for j := range a[i] {
			if a[i][j].Index != b[i][j].Index {
				t.Fatalf("FORK: ct %d stored share set differs by input order at %d: idx %d vs %d", i, j, a[i][j].Index, b[i][j].Index)
			}
		}
	}
	t.Log("fork-safe: the per-(operator,ciphertext) bound is order-independent across multiple ciphertexts — identical stored sets under two vote orderings, chaff rejected in both")
}
