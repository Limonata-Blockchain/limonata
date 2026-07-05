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
// CYCLE-9 FIX VERIFICATION (COMPUTE/HALT + honest-throughput lens).
//
// Cycle-8 keyed the ingest verify budget per (operator, EPOCH) at owned-points. That closed the
// compute-DoS but throttled the HONEST committee to ~1 decryptable ciphertext per block per epoch:
// a decryption share is per-CIPHERTEXT (D = x*A), so an honest member owes owned-points shares PER
// ciphertext, but the per-epoch budget only admitted owned-points TOTAL, piling the whole committee's
// budget onto the single oldest ciphertext and hard-dropping the rest past the 32-block grace.
//
// Cycle-9 re-keys the budget per (operator, CIPHERTEXT). These probes assert (a) honest liveness is
// RESTORED — every fully-served in-flight ciphertext of one epoch accrues its shares in ONE block, up
// to the bounded processed set — and (b) the compute bound still HOLDS: total block DLEQ verification
// is bounded by maxVerifyCiphertextsPerBlock * S regardless of attacker input.
// ============================================================================

// c8StoredAt returns how many decryption shares are stored for a specific ciphertext.
func c8StoredAt(c h3Committee, e types.EncTx) int {
	return len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq))
}

// TestC9_HonestMultiCiphertextThroughput_AllDecryptableInOneBlock is the cycle-9 liveness proof (the
// direct inverse of the cycle-8 regression): the full committee serves complete valid share sets for
// SEVERAL in-flight ciphertexts of one epoch in ONE block, and the per-(operator,ciphertext) budget
// lets EVERY one of them accrue >= t shares that block — not just the oldest.
func TestC9_HonestMultiCiphertextThroughput_AllDecryptableInOneBlock(t *testing.T) {
	c := c7Committee(t) // S=32, n=4, each owns 8 points, t=18
	tThresh := int(c.ak.Threshold)
	ops := []string{"attacker", "honest_A", "honest_B", "honest_C"} // canonical (operator-sorted) order

	// Three ciphertexts, SAME epoch, all matured at the same height. Plaintext distinct so a
	// successful decrypt is unambiguous.
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	plains := [][]byte{[]byte("ct1-oldest"), []byte("ct2"), []byte("ct3-youngest")}
	var es []types.EncTx
	var cts []*threshold.Ciphertext
	for _, pl := range plains {
		ct, err := threshold.Encrypt(c.ak.Pub, pl)
		if err != nil {
			t.Fatal(err)
		}
		e := c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1) // matures @12, seq ascending
		es = append(es, e)
		cts = append(cts, ct)
	}

	// Every operator serves REAL DLEQ-valid shares for ALL 3 ciphertexts, GROUPED oldest-first —
	// byte-for-byte the wire shape app.buildDecryptShares emits (iterate in-flight oldest-first,
	// inner loop over owned points). 4 ops * 3 cts * 8 points = 96 valid shares this block.
	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	var entries []keeper.VEEntry
	total := 0
	for _, op := range ops {
		var shares []types.VoteExtShare
		for i := range es {
			shares = append(shares, veSharesFor(t, c, base, es[i], cts[i], op)...)
		}
		entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: shares}})
		total += len(shares)
	}
	if total != 4*3*8 {
		t.Fatalf("precondition: expected 96 honest shares served, built %d", total)
	}

	c.k.ConsumeVoteExtensions(ing, entries)

	// COMPUTE-BOUND SANITY: all served shares are valid so verifications == shares stored; the block
	// must stay under the O(cap * S) ceiling.
	stored := []int{c8StoredAt(c, es[0]), c8StoredAt(c, es[1]), c8StoredAt(c, es[2])}
	s := c.k.GetParams(c.ctx).EffectiveShareBudget()
	ceiling := keeper.MaxVerifyCiphertextsPerBlock * s
	if stored[0]+stored[1]+stored[2] > ceiling {
		t.Fatalf("verify bound violated: stored %v exceeds O(cap*S) ceiling %d", stored, ceiling)
	}

	t.Logf("owned points/op = 8, per-(op,ciphertext) budget = 8, O(cap*S) ceiling = %d, decrypt capacity/block = 2048", ceiling)
	t.Logf("stored shares after ONE block of the FULL committee serving 3 matured ciphertexts: ct1=%d ct2=%d ct3=%d (t=%d needed each)",
		stored[0], stored[1], stored[2], tThresh)

	// THE FIX: ALL THREE ciphertexts accrued a full 32 shares (>= t) in the SAME block — no starve.
	decryptable := 0
	for i, sc := range stored {
		if sc != 4*8 {
			t.Fatalf("cycle-9 liveness: ciphertext %d must accrue all %d honest shares in one block, got %d", i, 4*8, sc)
		}
		if sc >= tThresh {
			decryptable++
		}
	}
	if decryptable != 3 {
		t.Fatalf("cycle-9 liveness REGRESSION: expected all 3 ciphertexts decryptable in one block, got %d (stored=%v)", decryptable, stored)
	}
	t.Logf("RESTORED: all %d fully-served matured ciphertexts reached t in ONE block — the per-(operator,ciphertext) budget no longer throttles honest throughput to ~1/block/epoch", decryptable)

	// No honest share was chaff-rejected.
	if rej := countEvents(ing, "encmempool_dkg_ve_share_rejected"); rej != 0 {
		t.Fatalf("no honest share should be chaff-rejected; got %d reject events", rej)
	}
}

// TestC9_ComputeBound_HoldsUnderFullCommitteeFlood is the POSITIVE proof for the COMPUTE/HALT lens
// under the cycle-9 per-ciphertext budget: even when EVERY committee member sprays a massive chaff
// flood across many ciphertexts in the SAME block, the total number of O(t) DLEQ verifications the
// block performs is bounded by maxVerifyCiphertextsPerBlock * S and never scales with the raw flood
// magnitude — so the per-block verify work is provably attacker-independent (no halt escalation).
func TestC9_ComputeBound_HoldsUnderFullCommitteeFlood(t *testing.T) {
	c := c7Committee(t)
	s := c.k.GetParams(c.ctx).EffectiveShareBudget() // 32
	ceiling := keeper.MaxVerifyCiphertextsPerBlock * s
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())

	var es []types.EncTx
	for i := 0; i < 20; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("flood"))
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
	}

	// (a) EXACT no-clamp full-committee flood: 5 ciphertexts, repeats=1. Each op serves 5*8=40 <= 256
	// (no per-VE clamp); per ciphertext all 4 ops' 8 points == S=32 verify, so the block does exactly
	// 5 * S = 160 verifications — the honest-liveness scaling, bounded by cap * S.
	exactIng := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	var exact []keeper.VEEntry
	for _, op := range []string{"attacker", "honest_A", "honest_B", "honest_C"} {
		exact = append(exact, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: c8ChaffAcross(t, c, es[:5], op, 1)}})
	}
	c.k.ConsumeVoteExtensions(exactIng, exact)
	if v := countEvents(exactIng, "encmempool_dkg_ve_share_rejected"); v != 5*s {
		t.Fatalf("no-clamp full-committee flood over 5 cts must cost exactly 5*S=%d verifications, got %d", 5*s, v)
	}

	// (b) MASSIVE flood: 8 owned points * 20 ciphertexts * 15 repeats = 2400 chaff shares EACH, 9600
	// across the committee — far above cap * S. VerifyVoteExtension would clamp a real 1-MiB extension,
	// but we bypass it to prove the keeper's authoritative bound alone suffices.
	var entries []keeper.VEEntry
	for _, op := range []string{"attacker", "honest_A", "honest_B", "honest_C"} {
		entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: c8ChaffAcross(t, c, es, op, 15)}})
	}
	ing := base.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(ing, entries)

	verifs := countEvents(ing, "encmempool_dkg_ve_share_rejected") // all chaff => verifications == rejects
	t.Logf("full-committee flood: 9600 chaff shares submitted -> %d DLEQ verifications (O(cap*S) ceiling = %d)", verifs, ceiling)
	if verifs > ceiling {
		t.Fatalf("HALT-CLASS REGRESSION: %d verifications exceed the O(cap*S) ceiling %d", verifs, ceiling)
	}
	t.Logf("COMPUTE BOUND HOLDS (cycle-9): a 9600-share full-committee flood costs %d verifications, bounded by cap*S=%d and independent of flood magnitude — HIGH-A closed", verifs, ceiling)
}

// TestC9_DrainRate_FullThroughput shows the consequence over time: a backlog of C matured ciphertexts
// (one epoch) fully served each block now accrues t shares for ALL of them in the FIRST block — the
// drain is bounded only by the decrypt budget (2048/block), not by a ~1-ct/block ingest throttle.
func TestC9_DrainRate_FullThroughput(t *testing.T) {
	c := c7Committee(t)
	tThresh := int(c.ak.Threshold)
	ops := []string{"attacker", "honest_A", "honest_B", "honest_C"}

	const C = 5
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	var es []types.EncTx
	var cts []*threshold.Ciphertext
	for i := 0; i < C; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 20, ct.A, ct.Nonce, ct.Body, 1)) // matures @30
		cts = append(cts, ct)
	}

	decryptableAfter := func() int {
		n := 0
		for _, e := range es {
			if len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)) >= tThresh {
				n++
			}
		}
		return n
	}

	// ONE block of the full committee serving all 5 ciphertexts makes ALL 5 decryptable.
	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	var entries []keeper.VEEntry
	for _, op := range ops {
		var shares []types.VoteExtShare
		for i := range es {
			shares = append(shares, veSharesFor(t, c, base, es[i], cts[i], op)...)
		}
		entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: shares}})
	}
	c.k.ConsumeVoteExtensions(ing, entries)

	if got := decryptableAfter(); got != C {
		t.Fatalf("cycle-9 full-throughput: expected all %d ciphertexts decryptable after ONE block, got %d", C, got)
	}
	t.Logf("RESTORED: %d/%d ciphertexts decryptable after ONE block of the full committee serving all of them — the ingest no longer throttles the drain to ~1/block", C, C)
}
