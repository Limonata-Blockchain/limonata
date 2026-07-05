package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-8 AUDIT (COMPUTE/HALT lens) — the honest-throughput cost of the O(S) verify bound.
//
// The committed cycle-8 probes only ever measure the ATTACKER view of the per-(operator,epoch)
// verify budget ("a chaff spammer is pinned to its owned-point count"). This probe measures the
// SAME budget from the HONEST view: the committee serving REAL, DLEQ-valid shares for several
// in-flight ciphertexts of one epoch in one block. Because every honest operator serves oldest-
// first and the budget caps it at len(owned points) verifications per (operator,epoch) per block,
// the whole committee piles its entire budget onto the single OLDEST ciphertext, so only ONE
// ciphertext accrues shares per block — no matter how many are matured and being served, and no
// matter that the decrypt side (maxDecryptAttemptsPerBlock = 2048) would gladly drain far more.
// ============================================================================

// c8StoredAt returns how many decryption shares are stored for a specific ciphertext.
func c8StoredAt(c h3Committee, e types.EncTx) int {
	return len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq))
}

// TestC8Audit_HonestMultiCiphertextThroughput_ThrottledToOnePerBlock demonstrates that the
// per-(operator,epoch) verify budget throttles the HONEST committee to ~1 decryptable ciphertext
// per block per epoch, even though every operator submits complete valid share sets for all of
// them in the SAME block.
func TestC8Audit_HonestMultiCiphertextThroughput_ThrottledToOnePerBlock(t *testing.T) {
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

	// COMPUTE-BOUND SANITY (the fix's stated guarantee): total DLEQ verifications this block are
	// bounded by the O(S) ceiling. All served shares are valid, so verifications == shares stored.
	stored := []int{c8StoredAt(c, es[0]), c8StoredAt(c, es[1]), c8StoredAt(c, es[2])}
	shareCap := c.k.GetParams(c.ctx).VoteExtShareCap()
	if stored[0]+stored[1]+stored[2] > shareCap {
		t.Fatalf("verify bound violated: stored %v exceeds O(S) ceiling %d", stored, shareCap)
	}

	t.Logf("owned points/op = 8, per-(op,epoch) budget = 8, O(S) ceiling = %d, decrypt capacity/block = 2048", shareCap)
	t.Logf("stored shares after ONE block of the FULL committee serving 3 matured ciphertexts: ct1=%d ct2=%d ct3=%d (t=%d needed each)",
		stored[0], stored[1], stored[2], tThresh)

	// THE FINDING: the whole committee's budget went to the OLDEST ciphertext; the others starved.
	if stored[0] < tThresh {
		t.Fatalf("expected the oldest ciphertext to accrue >= t=%d shares, got %d", tThresh, stored[0])
	}
	decryptable := 0
	for _, s := range stored {
		if s >= tThresh {
			decryptable++
		}
	}
	if decryptable != 1 {
		t.Fatalf("THROUGHPUT FINDING NOT REPRODUCED: expected exactly 1 decryptable ciphertext/block, got %d (stored=%v)", decryptable, stored)
	}
	t.Logf("REPRODUCED: only %d of 3 fully-served matured ciphertexts reached t in one block — honest throughput is throttled to ~1/block/epoch by the per-(operator,epoch) budget, independent of the 2048/block decrypt capacity", decryptable)

	// The starved ciphertexts are DEFERRED (not chaff-rejected): no reject events fired for them.
	if rej := countEvents(ing, "encmempool_dkg_ve_share_rejected"); rej != 0 {
		t.Fatalf("no honest share should be chaff-rejected; got %d reject events", rej)
	}
}

// TestC8Audit_ComputeBound_HoldsUnderFullCommitteeFlood is the POSITIVE proof for the primary
// COMPUTE/HALT lens: even when EVERY committee member (not just one attacker) sprays a massive chaff
// flood across many ciphertexts in the SAME block, the total number of O(t) DLEQ verifications the
// block performs is bounded by Sigma(owned points) == S and never exceeds the O(S) ceiling — so the
// per-block verify work is provably attacker-independent (no halt-class escalation).
func TestC8Audit_ComputeBound_HoldsUnderFullCommitteeFlood(t *testing.T) {
	c := c7Committee(t)
	shareCap := c.k.GetParams(c.ctx).VoteExtShareCap() // 256
	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())

	var es []types.EncTx
	for i := 0; i < 20; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("flood"))
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1))
	}

	// All 4 members flood: 8 owned points * 20 ciphertexts * 15 repeats = 2400 chaff shares EACH,
	// 9600 across the committee — far above the O(S) ceiling. VerifyVoteExtension would clamp a real
	// 1-MiB extension, but we bypass it to prove the keeper's authoritative bound alone suffices.
	var entries []keeper.VEEntry
	for _, op := range []string{"attacker", "honest_A", "honest_B", "honest_C"} {
		entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: c8ChaffAcross(t, c, es, op, 15)}})
	}
	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(ing, entries)

	// All chaff => nothing stores => verifications == reject events.
	verifs := countEvents(ing, "encmempool_dkg_ve_share_rejected")
	sumOwned := 0
	for _, op := range []string{"attacker", "honest_A", "honest_B", "honest_C"} {
		sumOwned += len(c.memberPoints(op))
	}
	t.Logf("full-committee flood: 9600 chaff shares submitted -> %d DLEQ verifications (Sigma owned points = %d, O(S) ceiling = %d)", verifs, sumOwned, shareCap)
	if verifs > shareCap {
		t.Fatalf("HALT-CLASS REGRESSION: %d verifications exceed the O(S) ceiling %d", verifs, shareCap)
	}
	if verifs != sumOwned {
		t.Fatalf("expected verifications pinned to Sigma owned points (%d), got %d", sumOwned, verifs)
	}
	t.Logf("COMPUTE BOUND HOLDS: a 9600-share full-committee flood costs exactly %d verifications (== Sigma owned points), independent of flood magnitude — HIGH-A closed", verifs)
}

// TestC8Audit_DrainRateOnePerBlock shows the consequence over time: a backlog of C matured
// ciphertexts (one epoch) drains at ~1 ciphertext per block, so ciphertext #k is not decryptable
// until ~k blocks after maturity. With the 32-block StrandedDecryptGrace, a backlog that exceeds
// the drain rate for long enough pushes the youngest past grace and into a LOUD honest drop.
func TestC8Audit_DrainRateOnePerBlock(t *testing.T) {
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

	// Drive several blocks; each block the whole committee re-serves ALL still-in-flight ciphertexts
	// (idempotent; stored shares are skipped O(1)). Count how many reach t after each block.
	decryptableAfter := func() int {
		n := 0
		for _, e := range es {
			if len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)) >= tThresh {
				n++
			}
		}
		return n
	}

	for blk := int64(11); blk <= 14; blk++ {
		ing := base.WithBlockHeight(blk).WithEventManager(sdk.NewEventManager())
		var entries []keeper.VEEntry
		for _, op := range ops {
			var shares []types.VoteExtShare
			for i := range es {
				shares = append(shares, veSharesFor(t, c, base, es[i], cts[i], op)...)
			}
			entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: shares}})
		}
		c.k.ConsumeVoteExtensions(ing, entries)
		t.Logf("after block %d: %d/%d ciphertexts decryptable", blk, decryptableAfter(), C)
	}

	// After 4 blocks of the FULL committee serving all 5, at ~1/block only ~4 are decryptable.
	got := decryptableAfter()
	if got >= C {
		t.Fatalf("expected the drain to be throttled (< %d decryptable after 4 blocks), got %d — throttle not reproduced", C, got)
	}
	t.Logf("REPRODUCED: %d/%d ciphertexts decryptable after 4 blocks of the full committee serving all of them — the drain is ~1/block, NOT the 2048/block the decrypt side allows", got, C)
}
