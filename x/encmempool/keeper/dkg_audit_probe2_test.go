// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"math/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// TestProbe_DecryptPanicSafety fuzzes the BeginBlock decrypt path with structurally
// garbage ciphertexts (arbitrary-length A and body; nonce length is enforced at ingress)
// on the LEGACY path, plus junk decryption shares, and asserts BeginBlock never panics
// (a data-dependent halt of consensus). The per-ciphertext recover guard must contain
// every crypto panic and still GC the bad entry.
func TestProbe_DecryptPanicSafety(t *testing.T) {
	k, ctx := newKeeper(t, 5)
	// legacy path: EncEnabled + Threshold>0, no DKG. epoch 0 stamps (no ref-count).
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 100,
		EncEnabled: true, Threshold: 2, DecryptDelay: 1,
		Keypers: []string{"kp1", "kp2", "kp3"},
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	nonce := make([]byte, threshold.NonceSize)
	// submit a batch of garbage ciphertexts maturing at height 6
	for i := 0; i < 200; i++ {
		alen := rng.Intn(40) // 0..39 bytes: mostly NOT a valid 33-byte compressed point
		a := make([]byte, alen)
		rng.Read(a)
		body := make([]byte, rng.Intn(64))
		rng.Read(body)
		rng.Read(nonce)
		// bypass ingress validation by writing directly (models a genesis-imported or
		// otherwise permissive ciphertext) AND also exercise the ingress path for some.
		k.SubmitEncTx(ctx, "attacker", 5, 1, a, append([]byte(nil), nonce...), body, 0)
	}
	// also drop in some junk shares at the maturity height for random seqs
	for seq := uint64(0); seq < 200; seq += 3 {
		d := make([]byte, rng.Intn(40))
		rng.Read(d)
		_ = k.SetEncShare(ctx, types.EncShare{Keyper: "kp1", DecryptHeight: 6, Seq: seq, Index: 1, D: d})
		_ = k.SetEncShare(ctx, types.EncShare{Keyper: "kp2", DecryptHeight: 6, Seq: seq, Index: 2, D: d})
	}

	bctx := ctx.WithBlockHeight(6).WithEventManager(sdk.NewEventManager())
	// If any garbage ciphertext panics OUTSIDE the per-ct recover guard, this call
	// propagates the panic and fails the test (a real chain would HALT here).
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("BeginBlock returned error: %v", err)
	}
	// Ciphertexts that ATTEMPTED a recover (>= t junk shares present) fail hard and are
	// GC'd immediately; the rest are short of t and get the BOUNDED H-B deferral grace
	// (kept, loud) before their stranded drop. Bounded state still holds: everything must
	// be gone by maturity + StrandedDecryptGraceBlocks, with no halt at any height.
	bx := ctx.WithBlockHeight(6 + int64(keeper.StrandedDecryptGraceBlocks)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bx); err != nil {
		t.Fatalf("BeginBlock returned error at grace expiry: %v", err)
	}
	if n := countEncTx(k, bx); n != 0 {
		t.Fatalf("garbage ciphertexts not drained: %d remain", n)
	}
	t.Logf("PROBE OK: 200 garbage ciphertexts + junk shares processed with no halt")
}

// TestProbe_DeferBacklogRescans asserts a sub-ceiling flood SELF-HEALS with bounded
// per-block work: decryptMatured materializes at most maxDecryptScanPerBlock entries per
// block (O(cap), not O(backlog)) and attempts at maxDecryptAttemptsPerBlock/block. These
// share-less ciphertexts get the BOUNDED H-B deferral grace after maturity (kept + loud,
// never silently dropped), then stranded-drop at cap-rate — so the 5000-entry flood clears
// within a few blocks after the grace expires, and everything is gone (no strand, no leak).
func TestProbe_DeferBacklogRescans(t *testing.T) {
	const n = 5000 // > maxDecryptAttemptsPerBlock (2048) so >= 2 blocks of backlog
	k, ctx := newKeeper(t, 10)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 100,
		EncEnabled: true, Threshold: 1, DecryptDelay: 2,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	body := []byte("x")
	for i := 0; i < n; i++ {
		k.SubmitEncTx(ctx, "user", 10, 2, a, nonce, body, 0)
	}
	blocks := 0
	deadline := int64(12 + keeper.StrandedDecryptGraceBlocks + 4) // grace + ceil(5000/2048) blocks of stranded drops
	for h := int64(12); h <= deadline; h++ {
		bctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatal(err)
		}
		blocks++
		if countEncTx(k, bctx) == 0 {
			break
		}
	}
	if got := countEncTx(k, ctx); got != 0 {
		t.Fatalf("backlog did not drain: %d remain", got)
	}
	t.Logf("PROBE OK: %d ciphertexts deferred for the bounded grace then drained over %d blocks (cap=2048/block)", n, blocks)
}

// TestProbe_NeverFinalizingFlapBoundedRounds flaps the member set continuously with the
// dampener OFF (gap=0) while NO member ever deals — so every opened round eventually
// FAILS (sub-quorum) and is immediately superseded by the next member-change round. This
// is the pure orphan-round vector: the fix must GC each superseded Open/Failed round's
// record (purgeFailedRound) so DkgRound state stays O(1) instead of one record per churn.
func TestProbe_NeverFinalizingFlapBoundedRounds(t *testing.T) {
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 1, DkgComplaintWindow: 1, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: 2, DkgMinRekeyGap: 0, // dampener OFF
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	maxRounds, maxKeys := 0, 0
	for h := int64(1); h <= 120; h++ {
		switch {
		case h%2 == 0:
			p.DkgMembers = declaredFrom([]member{A, B, D})
		default:
			p.DkgMembers = declaredFrom([]member{A, B, C})
		}
		_ = k.SetParams(ctx, p)
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
		if c := k.CountDkgRounds(ctx); c > maxRounds {
			maxRounds = c
		}
		if c := k.CountActiveKeys(ctx); c > maxKeys {
			maxKeys = c
		}
	}
	if maxRounds > 2 {
		t.Fatalf("ORPHAN ROUNDS: DkgRound records grew under never-finalizing flap (peak=%d over 120 blocks; want <= 2)", maxRounds)
	}
	if maxKeys > 0 {
		t.Fatalf("no round ever finalized, so no ActiveThresholdKey should exist, got peak=%d", maxKeys)
	}
	t.Logf("PROBE OK: 120 churn blocks, peak retained rounds=%d keys=%d", maxRounds, maxKeys)
}

// TestProbe_ExtremeHeightNoOverflow drives the retry/flap paths at heights near uint64
// max to confirm the saturating arithmetic never wraps a deadline below the current
// height (which would jam the round machine) and no counter overflows.
func TestProbe_ExtremeHeightNoOverflow(t *testing.T) {
	A, B, C := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")
	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 9_000_000, DkgComplaintWindow: 9_000_000, DkgRetryBackoff: 9_000_000,
		DkgMaxAttempts: 8, DkgThreshold: 2, DkgMinRekeyGap: 9_000_000,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// open near the top of the uint64 range
	hi := int64(^uint64(0)>>1) - 100 // large positive int64
	k.EndBlockDKG(ctx.WithBlockHeight(hi).WithEventManager(sdk.NewEventManager()))
	r, ok := k.GetDkgRound(ctx, 1)
	if !ok {
		t.Fatal("round 1 not opened")
	}
	// saturating add must have clamped, not wrapped below the open height.
	if r.DealDeadline < uint64(hi) || r.ComplaintDeadline < r.DealDeadline {
		t.Fatalf("deadline wrapped: open=%d DD=%d CD=%d", hi, r.DealDeadline, r.ComplaintDeadline)
	}
	// step a few more blocks; must not panic and must not mint unbounded rounds.
	for d := int64(1); d <= 5; d++ {
		k.EndBlockDKG(ctx.WithBlockHeight(hi + d).WithEventManager(sdk.NewEventManager()))
	}
	if c := k.CountDkgRounds(ctx); c > 2 {
		t.Fatalf("unexpected round growth near uint64 max: %d", c)
	}
	t.Logf("PROBE OK: open=%d DD=%d CD=%d, rounds=%d (no wrap, no growth)", hi, r.DealDeadline, r.ComplaintDeadline, k.CountDkgRounds(ctx))
}
