// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// validCtA returns a valid compressed secp256k1 point for the ciphertext ephemeral A. The admission
// tests submit dummy ciphertexts and only exercise the rate/ceiling gates, but SubmitEncrypted now
// validates A (audit #1: reject invalid-A ciphertexts at ingress so they cannot strand + farm rekeys).
func validCtA() []byte {
	s := make([]byte, 32)
	s[31] = 7 // scalar 7 -> a valid public key 7*G
	return secp256k1.PrivKeyFromBytes(s).PubKey().SerializeCompressed()
}

// TestSubmitEncrypted_AdmissionCeilings locks in the INGRESS admission control that closes the
// unbounded-state HIGH: SubmitEncrypted REJECTS a ciphertext once the per-submitter OR the
// global in-flight ceiling is reached, so a flooder can never grow EncTx state without bound.
// Pre-fix SubmitEncrypted accepted every ciphertext (no ceiling), so this FAILS pre-fix.
func TestSubmitEncrypted_AdmissionCeilings(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, EncExecEnabled: true, Threshold: 1, DecryptDelay: 100, // long delay: nothing matures during the test
		MaxInFlightEncTx: 20, MaxInFlightPerSubmitter: 5,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	pub := throwawayThresholdPub(t)
	// Spread submits across successive block heights so the STANDING-inventory ceilings under test
	// (per-submitter, global) are exercised independently of the Fix-1 C3' per-BLOCK admission rate
	// limit (which resets each block; tested separately in TestSubmitEncrypted_PerBlockRate). Nothing
	// matures during the test (DecryptDelay 100), so inventory still accumulates across heights.
	// Each submit is a fresh real ciphertext + submitter-bound PoK (SubmitEncrypted requires it).
	height := int64(10)
	submit := func(sub string) error {
		height++
		_, err := ms.SubmitEncrypted(ctx.WithBlockHeight(height).WithEventManager(sdk.NewEventManager()),
			encWithPoK(t, pub, "x", sub))
		return err
	}

	// PER-SUBMITTER ceiling: s1 may submit exactly 5; the 6th is rejected.
	for i := 0; i < 5; i++ {
		if err := submit("s1"); err != nil {
			t.Fatalf("s1 submit %d rejected early: %v", i, err)
		}
	}
	if err := submit("s1"); err == nil {
		t.Fatal("per-submitter ceiling not enforced: 6th submit from s1 was accepted")
	}
	if g := k.GetSubmitterEncCount(ctx, "s1"); g != 5 {
		t.Fatalf("s1 in-flight should be pinned at 5, got %d", g)
	}

	// GLOBAL ceiling: fill to 20 across submitters, then any further submit (even from a fresh
	// submitter under its own per-submitter cap) is rejected.
	for _, s := range []string{"s2", "s3", "s4"} {
		for i := 0; i < 5; i++ {
			if err := submit(s); err != nil {
				t.Fatalf("%s submit %d rejected early: %v", s, i, err)
			}
		}
	}
	if g := k.GetGlobalEncCount(ctx); g != 20 {
		t.Fatalf("want global in-flight 20, got %d", g)
	}
	if err := submit("s5"); err == nil {
		t.Fatal("global ceiling not enforced: submit at 20 in-flight was accepted")
	}
	// State stays bounded AT the ceiling — the rejection did not store anything.
	if g := k.GetGlobalEncCount(ctx); g != 20 {
		t.Fatalf("global in-flight grew past the ceiling: %d", g)
	}
}

// TestSubmitEncrypted_PerBlockRate verifies the Fix-1 C3' per-SUBMITTER per-BLOCK admission rate limit:
// a submitter may admit at most maxEncSubmitsPerBlockPerSubmitter (4) ciphertexts in a single block; the
// next in the SAME block is rejected, and the allowance RESETS the next block. Being per-submitter (not a
// global slot) is exactly what prevents one address from monopolizing ingress / a proposer from censoring.
func TestSubmitEncrypted_PerBlockRate(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)
	if err := k.SetParams(ctx, types.Params{
		EncEnabled: true, EncExecEnabled: true, Threshold: 1, DecryptDelay: 100,
		MaxInFlightEncTx: 0, MaxInFlightPerSubmitter: 0, // isolate the RATE dimension
	}); err != nil {
		t.Fatal(err)
	}
	pub := throwawayThresholdPub(t)
	submitAt := func(sub string, h int64) error {
		_, err := ms.SubmitEncrypted(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()),
			encWithPoK(t, pub, "x", sub))
		return err
	}
	for i := 0; i < 4; i++ { // 4 accepted in block 100
		if err := submitAt("r1", 100); err != nil {
			t.Fatalf("r1 submit %d in block 100 rejected early: %v", i, err)
		}
	}
	if err := submitAt("r1", 100); err == nil { // the 5th in the same block is rejected
		t.Fatal("per-block rate limit not enforced: 5th submit from r1 in one block was accepted")
	}
	if err := submitAt("r1", 101); err != nil { // allowance resets next block
		t.Fatalf("per-block rate limit did not reset at the new block: %v", err)
	}
	if err := submitAt("r2", 100); err != nil { // PER-SUBMITTER: a different submitter is unaffected
		t.Fatalf("per-block rate limit leaked across submitters (r2 blocked in a block r1 saturated): %v", err)
	}
}

// TestCeilingDropReleasesEpochRefcount_HIGH2Safe drives the LAST-RESORT ceiling drop and
// verifies the CRITICAL HIGH-2 invariant: every drop goes through releaseEncTx, so it
// decEpochEncCount + maybePruneEpoch. A SUPERSEDED, drained DKG epoch must therefore be
// reclaimed even when its ciphertexts left state via a DROP (not a decrypt). If the drop path
// leaked the epoch ref-count, the epoch would never reach zero and never prune.
func TestCeilingDropReleasesEpochRefcount_HIGH2Safe(t *testing.T) {
	const ceiling = 50
	const n = 200 // >> ceiling, so the drop path MUST fire
	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DecryptDelay: 2,
		DkgThreshold: 1, MaxInFlightEncTx: ceiling, MaxInFlightPerSubmitter: 0,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Fabricate a SUPERSEDED epoch 1 (active epoch + current epoch are 2), so epoch 1 is
	// prunable the instant its in-flight ciphertexts drain.
	_ = k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: 1, Threshold: 1})
	_ = k.SetDkgRound(ctx, types.DkgRound{Epoch: 1, Status: types.DkgStatusActive})
	_ = k.SetDkgRound(ctx, types.DkgRound{Epoch: 2, Status: types.DkgStatusActive})
	k.SetActiveEpoch(ctx, 2)
	k.SetCurrentEpoch(ctx, 2)

	a := validCtA()
	nonce := make([]byte, threshold.NonceSize)
	body := []byte("x")
	for i := 0; i < n; i++ {
		k.SubmitEncTx(ctx, "attacker", 10, 2, a, nonce, body, 1) // stamped to superseded epoch 1
	}
	if got := k.GetEpochEncCount(ctx, 1); got != n {
		t.Fatalf("epoch-1 ref-count should be %d, got %d", n, got)
	}

	// Block 12: all mature. Global (200) > ceiling (50) => the drop path sheds the excess 150
	// IMMEDIATELY (the ceiling shed ignores the H-B deferral grace — flood pressure wins). The
	// remaining 50 share-less entries are DEFERRED (kept, loud) for the bounded grace.
	b12 := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(b12, "encmempool_enc_dropped_ceiling") {
		t.Fatal("expected the last-resort ceiling drop to fire (in-flight 200 >> ceiling 50)")
	}
	if got := countEncTx(k, b12); got != ceiling {
		t.Fatalf("ceiling shed must leave exactly the ceiling in state (H-B defers the rest): want %d, got %d", ceiling, got)
	}
	if got := k.GetEpochEncCount(ctx, 1); got != uint64(ceiling) {
		t.Fatalf("epoch-1 ref-count must track the 150 ceiling drops: want %d, got %d", ceiling, got)
	}

	// Grace expiry: the deferred 50 are stranded-dropped LOUDLY; the superseded epoch fully
	// drains and MUST be pruned via the drop paths' decEpochEncCount+maybePrune (HIGH-2).
	bx := ctx.WithBlockHeight(12 + int64(keeper.StrandedDecryptGraceBlocks)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bx); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(bx, "encmempool_decrypt_stranded") {
		t.Fatal("H-B: the deferred entries' final drop must be LOUD (encmempool_decrypt_stranded)")
	}
	if got := k.GetEpochEncCount(ctx, 1); got != 0 {
		t.Fatalf("HIGH-2 REGRESSION: drop path leaked epoch ref-count (epoch-1 count=%d, want 0)", got)
	}
	if _, ok := k.GetActiveKey(ctx, 1); ok {
		t.Fatal("HIGH-2 REGRESSION: superseded epoch 1 ActiveThresholdKey survived a drop-drain (ref-count leaked)")
	}
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("HIGH-2 REGRESSION: superseded epoch 1 DkgRound survived a drop-drain (ref-count leaked)")
	}
	if g := k.GetGlobalEncCount(bx); g != 0 {
		t.Fatalf("global in-flight should be 0 after full drop+drain, got %d", g)
	}
	if got := countEncTx(k, bx); got != 0 {
		t.Fatalf("state not bounded: %d EncTx remain after the ceiling drop + grace expiry", got)
	}
}

// TestCollectMaturedUpTo_BoundedWindow locks in the BOUNDED-SCAN primitive: the matured scan
// materializes at most `limit` entries and reports truncation, so per-block decrypt cost is
// O(cap), not O(backlog). Pre-fix decryptMatured used an UNBOUNDED IterateEncTxUpTo that read
// the whole backlog into a slice every block.
func TestCollectMaturedUpTo_BoundedWindow(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, types.Params{RevealDelay: 1, MaxRevealWindow: 1_000_000, EncEnabled: true, EncExecEnabled: true, Threshold: 1, DecryptDelay: 2}); err != nil {
		t.Fatal(err)
	}
	a := validCtA()
	nonce := make([]byte, threshold.NonceSize)
	for i := 0; i < 100; i++ {
		k.SubmitEncTx(ctx, "user", 10, 2, a, nonce, []byte("x"), 0) // all mature at height 12
	}
	got, truncated := k.CollectMaturedUpTo(ctx, 12, 30)
	if len(got) != 30 || !truncated {
		t.Fatalf("bounded scan broken: got %d entries truncated=%v (want 30, true)", len(got), truncated)
	}
	got, truncated = k.CollectMaturedUpTo(ctx, 12, 200)
	if len(got) != 100 || truncated {
		t.Fatalf("full scan broken: got %d entries truncated=%v (want 100, false)", len(got), truncated)
	}
}

// TestParamsValidate_DecryptDelayAndCeilings locks in the folded param bounds: DecryptDelay
// (which drives the key-retention window) is now bounded, and a per-submitter ceiling above the
// global ceiling is rejected. Pre-fix DecryptDelay was unvalidated.
func TestParamsValidate_DecryptDelayAndCeilings(t *testing.T) {
	gs := types.DefaultGenesisState()
	gs.Params.DecryptDelay = 10_000_001 // just over the bound
	if err := gs.Validate(); err == nil {
		t.Fatal("expected an out-of-bounds decrypt_delay to be rejected")
	}
	gs.Params.DecryptDelay = 100 // realistic
	if err := gs.Validate(); err != nil {
		t.Fatalf("realistic decrypt_delay rejected: %v", err)
	}

	gs2 := types.DefaultGenesisState()
	gs2.Params.MaxInFlightEncTx = 10
	gs2.Params.MaxInFlightPerSubmitter = 20 // per-submitter above global is meaningless
	if err := gs2.Validate(); err == nil {
		t.Fatal("expected max_in_flight_per_submitter > max_in_flight_enc_tx to be rejected")
	}
}
