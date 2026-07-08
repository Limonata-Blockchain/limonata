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
// CYCLE-5 item 2: StrandedDecryptGrace deferral — heal-within-grace, drop-at-
// grace-end (loud + H2-safe), and the bounded/fair deferral cap under a flood.
//
// These lock in the deferral contract that cycle 4 only proved in-process:
//   - a matured ciphertext short of t is DEFERRED (kept, ref-counts intact) and
//     HEALS if enough shares land within StrandedDecryptGraceBlocks;
//   - a permanent shortfall drops EXACTLY ONCE, LOUDLY (encmempool_decrypt_stranded)
//     through releaseEncTx, with the epoch ref-count released + epoch pruned (H2);
//   - the concurrently-deferred set is CAPPED at MaxDeferredDecryptsPerBlock so a
//     backlog flood can neither exceed the cap nor break the O(cap) bounded scan,
//     and the cap is fair-shared so an attacker cannot deny honest ciphertexts grace.
// ============================================================================

// TestDeferral_HealWithinGrace: a ciphertext that matures ONE share short is deferred
// (decrypt_missed, kept in state), then DECRYPTS the moment the late share lands inside
// the grace window — the healing property the deferral exists for.
func TestDeferral_HealWithinGrace(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2) // 3 keypers, need 2
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("heal me before the grace expires")
	ct, err := threshold.Encrypt(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	keypers := []string{"k1", "k2", "k3"}
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, enableParams(pub, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}
	e := k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 0) // matures at 12

	// Only ONE share by maturity (< t=2): must DEFER (missed), never decrypt, stay in state.
	ds0, _ := threshold.ComputeShare(shares[0], ct)
	_ = k.SetEncShare(ctx, types.EncShare{Keyper: keypers[0], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds0.Index, D: ds0.D})

	b12 := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if _, ok := decryptedLen(b12); ok {
		t.Fatal("must NOT decrypt with < t shares")
	}
	if !hasEvent(b12, "encmempool_decrypt_missed") {
		t.Fatal("short-at-maturity ciphertext must DEFER with encmempool_decrypt_missed")
	}
	if countEncTx(k, b12) != 1 || k.GetGlobalEncCount(b12) != 1 {
		t.Fatal("deferred ciphertext must stay in state with its ref-count intact")
	}

	// The late share lands well inside the grace window (block 20 < 12+32). Next BeginBlock heals.
	ds1, _ := threshold.ComputeShare(shares[1], ct)
	_ = k.SetEncShare(b12, types.EncShare{Keyper: keypers[1], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds1.Index, D: ds1.D})

	b20 := ctx.WithBlockHeight(20).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b20); err != nil {
		t.Fatal(err)
	}
	got, ok := decryptedLen(b20)
	if !ok {
		t.Fatal("HEAL FAILED: late share within grace must decrypt the deferred ciphertext")
	}
	if got != len(plain) {
		t.Fatalf("healed plaintext length mismatch: got %d want %d", got, len(plain))
	}
	if countEncTx(k, b20) != 0 || k.GetGlobalEncCount(b20) != 0 {
		t.Fatal("healed ciphertext must leave state with all ref-counts released")
	}
}

// TestDeferral_DropAtGraceEnd_H2Safe: a DKG-epoch ciphertext that NEVER heals is re-deferred
// every block through the grace window, its epoch ref-count intact the whole time, then drops
// EXACTLY ONCE at the grace boundary with a LOUD encmempool_decrypt_stranded event via
// releaseEncTx — releasing the epoch ref-count and pruning the (superseded, drained) epoch.
func TestDeferral_DropAtGraceEnd_H2Safe(t *testing.T) {
	const epoch = 7
	k, ctx := newKeeper(t, 10)
	// EncEnabled + DkgEnabled so decryptMatured runs; DecryptDelay=2 so submit@10 matures@12.
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DecryptDelay: 2,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// An active epoch key requiring 5 shares; we post ZERO, so recoverSharedSecret returns
	// errNotEnoughShares before any crypto — the deferral/strand path under test.
	if err := k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: epoch, Threshold: 5}); err != nil {
		t.Fatal(err)
	}
	e := k.SubmitEncTx(ctx, "user", 10, 2, make([]byte, 33), nil, []byte("x"), epoch) // matures@12
	if k.GetEpochEncCount(ctx, epoch) != 1 {
		t.Fatal("submit must pin the epoch ref-count")
	}

	matureH := int64(e.DecryptHeight) // 12
	expiry := matureH + keeper.StrandedDecryptGraceBlocks

	// Every block from maturity up to (but not including) the grace boundary: DEFER (missed),
	// keep in state, epoch ref-count stays pinned — NEVER stranded early.
	strandedCount := 0
	for h := matureH; h < expiry; h++ {
		bctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatal(err)
		}
		if !hasEvent(bctx, "encmempool_decrypt_missed") {
			t.Fatalf("block %d: within grace must DEFER (encmempool_decrypt_missed)", h)
		}
		if hasEvent(bctx, "encmempool_decrypt_stranded") {
			t.Fatalf("block %d: must NOT strand before the grace boundary", h)
		}
		if countEncTx(k, bctx) != 1 || k.GetEpochEncCount(bctx, epoch) != 1 {
			t.Fatalf("block %d: deferred ciphertext + epoch ref-count must stay intact", h)
		}
	}

	// At the grace boundary: drop EXACTLY ONCE, LOUDLY, and H2-safe (epoch ref-count released,
	// epoch record + active key pruned).
	bx := ctx.WithBlockHeight(expiry).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bx); err != nil {
		t.Fatal(err)
	}
	strandedCount += countEvents(bx, "encmempool_decrypt_stranded")
	if strandedCount != 1 {
		t.Fatalf("grace expiry must drop with exactly ONE encmempool_decrypt_stranded, got %d", strandedCount)
	}
	if hasEvent(bx, "encmempool_decrypt_missed") {
		t.Fatal("grace-expired ciphertext must NOT be re-deferred")
	}
	if countEncTx(k, bx) != 0 {
		t.Fatal("stranded ciphertext must leave state")
	}
	if k.GetEpochEncCount(bx, epoch) != 0 || k.GetGlobalEncCount(bx) != 0 {
		t.Fatal("H2: stranded drop must release the epoch + global ref-counts")
	}
	if _, ok := k.GetActiveKey(bx, epoch); ok {
		t.Fatal("H2: drained superseded epoch must be pruned (active key gone)")
	}

	// EXACTLY ONCE: another block must not re-emit a stranded event or touch state.
	b2 := ctx.WithBlockHeight(expiry + 1).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b2); err != nil {
		t.Fatal(err)
	}
	if hasEvent(b2, "encmempool_decrypt_stranded") {
		t.Fatal("stranded drop must happen exactly once (no repeat after the entry is gone)")
	}
}

// TestDeferral_CapBoundsBacklogBeyondScanWindow: a backlog LARGER than the O(cap) decrypt scan
// window must NOT break the bound — per block the deferred set stays <= MaxDeferredDecryptsPerBlock,
// the scan stays O(cap) (a truncation signal fires), every removal is loud (no silent loss), and
// the whole backlog drains to zero with no ref-count leak.
func TestDeferral_CapBoundsBacklogBeyondScanWindow(t *testing.T) {
	// A flood strictly larger than the bounded scan window (= 2 * the per-block decrypt cap), so
	// both the scan truncation AND the deferral cap are exercised together.
	flood := 2*keeper.MaxDecryptAttemptsPerBlock + 500
	k, ctx := newKeeper(t, 10)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, EncExecEnabled: true, Threshold: 1, DecryptDelay: 2, // legacy path; 0 shares => all short
		MaxInFlightEncTx: 0, MaxInFlightPerSubmitter: 0, // admission disabled: inject worst case
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	for i := 0; i < flood; i++ {
		k.SubmitEncTx(ctx, "attacker", 10, 2, a, nonce, []byte("x"), 0)
	}
	if countEncTx(k, ctx) != flood {
		t.Fatalf("want %d stored, got %d", flood, countEncTx(k, ctx))
	}

	// Drain, asserting the invariants every block until state is empty.
	sawTruncated := false
	drained := false
	for h := int64(12); h <= int64(12+keeper.StrandedDecryptGraceBlocks)+200; h++ {
		before := countEncTx(k, ctx)
		bctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatal(err)
		}
		if m := countEvents(bctx, "encmempool_decrypt_missed"); m > keeper.MaxDeferredDecryptsPerBlock {
			t.Fatalf("block %d: deferred %d exceeds the cap %d", h, m, keeper.MaxDeferredDecryptsPerBlock)
		}
		// BOUNDED O(cap) WORK: attempts (missed + capped + decrypted + failed) never exceed the
		// per-block decrypt cap, regardless of the huge backlog.
		attempts := countEvents(bctx, "encmempool_decrypt_missed") +
			countEvents(bctx, "encmempool_decrypt_deferral_capped") +
			countEvents(bctx, "encmempool_decrypted") +
			countEvents(bctx, "encmempool_decrypt_failed")
		if attempts > keeper.MaxDecryptAttemptsPerBlock {
			t.Fatalf("block %d: %d attempts exceed the O(cap) budget %d", h, attempts, keeper.MaxDecryptAttemptsPerBlock)
		}
		// NO SILENT LOSS: state removed == loud drops (decrypted + stranded + deferral_capped).
		removed := before - countEncTx(k, bctx)
		loud := countEvents(bctx, "encmempool_decrypted") +
			countEvents(bctx, "encmempool_decrypt_stranded") +
			countEvents(bctx, "encmempool_decrypt_deferral_capped")
		if removed != loud {
			t.Fatalf("block %d: removed %d but only %d loud drops (silent loss!)", h, removed, loud)
		}
		if countEvents(bctx, "encmempool_decrypt_deferred") > 0 {
			for _, ev := range bctx.EventManager().Events() {
				if ev.Type != "encmempool_decrypt_deferred" {
					continue
				}
				for _, at := range ev.Attributes {
					if at.Key == "scan_truncated" && at.Value == "true" {
						sawTruncated = true
					}
				}
			}
		}
		if countEncTx(k, bctx) == 0 {
			drained = true
			break
		}
	}
	if !sawTruncated {
		t.Fatal("a backlog beyond the scan window must signal scan_truncated=true (O(cap) scan)")
	}
	if !drained || countEncTx(k, ctx) != 0 {
		t.Fatalf("backlog did not fully drain: %d remain", countEncTx(k, ctx))
	}
	if g := k.GetGlobalEncCount(ctx); g != 0 {
		t.Fatalf("global in-flight counter leaked: %d", g)
	}
}
