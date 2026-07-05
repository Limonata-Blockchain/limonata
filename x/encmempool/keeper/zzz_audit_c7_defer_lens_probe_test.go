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
// CYCLE-7 ADVERSARIAL RE-AUDIT — DEFER ROUTING + GRACE lens.
//
// The fix routes RecoverVerified's ErrInsufficientVerified into the SAME within-grace
// DEFER branch as a raw share shortfall (errNotEnoughShares). These probes attack the
// three claims that make that routing SAFE rather than a new hole:
//   (1) a matured ct that is DEFERRED via the insufficient-verified route but NEVER heals
//       must still DROP — LOUDLY (encmempool_decrypt_stranded), exactly at grace end, via
//       releaseEncTx (H2-safe: the epoch ref-count is released). i.e. no defer-forever /
//       no state leak.
//   (2) the routing must NOT MASK a genuinely-malformed ciphertext (valid shares recover a
//       secret but the body fails to open): that must still HARD-DROP (decrypt_failed) at
//       maturity, never be laundered into the heal grace.
//   (3) a FLOOD routed through the new ErrInsufficientVerified path must stay bounded by the
//       128 defer-cap, with the overflow dropped via releaseEncTx (H2-safe) — the cap the
//       new candidate source must not be able to overrun.
// ============================================================================

// injectChaffAtAttackerPoints pads the raw share count past t (marking the attacker present)
// with unverified garbage, injected DIRECTLY via SetEncShare to bypass the ingest DLEQ gate —
// modelling a share that reached state without ingest verification (legacy/declared/genesis
// door). RecoverVerified drops it, so verified < t while raw >= t: the exact input that fix #3
// routes to DEFER.
func injectChaffAtAttackerPoints(t *testing.T, c h3Committee, ctx sdk.Context, e types.EncTx) {
	t.Helper()
	for _, p := range c.memberPoints("attacker") {
		if err := c.k.SetEncShare(ctx, types.EncShare{
			Keyper: "attacker", DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: p,
			D: []byte("garbage-D-not-a-real-partial"), // non-empty; no valid proof
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAudit_C7_NeverHeals_DropsStrandedAtGraceEnd_H2Safe drives the case the existing fix probes
// do NOT: an insufficient-VERIFIED ciphertext that is deferred and then NEVER receives late honest
// shares. The routing must not turn "heal-eligible" into "defer forever": at grace end it must drop
// LOUDLY via releaseEncTx, releasing the epoch ref-count (H2). Not decrypt_failed (that would be the
// pre-fix mislabel); a distinct stranded event; and gone from state with the epoch ref-count at 0.
func TestAudit_C7_NeverHeals_DropsStrandedAtGraceEnd_H2Safe(t *testing.T) {
	c := c7Committee(t)
	plain := []byte("never heals -> must strand at grace end, not defer forever")

	ctx := c.ctx.WithBlockHeight(20).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 20, 2, ct.A, ct.Nonce, ct.Body, 1) // matures @22, grace end @ 22+32=54

	// 16 REAL verified honest points (A+B, < t=18) + 8 UNVERIFIED chaff at the attacker's own
	// points: raw count 24 >= t (count gate passes), attacker marked present (stake gate passes),
	// verified 16 < 18 -> RecoverVerified returns ErrInsufficientVerified -> fix #3 -> DEFER.
	if got := setValidShares(t, c, ctx, e, ct, "honest_A") + setValidShares(t, c, ctx, e, ct, "honest_B"); got != 16 {
		t.Fatalf("expected 16 honest verified points, got %d", got)
	}
	injectChaffAtAttackerPoints(t, c, ctx, e)
	if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 24 {
		t.Fatalf("precondition: raw count padded to 24, got %d", n)
	}
	if rc := c.k.GetEpochEncCount(c.ctx, 1); rc != 1 {
		t.Fatalf("precondition: epoch-1 in-flight ref-count should be 1, got %d", rc)
	}

	// Maturity + every block INSIDE the grace window: DEFER, never a hard drop, never dropped.
	for _, hgt := range []int64{22, 30, 40, 53} { // 53 = last block strictly inside grace (< 54)
		b := c.ctx.WithBlockHeight(hgt).WithEventManager(sdk.NewEventManager())
		if err := c.k.BeginBlock(b); err != nil {
			t.Fatal(err)
		}
		if hasEvent(b, "encmempool_decrypt_failed") {
			t.Fatalf("h%d: insufficient-verified must DEFER, never HARD-DROP (decrypt_failed)", hgt)
		}
		if hasEvent(b, "encmempool_decrypt_stranded") {
			t.Fatalf("h%d: stranded drop fired BEFORE grace end (grace end is h54)", hgt)
		}
		if !hasEvent(b, "encmempool_decrypt_missed") {
			t.Fatalf("h%d: matured-but-short ct must emit the DEFER signal (decrypt_missed)", hgt)
		}
		if _, ok := c.k.GetEncTx(c.ctx, e.DecryptHeight, e.Seq); !ok {
			t.Fatalf("h%d: deferred ct must stay in state within grace", hgt)
		}
		if rc := c.k.GetEpochEncCount(c.ctx, 1); rc != 1 {
			t.Fatalf("h%d: epoch ref-count must stay held (=1) while deferred, got %d", hgt, rc)
		}
	}

	// GRACE END (h54 = DecryptHeight+32): the never-healing ct drops LOUDLY + H2-safely.
	b54 := c.ctx.WithBlockHeight(54).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b54); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(b54, "encmempool_decrypt_stranded") {
		t.Fatal("at grace end a never-healing insufficient-verified ct MUST drop LOUDLY (encmempool_decrypt_stranded)")
	}
	if hasEvent(b54, "encmempool_decrypt_failed") {
		t.Fatal("grace-end drop must be labelled STRANDED (heal window elapsed), not decrypt_failed (malformed)")
	}
	if _, ok := c.k.GetEncTx(c.ctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("stranded ct must be REMOVED from state at grace end (no leak)")
	}
	if rc := c.k.GetEpochEncCount(c.ctx, 1); rc != 0 {
		t.Fatalf("H2 REGRESSION: grace-end stranded drop must release the epoch ref-count (0), got %d", rc)
	}
	if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 0 {
		t.Fatalf("stranded drop must delete the ct's shares too (no share leak), got %d", n)
	}
	t.Log("SAFE: insufficient-verified defer that never heals drops STRANDED at exactly grace end, via releaseEncTx (epoch ref-count 0) — no defer-forever, no leak")
}

// TestAudit_C7_MalformedBody_HardDropsNotMasked verifies fix #3 does NOT over-capture. A ciphertext
// with a VALID ephemeral A and a full set of VALID verified shares (so RecoverVerified SUCCEEDS and
// returns a shared secret) but a CORRUPTED body must fail the AEAD open and HARD-DROP at maturity
// (encmempool_decrypt_failed) — it must never be laundered into the heal grace, because no late
// honest share can ever fix a malformed body. ErrInsufficientVerified is a share-availability
// sentinel; a decrypt-open failure is a distinct terminal error and must stay terminal.
func TestAudit_C7_MalformedBody_HardDropsNotMasked(t *testing.T) {
	c := c7Committee(t)
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("this body will be corrupted before submit"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the body: the recovered shared secret is correct (shares are proved against the
	// UNCHANGED A), but the AES-GCM tag over the tampered body fails -> a genuine terminal fault.
	badBody := append([]byte(nil), ct.Body...)
	badBody[0] ^= 0xff

	ctx := c.ctx.WithBlockHeight(20).WithEventManager(sdk.NewEventManager())
	e := c.k.SubmitEncTx(ctx, "user", 20, 2, ct.A, ct.Nonce, badBody, 1) // matures @22

	// A+B+C = 24 REAL verified shares >= t=18: both gates pass and RecoverVerified SUCCEEDS.
	if got := setValidShares(t, c, ctx, e, ct, "honest_A") +
		setValidShares(t, c, ctx, e, ct, "honest_B") +
		setValidShares(t, c, ctx, e, ct, "honest_C"); got != 24 {
		t.Fatalf("expected 24 verified shares, got %d", got)
	}

	b22 := c.ctx.WithBlockHeight(22).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b22); err != nil {
		t.Fatal(err)
	}
	if _, ok := decryptedPlaintext(b22); ok {
		t.Fatal("a corrupted body must not decrypt")
	}
	if !hasEvent(b22, "encmempool_decrypt_failed") {
		t.Fatal("a malformed ct (recover OK, open FAILS) must HARD-DROP (encmempool_decrypt_failed)")
	}
	if hasEvent(b22, "encmempool_decrypt_missed") || hasEvent(b22, "encmempool_decrypt_stranded") {
		t.Fatal("MASK REGRESSION: a malformed ct was laundered into the heal grace instead of hard-dropping")
	}
	if _, ok := c.k.GetEncTx(c.ctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("a hard-dropped malformed ct must be removed at maturity, not held for grace")
	}
	if rc := c.k.GetEpochEncCount(c.ctx, 1); rc != 0 {
		t.Fatalf("H2: malformed-ct hard drop must release the epoch ref-count (0), got %d", rc)
	}
	t.Log("SAFE: fix #3 does not mask a malformed ct — corrupt body hard-drops (decrypt_failed) at maturity, never deferred")
}

// TestAudit_C7_InsufficientVerifiedFlood_DeferCapBounded stresses the 128 defer-cap through the NEW
// candidate source. A flood of >128 ciphertexts each padded to insufficient-verified (raw >= t,
// verified < t) is exactly what fix #3 routes into the defer branch. The concurrently-deferred set
// must stay bounded at 128; the overflow must drop NOW via releaseEncTx (encmempool_decrypt_
// deferral_capped), not silently accumulate — i.e. the new route cannot overrun the cap.
func TestAudit_C7_InsufficientVerifiedFlood_DeferCapBounded(t *testing.T) {
	c := c7Committee(t)
	const n = keeper.MaxDeferredDecryptsPerBlock + 40 // comfortably over the 128 cap

	ctx := c.ctx.WithBlockHeight(20).WithEventManager(sdk.NewEventManager())
	made := 0
	for i := 0; i < n; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte("flood"))
		if err != nil {
			t.Fatal(err)
		}
		// Distinct submitters so per-submitter fairness does not ration them before the cap; the
		// cap itself is what must bound the set.
		e := c.k.SubmitEncTx(ctx, submitterName(i), 20, 2, ct.A, ct.Nonce, ct.Body, 1) // all mature @22
		// 16 honest verified + 8 chaff => raw 24 >= t=18, verified 16 < 18 => ErrInsufficientVerified.
		_ = setValidShares(t, c, ctx, e, ct, "honest_A") + setValidShares(t, c, ctx, e, ct, "honest_B")
		injectChaffAtAttackerPoints(t, c, ctx, e)
		made++
	}
	if made != n {
		t.Fatalf("setup: expected %d cts, made %d", n, made)
	}

	b22 := c.ctx.WithBlockHeight(22).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b22); err != nil {
		t.Fatal(err)
	}

	// Count the concurrently-deferred set: cts still in state after the block.
	deferred := 0
	c.k.IterateInFlightFrom(c.ctx, 0, 1<<30, func(types.EncTx) bool { deferred++; return true })
	if deferred > keeper.MaxDeferredDecryptsPerBlock {
		t.Fatalf("DEFER-CAP OVERRUN via the insufficient-verified route: %d deferred > cap %d", deferred, keeper.MaxDeferredDecryptsPerBlock)
	}
	if deferred != keeper.MaxDeferredDecryptsPerBlock {
		t.Fatalf("expected exactly the cap (%d) deferred under a >cap flood, got %d", keeper.MaxDeferredDecryptsPerBlock, deferred)
	}
	capped := countEvents(b22, "encmempool_decrypt_deferral_capped")
	if capped != n-keeper.MaxDeferredDecryptsPerBlock {
		t.Fatalf("overflow must drop via deferral_capped: expected %d, got %d", n-keeper.MaxDeferredDecryptsPerBlock, capped)
	}
	if !hasEvent(b22, "encmempool_decrypt_missed") {
		t.Fatal("the granted 128 must emit the defer signal")
	}
	// H2: every capped drop released its epoch ref-count -> remaining ref-count == deferred set.
	if rc := c.k.GetEpochEncCount(c.ctx, 1); int(rc) != deferred {
		t.Fatalf("H2: epoch ref-count (%d) must equal the still-deferred set (%d) after capped drops", rc, deferred)
	}
	t.Logf("SAFE: insufficient-verified flood is bounded at the 128 defer-cap (%d deferred, %d capped-dropped via releaseEncTx)", deferred, capped)
}


func submitterName(i int) string {
	const alpha = "0123456789abcdefghijklmnopqrstuvwxyz"
	return "flooder-" + string([]byte{alpha[i/36], alpha[i%36]})
}
