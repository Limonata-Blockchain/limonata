// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"strconv"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-6 ADVERSARIAL RE-AUDIT PROBES — LIVENESS + DEFER-CAP lens.
// These are throwaway probes (delete before commit). They drive the REAL
// BeginBlock decrypt path, same as the committed cycle-6 tests.
// ============================================================================

// floodParams: legacy path (epoch 0), admission OFF, decrypt delay 2.
func floodParams() types.Params {
	return types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, EncExecEnabled: true, Threshold: 2, // legacy path; 0 shares posted => errNotEnoughShares
		DecryptDelay: 2, MaxInFlightEncTx: 0, MaxInFlightPerSubmitter: 0,
	}
}

// countCapped / countMissed / seqCapped helpers over emitted events.
func seqSetOf(ctx sdk.Context, typ string) map[string]bool {
	out := map[string]bool{}
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type != typ {
			continue
		}
		for _, a := range ev.Attributes {
			if a.Key == "seq" {
				out[a.Value] = true
			}
		}
	}
	return out
}

// PROBE 1 — SYBIL DEFEATS THE DEFER-CAP FAIRNESS.
//
// The abci.go PASS-2 comment claims the per-submitter fair-share "stops an attacker who
// floods short spam ... from consuming every heal slot and denying grace to honest
// ciphertexts". This probe shows that claim FAILS against a Sybil attacker: >128 distinct
// submitter identities (each 1 short ciphertext, all submitted BEFORE the honest one so they
// hold the lower seqs) consume all 128 layer-0 round-robin slots, so the honest short
// ciphertext is DROPPED (encmempool_decrypt_deferral_capped + releaseEncTx) in the very block
// it matures — its 32-block heal grace denied. A control with the SAME ciphertext volume from
// a SINGLE attacker identity does NOT drop the honest one, proving the lever is Sybil identity
// count, not flood volume.
func TestProbe_SybilDefeatsDeferCapFairness(t *testing.T) {
	capN := keeper.MaxDeferredDecryptsPerBlock // 128
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)

	// ---- Sybil case: capN+72 = 200 distinct attacker identities, each 1 short ct ----
	nSybil := capN + 72
	kS, ctxS := newKeeper(t, 10)
	if err := kS.SetParams(ctxS, floodParams()); err != nil {
		t.Fatal(err)
	}
	// Attackers submit FIRST (lower seqs), each from a UNIQUE submitter address.
	for i := 0; i < nSybil; i++ {
		kS.SubmitEncTx(ctxS, "sybil-"+strconv.Itoa(i), 10, 2, a, nonce, []byte("x"), 0)
	}
	// Honest submitter, single ciphertext, submitted LAST (highest seq).
	honest := kS.SubmitEncTx(ctxS, "honest", 10, 2, a, nonce, []byte("x"), 0)
	honestSeq := strconv.FormatUint(honest.Seq, 10)

	b := ctxS.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := kS.BeginBlock(b); err != nil {
		t.Fatal(err)
	}
	missed := seqSetOf(b, "encmempool_decrypt_missed")
	capped := seqSetOf(b, "encmempool_decrypt_deferral_capped")

	t.Logf("SYBIL: identities=%d honestSeq=%s honest_granted_grace=%v honest_cap_dropped=%v",
		nSybil, honestSeq, missed[honestSeq], capped[honestSeq])
	if !capped[honestSeq] {
		t.Fatalf("EXPECTED the Sybil flood to cap-DROP the honest ciphertext (fairness defeated), "+
			"but honest seq %s was not in the capped set", honestSeq)
	}
	if missed[honestSeq] {
		t.Fatalf("honest seq %s was granted grace — Sybil did not defeat fairness", honestSeq)
	}
	// Confirm the honest ct actually left state this block (dropped, must resubmit).
	if _, ok := kS.GetEncTx(ctxS, honest.DecryptHeight, honest.Seq); ok {
		t.Fatalf("honest ct still in state; expected it dropped by deferral cap")
	}

	// ---- Control: SAME volume, but ONE attacker identity ----
	kC, ctxC := newKeeper(t, 10)
	if err := kC.SetParams(ctxC, floodParams()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nSybil; i++ {
		kC.SubmitEncTx(ctxC, "one-attacker", 10, 2, a, nonce, []byte("x"), 0)
	}
	honest2 := kC.SubmitEncTx(ctxC, "honest", 10, 2, a, nonce, []byte("x"), 0)
	honest2Seq := strconv.FormatUint(honest2.Seq, 10)
	bc := ctxC.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := kC.BeginBlock(bc); err != nil {
		t.Fatal(err)
	}
	missedC := seqSetOf(bc, "encmempool_decrypt_missed")
	cappedC := seqSetOf(bc, "encmempool_decrypt_deferral_capped")
	t.Logf("CONTROL: honest_granted_grace=%v honest_cap_dropped=%v", missedC[honest2Seq], cappedC[honest2Seq])
	if cappedC[honest2Seq] || !missedC[honest2Seq] {
		t.Fatalf("CONTROL broken: single-attacker flood should NOT drop honest (fairness protects it); "+
			"granted=%v dropped=%v", missedC[honest2Seq], cappedC[honest2Seq])
	}
	t.Logf("RESULT: fairness holds vs 1 identity but is DEFEATED by %d Sybil identities of equal volume", nSybil)
}

// PROBE 2 — release-exactly-once + H2 ref-count + no-silent-loss under a huge single-submitter
// flood (beyond the scan window). Instruments that stored-count == global counter at every step
// (no double/missed release) and that the epoch ref-count returns to 0 (H2), and records the
// instantaneous concurrently-deferred set size across blocks (bound observation).
func TestProbe_DeferCapInvariantsUnderHugeFlood(t *testing.T) {
	const epoch = 9
	k, ctx := newKeeper(t, 10)
	p := floodParams()
	p.DkgEnabled = true // exercise the epoch ref-count (H2) path
	p.Threshold = 0
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: epoch, Threshold: 5}); err != nil {
		t.Fatal(err)
	}
	const flood = 5000 // > maxDecryptScanPerBlock (4096)
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	for i := 0; i < flood; i++ {
		k.SubmitEncTx(ctx, "flooder", 10, 2, a, nonce, []byte("x"), epoch)
	}
	if int(k.GetGlobalEncCount(ctx)) != flood || countEncTx(k, ctx) != flood {
		t.Fatalf("setup: global=%d stored=%d want %d", k.GetGlobalEncCount(ctx), countEncTx(k, ctx), flood)
	}
	maxDeferredObserved := 0
	drained := false
	for h := int64(12); h <= int64(12+keeper.StrandedDecryptGraceBlocks)+40; h++ {
		before := countEncTx(k, ctx)
		b := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(b); err != nil {
			t.Fatal(err)
		}
		// invariant: stored count == global counter (no double-release => not <, no missed => not >)
		if g, s := int(k.GetGlobalEncCount(b)), countEncTx(k, b); g != s {
			t.Fatalf("block %d: global counter %d != stored %d (release accounting broken)", h, g, s)
		}
		missed := countEvents(b, "encmempool_decrypt_missed")
		capped := countEvents(b, "encmempool_decrypt_deferral_capped")
		stranded := countEvents(b, "encmempool_decrypt_stranded")
		// no silent loss: removed == loud terminal drops
		removed := before - countEncTx(k, b)
		if removed != capped+stranded {
			t.Fatalf("block %d: removed %d but loud drops (capped+stranded)=%d — silent loss", h, removed, capped+stranded)
		}
		if missed > maxDeferredObserved {
			maxDeferredObserved = missed
		}
		// bounded O(cap): the deferred (missed) set per block never exceeds the cap
		if missed > keeper.MaxDeferredDecryptsPerBlock {
			t.Fatalf("block %d: missed %d exceeds cap %d", h, missed, keeper.MaxDeferredDecryptsPerBlock)
		}
		if countEncTx(k, b) == 0 {
			drained = true
			t.Logf("drained at block %d; max per-block deferred(missed)=%d", h, maxDeferredObserved)
			break
		}
	}
	if !drained {
		t.Fatalf("flood did not drain; %d remain", countEncTx(k, ctx))
	}
	if g := k.GetGlobalEncCount(ctx); g != 0 {
		t.Fatalf("global counter leaked: %d", g)
	}
	if ec := k.GetEpochEncCount(ctx, epoch); ec != 0 {
		t.Fatalf("H2: epoch ref-count leaked: %d", ec)
	}
	if _, ok := k.GetActiveKey(ctx, epoch); ok {
		t.Fatal("H2: drained superseded epoch's active key must be pruned")
	}
}

// PROBE 3 — observe the INSTANTANEOUS concurrently-deferred set (stored matured-but-short
// entries) during the flood transient, to check the docstring claim that the cap "bounds the
// concurrently-deferred set" to 128. It records the count of stored ciphertexts still in the
// buildDecryptShares window [h-grace, h] each block. (Informational: measures whether the
// instantaneous deferred set can exceed 128.)
func TestProbe_ConcurrentlyDeferredSetSize(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	p := floodParams() // legacy epoch 0
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	const flood = 5000
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	for i := 0; i < flood; i++ {
		k.SubmitEncTx(ctx, "flooder", 10, 2, a, nonce, []byte("x"), 0)
	}
	maxStoredWithinGrace := 0
	for h := int64(12); h <= int64(12+keeper.StrandedDecryptGraceBlocks)+40; h++ {
		b := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(b); err != nil {
			t.Fatal(err)
		}
		// stored matured entries still inside the share-serving window [h-grace, h]
		from := uint64(0)
		if h > int64(keeper.StrandedDecryptGraceBlocks) {
			from = uint64(h) - keeper.StrandedDecryptGraceBlocks
		}
		within := 0
		k.IterateInFlightFrom(b, from, 1<<30, func(e types.EncTx) bool {
			if e.DecryptHeight <= uint64(h) {
				within++
			}
			return true
		})
		if within > maxStoredWithinGrace {
			maxStoredWithinGrace = within
		}
		if countEncTx(k, b) == 0 {
			break
		}
	}
	t.Logf("MAX stored matured-but-deferred entries inside the [h-grace,h] share-serving window = %d (cap claim = %d)",
		maxStoredWithinGrace, keeper.MaxDeferredDecryptsPerBlock)
}
