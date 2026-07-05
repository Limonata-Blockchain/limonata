package keeper_test

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// u64s formats a uint64 as a decimal string (matching the module's seq event attributes).
func u64s(v uint64) string { return strconv.FormatUint(v, 10) }

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ============================================================================
// CYCLE-6 (exhaustive re-audit) — item (a): the 128-entry deferral cap driven
// LIVE, i.e. through the real BeginBlock decrypt path, on paths cycle-5 could not
// exercise:
//
//   - the DKG-EPOCH (epoch > 0) path, so the H2 epoch ref-count release + the
//     superseded-epoch prune are proven under a >128 concurrent-shortfall flood
//     (the existing cap test — TestDeferral_CapBoundsBacklogBeyondScanWindow —
//     only exercises the LEGACY epoch-0 path, which has NO epoch ref-count);
//   - per-submitter FAIRNESS of the bounded defer slots under the flood (the
//     existing test floods from a single "attacker"), so a flooder provably
//     cannot monopolize the 128 grace slots and deny honest ciphertexts their
//     heal window;
//   - liveness-under-flood: an honest submitter's ciphertexts still DECRYPT while
//     an attacker sprays >128 concurrent shortfalls every block.
//
// These are the paths the mission calls out as "unit-tested only" — here they run
// through k.BeginBlock exactly as a live node's consensus BeginBlock does.
// ============================================================================

// attr returns an event attribute value by key.
func attr(ev sdk.Event, key string) (string, bool) {
	for _, a := range ev.Attributes {
		if a.Key == key {
			return a.Value, true
		}
	}
	return "", false
}

// eventSeqSet returns the set of "seq" attribute values across all events of a type.
func eventSeqSet(ctx sdk.Context, typ string) map[string]bool {
	out := map[string]bool{}
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type != typ {
			continue
		}
		if s, ok := attr(ev, "seq"); ok {
			out[s] = true
		}
	}
	return out
}

// TestCycle6_DeferralCap_DkgEpoch_H2SafeAndFairUnderFlood floods a single DKG epoch
// with far MORE than MaxDeferredDecryptsPerBlock matured-but-short ciphertexts, spread
// across several submitters, and drives the real BeginBlock decrypt path to grace expiry.
// It proves, LIVE on the DKG-epoch path:
//
//	(bounded)   per block: deferred (missed) <= cap, attempts <= the decrypt budget;
//	(fair)      the cap's grace slots are split EVENLY across submitters (round-robin),
//	            so no single flooder monopolizes the heal window;
//	(loud)      every state removal is a loud event (no silent loss);
//	(H2-safe)   every drop — deferral-cap shed AND grace-expiry strand — releases the
//	            epoch ref-count, and the superseded epoch is PRUNED once drained;
//	(no leak)   the global in-flight counter returns to zero.
func TestCycle6_DeferralCap_DkgEpoch_H2SafeAndFairUnderFlood(t *testing.T) {
	const epoch = 7
	// 4 submitters, each contributing the SAME count, chosen so the cap (128) splits
	// evenly across them (128 / 4 = 32) — a crisp per-submitter fairness assertion.
	submitters := []string{"flooderA", "flooderB", "flooderC", "flooderD"}
	const perSub = 100 // 400 total >> cap 128, and > cap even after the first drain
	capN := keeper.MaxDeferredDecryptsPerBlock
	if capN%len(submitters) != 0 {
		t.Fatalf("test presumes cap (%d) divisible by submitters (%d)", capN, len(submitters))
	}
	wantGracePerSub := capN / len(submitters)

	k, ctx := newKeeper(t, 10)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, DkgEnabled: true, DecryptDelay: 2, // submit@10 -> mature@12
		MaxInFlightEncTx: 0, MaxInFlightPerSubmitter: 0, // admission off: inject the worst case
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// A FINALIZED epoch key requiring 5 shares; we post ZERO, so recoverSharedSecret returns
	// errNotEnoughShares (the deferral trigger) for every ciphertext. The epoch is SUPERSEDED
	// (active/current epoch pointers are left at 0), so it is prune-eligible the instant its
	// last stamped ciphertext leaves state — the H2 property under test.
	if err := k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: epoch, Threshold: 5}); err != nil {
		t.Fatal(err)
	}

	seqOwner := map[string]string{} // seq -> submitter
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	// Interleave submissions so the (seq)-ordered scan sees all submitters early (the
	// round-robin's first-appearance order); the fair split holds regardless, but this
	// mirrors a realistic concurrent flood.
	for i := 0; i < perSub; i++ {
		for _, s := range submitters {
			e := k.SubmitEncTx(ctx, s, 10, 2, a, nonce, []byte("x"), epoch)
			seqOwner[u64s(e.Seq)] = s
		}
	}
	total := perSub * len(submitters)
	if countEncTx(k, ctx) != total || int(k.GetGlobalEncCount(ctx)) != total {
		t.Fatalf("want %d stored + counted, got %d / %d", total, countEncTx(k, ctx), k.GetGlobalEncCount(ctx))
	}
	if int(k.GetEpochEncCount(ctx, epoch)) != total {
		t.Fatalf("epoch ref-count must pin all %d in-flight ciphertexts, got %d", total, k.GetEpochEncCount(ctx, epoch))
	}

	firstBlock := true
	drained := false
	sawCapped := false
	for h := int64(12); h <= int64(12+keeper.StrandedDecryptGraceBlocks)+5; h++ {
		before := countEncTx(k, ctx)
		bctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatal(err)
		}

		missed := countEvents(bctx, "encmempool_decrypt_missed")
		capped := countEvents(bctx, "encmempool_decrypt_deferral_capped")
		stranded := countEvents(bctx, "encmempool_decrypt_stranded")
		decd := countEvents(bctx, "encmempool_decrypted")
		failed := countEvents(bctx, "encmempool_decrypt_failed")

		// BOUNDED: the concurrently-deferred set never exceeds the cap.
		if missed > capN {
			t.Fatalf("block %d: deferred %d exceeds cap %d", h, missed, capN)
		}
		// BOUNDED O(cap): total attempts stay within the per-block decrypt budget.
		if att := missed + capped + stranded + decd + failed; att > keeper.MaxDecryptAttemptsPerBlock {
			t.Fatalf("block %d: %d attempts exceed the O(cap) budget %d", h, att, keeper.MaxDecryptAttemptsPerBlock)
		}
		// NO SILENT LOSS: state removed == loud terminal drops this block.
		removed := before - countEncTx(k, bctx)
		if loud := decd + stranded + capped; removed != loud {
			t.Fatalf("block %d: removed %d but only %d loud drops (silent loss!)", h, removed, loud)
		}
		if decd != 0 || failed != 0 {
			t.Fatalf("block %d: no ciphertext can decrypt/hard-fail here (0 shares), got decd=%d failed=%d", h, decd, failed)
		}

		// The FIRST block sees the whole flood mature at once: exactly `cap` get grace,
		// split EVENLY across submitters, and the rest drop LOUDLY (deferral_capped).
		if firstBlock {
			firstBlock = false
			if missed != capN {
				t.Fatalf("first block must grant exactly cap=%d grace slots, got %d", capN, missed)
			}
			if capped != total-capN {
				t.Fatalf("first block must cap-drop exactly %d, got %d", total-capN, capped)
			}
			// Per-submitter fairness: the capped drops carry the submitter attribute; each
			// submitter must lose the SAME number (total/nSub - cap/nSub), i.e. the grace
			// slots are split evenly.
			perSubCapped := map[string]int{}
			for _, ev := range bctx.EventManager().Events() {
				if ev.Type != "encmempool_decrypt_deferral_capped" {
					continue
				}
				if s, ok := attr(ev, "submitter"); ok {
					perSubCapped[s]++
				}
			}
			wantCappedPerSub := perSub - wantGracePerSub
			for _, s := range submitters {
				if perSubCapped[s] != wantCappedPerSub {
					t.Fatalf("fairness broken: submitter %s cap-dropped %d, want %d (grace must split evenly)",
						s, perSubCapped[s], wantCappedPerSub)
				}
			}
			// And the grace (missed) seqs must come from ALL submitters, ~evenly.
			perSubGrace := map[string]int{}
			for s := range eventSeqSet(bctx, "encmempool_decrypt_missed") {
				perSubGrace[seqOwner[s]]++
			}
			for _, s := range submitters {
				if perSubGrace[s] != wantGracePerSub {
					t.Fatalf("fairness broken: submitter %s got %d grace slots, want %d", s, perSubGrace[s], wantGracePerSub)
				}
			}
		}
		if capped > 0 {
			sawCapped = true
		}

		if countEncTx(k, bctx) == 0 {
			// The final drain must be the loud grace-expiry strand of the last `cap` entries.
			if stranded == 0 {
				t.Fatalf("block %d: final drain must strand the grace-expired remainder", h)
			}
			drained = true
			break
		}
	}

	if !sawCapped {
		t.Fatal("a >128 concurrent flood must LOUDLY cap-drop (encmempool_decrypt_deferral_capped)")
	}
	if !drained {
		t.Fatalf("flood did not fully drain: %d remain", countEncTx(k, ctx))
	}
	// H2: the epoch ref-count is fully released and the SUPERSEDED epoch is pruned.
	if g := k.GetGlobalEncCount(ctx); g != 0 {
		t.Fatalf("global in-flight counter leaked: %d", g)
	}
	if ec := k.GetEpochEncCount(ctx, epoch); ec != 0 {
		t.Fatalf("H2: epoch ref-count leaked: %d", ec)
	}
	if _, ok := k.GetActiveKey(ctx, epoch); ok {
		t.Fatal("H2: drained superseded epoch must be pruned (active key gone)")
	}
}

// TestCycle6_DeferralCap_HonestHealsUnderAttackerFlood proves LIVENESS under the flood:
// while an attacker sprays FAR more than the cap of never-healing shortfalls every block,
// an honest submitter's handful of ciphertexts are (a) never starved into an immediate
// cap-drop — they always receive a grace slot (fairness) — and (b) actually DECRYPT the
// moment their shares land inside the grace window. Uses the legacy trusted-setup path so
// the honest heal is a cheap real threshold recover; the fair-share + cap logic under test
// is identical on both key paths.
func TestCycle6_DeferralCap_HonestHealsUnderAttackerFlood(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2) // 3 keypers, need 2
	if err != nil {
		t.Fatal(err)
	}
	keypers := []string{"k1", "k2", "k3"}
	k, ctx := newKeeper(t, 10)
	p := enableParams(pub, 2, 2, keypers) // legacy path, DecryptDelay=2
	p.MaxRevealWindow = 1_000_000
	p.MaxInFlightEncTx = 0
	p.MaxInFlightPerSubmitter = 0
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Honest submitter: 5 real ciphertexts (distinct plaintexts).
	type hon struct {
		seq   uint64
		plain []byte
		ct    *threshold.Ciphertext
	}
	honest := make([]hon, 5)
	for i := range honest {
		plain := []byte("honest-order-" + u64s(uint64(i)))
		ct, err := threshold.Encrypt(pub, plain)
		if err != nil {
			t.Fatal(err)
		}
		e := k.SubmitEncTx(ctx, "honest", 10, 2, ct.A, ct.Nonce, ct.Body, 0)
		honest[i] = hon{seq: e.Seq, plain: plain, ct: ct}
	}
	honestSeq := map[string]bool{}
	for _, h := range honest {
		honestSeq[u64s(h.seq)] = true
	}

	// Attacker flood: far more than the cap of never-decrypting shortfalls (0 shares posted).
	const flood = 2500
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	for i := 0; i < flood; i++ {
		k.SubmitEncTx(ctx, "attacker", 10, 2, a, nonce, []byte("x"), 0)
	}

	// Block 12 (maturity): the honest 5 are short (no shares yet) so they DEFER — and, under
	// fairness, every one of them must get a grace slot, NONE may be cap-dropped.
	b12 := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if countEvents(b12, "encmempool_decrypt_deferral_capped") == 0 {
		t.Fatal("precondition: the attacker flood must actually breach the cap this block")
	}
	missed12 := eventSeqSet(b12, "encmempool_decrypt_missed")
	capped12 := eventSeqSet(b12, "encmempool_decrypt_deferral_capped")
	for s := range honestSeq {
		if !missed12[s] {
			t.Fatalf("fairness/liveness broken: honest seq %s was not granted a grace slot under flood", s)
		}
		if capped12[s] {
			t.Fatalf("fairness broken: honest seq %s was cap-dropped by the attacker flood", s)
		}
	}

	// The honest keypers post their 2-of-3 shares for each honest ciphertext, well inside grace.
	for _, h := range honest {
		for _, ki := range []int{0, 2} {
			ds, err := threshold.ComputeShare(shares[ki], h.ct)
			if err != nil {
				t.Fatal(err)
			}
			if err := k.SetEncShare(b12, types.EncShare{
				Keyper: keypers[ki], DecryptHeight: 12, Seq: h.seq, Index: ds.Index, D: ds.D,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Next block (still deep inside grace): every honest ciphertext DECRYPTS despite the
	// attacker still flooding, and the exact plaintext comes back.
	b13 := ctx.WithBlockHeight(13).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b13); err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, ev := range b13.EventManager().Events() {
		if ev.Type != "encmempool_decrypted" {
			continue
		}
		seq, _ := attr(ev, "seq")
		ph, _ := attr(ev, "plaintext_hex")
		got[seq] = mustHex(t, ph)
	}
	for _, h := range honest {
		out, ok := got[u64s(h.seq)]
		if !ok {
			t.Fatalf("liveness-under-flood broken: honest ciphertext seq %d did not decrypt", h.seq)
		}
		if !bytes.Equal(out, h.plain) {
			t.Fatalf("honest seq %d decrypted to the wrong plaintext", h.seq)
		}
	}
	// The attacker's shortfalls never decrypt.
	for s := range got {
		if !honestSeq[s] {
			t.Fatalf("attacker seq %s must never decrypt (no shares)", s)
		}
	}
}
