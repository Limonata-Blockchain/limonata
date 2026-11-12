// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// HIGH-2 VARIANT regression suite: the member-change / ACTIVE-epoch door.
//
// Pre-fix, every successful rekey RETAINED its DkgRound record + ActiveThresholdKey
// forever (there was no DeleteActiveKey and successful epochs were never pruned), so a
// validator inducing member-change flaps could mint unbounded active-epoch state — the
// same unbounded-state DoS as HIGH-2 via a different path. These tests lock in the fix:
//   - prune-on-mature GC bounds retained active-epoch records to O(pending epochs);
//   - in-flight decryption is PRESERVED (a pinned epoch is never pruned early);
//   - a member-change FLAP is dampened but a settled change still rekeys promptly;
//   - the per-block decrypt cap DEFERS (carries) work rather than DROPPING it.
// ============================================================================

// TestOnChainDKG_ActiveEpochBoundedUnderRekeys is the primary HIGH-2 variant regression.
// It drives FIVE full successful rekeys (each finalizes a fresh active key) with NO
// in-flight ciphertexts, and asserts retained DkgRound + ActiveThresholdKey state stays
// O(1) instead of growing one record per rekey. Pre-fix (no prune / no DeleteActiveKey)
// the peaks would be 6 and 6 — this test would FAIL.
func TestOnChainDKG_ActiveEpochBoundedUnderRekeys(t *testing.T) {
	const thr = 2
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	all := []member{A, B, C, D}
	setA := []member{A, B, C}
	setB := []member{A, B, D}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0, // dampener OFF: isolate the GC path
		DkgMembers: declaredFrom(setA),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// epoch 1 (start): open @1 (DD=3, CD=5), deal @2, finalize @5.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(2), all, 1, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
	if k.GetActiveEpoch(ctx) != 1 {
		t.Fatalf("epoch 1 must be active, got %d", k.GetActiveEpoch(ctx))
	}

	maxRounds, maxKeys := 0, 0
	record := func() {
		if c := k.CountDkgRounds(ctx); c > maxRounds {
			maxRounds = c
		}
		if c := k.CountActiveKeys(ctx); c > maxKeys {
			maxKeys = c
		}
	}
	record()

	// Five successful member-change rekeys (epochs 2..6), each fully finalized.
	h := int64(6)
	for epoch := uint64(2); epoch <= 6; epoch++ {
		if epoch%2 == 0 {
			p.DkgMembers = declaredFrom(setB)
		} else {
			p.DkgMembers = declaredFrom(setA)
		}
		_ = k.SetParams(ctx, p)

		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())) // member_change opens `epoch`
		if k.GetCurrentEpoch(ctx) != epoch {
			t.Fatalf("member change must open epoch %d, got %d", epoch, k.GetCurrentEpoch(ctx))
		}
		record() // peak: {prev active, new open} = 2 rounds, {prev active} = 1 key
		dealAllMembers(t, k, ms, ctx.WithBlockHeight(h+1), all, epoch, thr)
		k.EndBlockDKG(ctx.WithBlockHeight(h + 4).WithEventManager(sdk.NewEventManager())) // finalize `epoch` + prune epoch-1
		if k.GetActiveEpoch(ctx) != epoch {
			t.Fatalf("epoch %d must be active after finalize, got %d", epoch, k.GetActiveEpoch(ctx))
		}
		record()
		h += 5
	}

	if k.GetCurrentEpoch(ctx) != 6 {
		t.Fatalf("expected 5 rekeys reaching epoch 6, got %d", k.GetCurrentEpoch(ctx))
	}
	if maxRounds > 2 {
		t.Fatalf("HIGH-2 variant: retained DkgRound records grew with rekeys (peak=%d over 6 epochs; want <= 2)", maxRounds)
	}
	if maxKeys > 1 {
		t.Fatalf("HIGH-2 variant: retained ActiveThresholdKey records grew with rekeys (peak=%d; want <= 1)", maxKeys)
	}
	// Steady state: exactly the serving epoch's round + key remain.
	if r, ak := k.CountDkgRounds(ctx), k.CountActiveKeys(ctx); r != 1 || ak != 1 {
		t.Fatalf("after rekeys: want 1 round + 1 key retained, got rounds=%d keys=%d", r, ak)
	}
	t.Logf("bounded: 5 rekeys, peak retained rounds=%d keys=%d", maxRounds, maxKeys)
}

// TestOnChainDKG_InFlightCiphertextSurvivesRekey is the in-flight-safety regression: a
// ciphertext stamped to epoch E must still decrypt after LATER rekeys, and E's DkgRound +
// ActiveThresholdKey must NOT be pruned while E is still referenced by an un-matured
// ciphertext — but MUST be reclaimed once that ciphertext matures.
func TestOnChainDKG_InFlightCiphertextSurvivesRekey(t *testing.T) {
	const thr = 2
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	all := []member{A, B, C, D}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: 100,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// epoch 1: open @1 (DD=3, CD=5), deal @2, finalize @5. Capture derived member shares.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	ak1, derived1 := dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, []member{A, B, C}, 1, thr)

	// Submit a ciphertext encrypted to epoch 1's key with a FAR decrypt height (106).
	plain := []byte("in-flight ciphertext must survive later rekeys and its key must not be GC'd early")
	ct, ctR, err := threshold.EncryptWithR(ak1.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ms.SubmitEncrypted(ctx.WithBlockHeight(6), &types.MsgSubmitEncrypted{
		Submitter: "acc1", A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
		Pok: dkg.ProveEncKeyPoK(ctR, ctx.ChainID(), "acc1", ct.A, ct.Nonce, ct.Body).Marshal(),
	})
	if err != nil {
		t.Fatalf("SubmitEncrypted: %v", err)
	}
	if resp.DecryptHeight != 106 {
		t.Fatalf("expected decrypt height 106, got %d", resp.DecryptHeight)
	}
	e, ok := k.GetEncTx(ctx, resp.DecryptHeight, resp.Seq)
	if !ok || e.Epoch != 1 {
		t.Fatalf("enc tx not stored with epoch 1: ok=%v epoch=%d", ok, e.Epoch)
	}

	// Rekey to epoch 2 (member change {A,B,C} -> {A,B,D}) and fully finalize it. This
	// SUPERSEDES epoch 1 and attempts to prune it — but epoch 1 is pinned by the in-flight
	// ciphertext, so it must be RETAINED.
	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(7).WithEventManager(sdk.NewEventManager())) // open epoch 2 (DD=9, CD=11)
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(8), all, 2, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())) // finalize epoch 2 -> supersede epoch 1
	if k.GetActiveEpoch(ctx) != 2 {
		t.Fatalf("epoch 2 must be active, got %d", k.GetActiveEpoch(ctx))
	}
	if _, ok := k.GetActiveKey(ctx, 1); !ok {
		t.Fatal("IN-FLIGHT SAFETY: epoch 1 ActiveThresholdKey was pruned early (a pending ciphertext still references it)")
	}
	if _, ok := k.GetDkgRound(ctx, 1); !ok {
		t.Fatal("IN-FLIGHT SAFETY: epoch 1 DkgRound was pruned early (still needed to authorize decryption shares)")
	}

	// Rekey again to epoch 3 (back to {A,B,C}) and finalize. epoch 2 has NO pending
	// ciphertexts, so it IS reclaimed; epoch 1 (pinned) is still retained.
	p.DkgMembers = declaredFrom([]member{A, B, C})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())) // open epoch 3 (DD=14, CD=16)
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(13), all, 3, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(16).WithEventManager(sdk.NewEventManager())) // finalize epoch 3 -> prune epoch 2
	if _, ok := k.GetActiveKey(ctx, 2); ok {
		t.Fatal("epoch 2 (superseded + drained) should have been pruned")
	}
	if _, ok := k.GetDkgRound(ctx, 2); ok {
		t.Fatal("epoch 2 DkgRound (superseded + drained) should have been pruned")
	}
	if _, ok := k.GetActiveKey(ctx, 1); !ok {
		t.Fatal("IN-FLIGHT SAFETY: epoch 1 key pruned while a ciphertext still pins it")
	}

	// Now decrypt the epoch-1 ciphertext: t epoch-1 members post DLEQ-proved shares and
	// BeginBlock at the decrypt height recovers it under the RETAINED epoch-1 key.
	round1, _ := k.GetDkgRound(ctx, 1)
	for _, rm := range round1.Members[:thr] {
		ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: rm.Index, Xi: derived1[rm.Index]}, ct)
		if err != nil {
			t.Fatalf("ProveDecryptShare: %v", err)
		}
		if _, err := ms.SubmitDecryptionShare(ctx.WithBlockHeight(106), &types.MsgSubmitDecryptionShare{
			Keyper: rm.AccountAddr, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: rm.Index,
			D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		}); err != nil {
			t.Fatalf("SubmitDecryptionShare(%s): %v", rm.AccountAddr, err)
		}
	}
	bctx := ctx.WithBlockHeight(106).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatal(err)
	}
	got, ok := decryptedLen(bctx)
	if !ok {
		t.Fatal("IN-FLIGHT SAFETY: ciphertext stamped to a superseded epoch failed to decrypt")
	}
	if got != len(plain) {
		t.Fatalf("decrypted plaintext mismatch:\n got %q\nwant %q", got, plain)
	}
	// Drained: epoch 1 is now reclaimed (matured ciphertext dropped its last ref).
	if _, ok := k.GetActiveKey(ctx, 1); ok {
		t.Fatal("epoch 1 key should be pruned once its last ciphertext matured")
	}
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("epoch 1 DkgRound should be pruned once its last ciphertext matured")
	}
}

// TestOnChainDKG_MemberChangeFlapDampened locks in the flap dampener: a rapid membership
// churn must NOT mint a fresh round every block (it is rate-limited to at most once per
// DkgMinRekeyGap), while a GENUINE settled change still rekeys on the very next block.
func TestOnChainDKG_MemberChangeFlapDampened(t *testing.T) {
	const gap = 10
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")

	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 1, DkgComplaintWindow: 1, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: 2, DkgMinRekeyGap: gap,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	markActive := func(epoch uint64) {
		r, ok := k.GetDkgRound(ctx, epoch)
		if !ok {
			t.Fatalf("epoch %d missing", epoch)
		}
		r.Status = types.DkgStatusActive
		_ = k.SetDkgRound(ctx, r)
	}

	k.EndBlockDKG(ctx.WithBlockHeight(1)) // open epoch 1
	markActive(1)

	// Flap the member set every block for 40 blocks. Each opened round is marked active
	// immediately so the round WINDOW does not mask the dampener — the rate-limit under
	// test is DkgMinRekeyGap alone.
	opens := 0
	prev := k.GetCurrentEpoch(ctx)
	for h := int64(2); h <= 41; h++ {
		if h%2 == 0 {
			p.DkgMembers = declaredFrom([]member{A, B, D})
		} else {
			p.DkgMembers = declaredFrom([]member{A, B, C})
		}
		_ = k.SetParams(ctx, p)
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
		if cur := k.GetCurrentEpoch(ctx); cur != prev {
			opens++
			prev = cur
			markActive(cur)
		}
	}
	if opens == 0 {
		t.Fatal("flap dampener starved ALL rekeys — a member change must still eventually rekey (liveness)")
	}
	if opens > 6 {
		t.Fatalf("flap NOT dampened: %d rekeys over 40 churn blocks with gap=%d (want ~4)", opens, gap)
	}
	t.Logf("dampened: %d rekeys over 40 churn blocks (gap=%d)", opens, gap)

	// SETTLED change: well past the gap, a single membership change must rekey promptly
	// (next block), i.e. it is NOT delayed by the dampener.
	last := k.GetLastRekeyHeight(ctx)
	p.DkgMembers = declaredFrom([]member{A, C, D}) // differs from both flap sets
	_ = k.SetParams(ctx, p)
	before := k.GetCurrentEpoch(ctx)
	settledH := int64(last + gap + 50)
	k.EndBlockDKG(ctx.WithBlockHeight(settledH).WithEventManager(sdk.NewEventManager()))
	if after := k.GetCurrentEpoch(ctx); after != before+1 {
		t.Fatalf("SETTLED change was delayed by the dampener: epoch %d -> %d (want prompt %d)", before, after, before+1)
	}
}

// TestDecryptFloodBoundedAndFair REPLACES the old TestDecryptCapDefersNotDrops. Its former
// invariant ("nothing is ever dropped; defer everything") was the self-inflicted HIGH: an
// unbounded DEFER lets a flooder grow EncTx state without bound and starve honest ciphertexts.
// The invariants under the cycle-3 H-B semantics (share-shortfall entries get a BOUNDED
// deferral grace before a LOUD stranded drop — never a silent loss, never an unbounded defer):
//   - ANTI-STARVATION FAIRNESS: honest ciphertexts submitted BEHIND a flood from another
//     submitter are ATTEMPTED on the very next block (round-robin fair-share), not stuck
//     behind the whole attacker backlog;
//   - BOUNDED per-block work: attempts per block never exceed maxDecryptAttemptsPerBlock, and
//     once the grace expires exactly the cap is stranded-dropped per block;
//   - BOUNDED deferral, non-silent: every share-less entry leaves state by
//     maturity + StrandedDecryptGraceBlocks with an encmempool_decrypt_stranded event, and
//     every counter returns to zero (no strand, no leak).
//
// Pre-fix (strict seq order), the honest ciphertexts (higher seqs, submitted after the flood)
// were deferred behind the entire 3000-entry attacker backlog and not even attempted on block 12.
func TestDecryptFloodBoundedAndFair(t *testing.T) {
	const flood = 3000 // > maxDecryptAttemptsPerBlock, < maxDecryptScanPerBlock (fits the fair window)
	const honestN = 5
	k, ctx := newKeeper(t, 10)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, EncExecEnabled: true, Threshold: 1, DecryptDelay: 2, // legacy path; 0 shares => decrypt_missed
		// Admission DISABLED so we can inject the flood directly (models the worst case the
		// drain path must survive); fairness lives entirely in decryptMatured, independent of it.
		MaxInFlightEncTx: 0, MaxInFlightPerSubmitter: 0,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	body := []byte("x")
	// Attacker floods first (LOWEST seqs), honest submits AFTER (highest seqs) — the adversarial
	// ordering that starves honest under strict seq processing.
	for i := 0; i < flood; i++ {
		k.SubmitEncTx(ctx, "attacker", 10, 2, a, nonce, body, 0)
	}
	honestSeq := make([]uint64, 0, honestN)
	for i := 0; i < honestN; i++ {
		e := k.SubmitEncTx(ctx, "honest", 10, 2, a, nonce, body, 0)
		honestSeq = append(honestSeq, e.Seq)
	}
	if got := countEncTx(k, ctx); got != flood+honestN {
		t.Fatalf("want %d stored, got %d", flood+honestN, got)
	}

	// Block 12: everything matures (with ZERO shares posted — all short of t). CYCLE-5 contract:
	//   (bounded)  at most MaxDeferredDecryptsPerBlock ciphertexts are DEFERRED (decrypt_missed);
	//              the rest of the attempted short ones are dropped LOUDLY (deferral_capped) so
	//              the deferred backlog can never grow past the cap and starve the scan / VE.
	//   (fair)     the defer slots are fair-shared across submitters, so an attacker flooding the
	//              LOW seqs (head of the window) cannot consume every heal slot — every honest
	//              ciphertext still gets a defer slot (a decrypt_missed).
	//   (bounded work) attempts (missed + capped) equal the per-block decrypt cap.
	b12 := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	missedSeqs := map[uint64]bool{}
	missed := 0
	for _, ev := range b12.EventManager().Events() {
		if ev.Type != "encmempool_decrypt_missed" {
			continue
		}
		missed++
		for _, a := range ev.Attributes {
			if a.Key == "seq" {
				var s uint64
				fmt.Sscanf(a.Value, "%d", &s)
				missedSeqs[s] = true
			}
		}
	}
	// FAIRNESS: every honest ciphertext must get a fair defer slot despite the attacker owning
	// the whole low-seq head of the window.
	for _, seq := range honestSeq {
		if !missedSeqs[seq] {
			t.Fatalf("UNFAIR: honest ciphertext seq %d denied a defer slot (attacker monopolized the heal grace)", seq)
		}
	}
	// BOUNDED deferred set: exactly the cap deferred, never more.
	if missed != keeper.MaxDeferredDecryptsPerBlock {
		t.Fatalf("deferred set must equal the cap %d, got %d", keeper.MaxDeferredDecryptsPerBlock, missed)
	}
	capped := countEvents(b12, "encmempool_decrypt_deferral_capped")
	// BOUNDED work: total attempts (deferred + capped-dropped) equal the per-block decrypt cap.
	if missed+capped != keeper.MaxDecryptAttemptsPerBlock {
		t.Fatalf("attempts (missed %d + capped %d) must equal the decrypt cap %d", missed, capped, keeper.MaxDecryptAttemptsPerBlock)
	}
	// The capped drops are LOUD and H2-safe: state fell by exactly the capped count, and the
	// global in-flight counter agrees with stored EncTx (no leak, no silent loss).
	remaining := countEncTx(k, b12)
	if remaining != flood+honestN-capped {
		t.Fatalf("state must fall by exactly the capped drops: want %d, got %d", flood+honestN-capped, remaining)
	}
	if uint64(remaining) != k.GetGlobalEncCount(b12) {
		t.Fatalf("global in-flight counter (%d) disagrees with stored EncTx (%d)", k.GetGlobalEncCount(b12), remaining)
	}
	if !hasEvent(b12, "encmempool_decrypt_deferred") {
		t.Fatal("expected a deferred event while the flood drains")
	}

	// Drain the remaining backlog block by block. INVARIANTS every block: the deferred set never
	// exceeds the cap, no ciphertext is ever silently lost (every state removal has a loud
	// event), and the grace expiry (block 12+grace) drops the never-healed remainder LOUDLY.
	expiry := int64(12 + keeper.StrandedDecryptGraceBlocks)
	sawStranded := false
	for h := int64(13); h <= expiry+4; h++ {
		before := countEncTx(k, ctx)
		bctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatal(err)
		}
		if m := countEvents(bctx, "encmempool_decrypt_missed"); m > keeper.MaxDeferredDecryptsPerBlock {
			t.Fatalf("block %d deferred %d > cap %d", h, m, keeper.MaxDeferredDecryptsPerBlock)
		}
		// No silent loss: state removed this block == the loud drops (decrypted + stranded +
		// deferral_capped). decrypt_missed does NOT remove state (the entry is kept).
		removed := before - countEncTx(k, bctx)
		loud := countEvents(bctx, "encmempool_decrypted") +
			countEvents(bctx, "encmempool_decrypt_stranded") +
			countEvents(bctx, "encmempool_decrypt_deferral_capped")
		if removed != loud {
			t.Fatalf("block %d removed %d ciphertexts but only %d loud drops (silent loss!)", h, removed, loud)
		}
		if countEvents(bctx, "encmempool_decrypt_stranded") > 0 {
			sawStranded = true
		}
		if countEncTx(k, bctx) == 0 {
			break
		}
	}
	if !sawStranded {
		t.Fatal("H-B REGRESSION: the never-healed remainder must drop with a LOUD encmempool_decrypt_stranded event")
	}
	if got := countEncTx(k, ctx); got != 0 {
		t.Fatalf("flood did not fully drain: %d remain", got)
	}
	if g := k.GetGlobalEncCount(ctx); g != 0 {
		t.Fatalf("global in-flight counter leaked: %d (want 0 after full drain)", g)
	}
}

// dealAndFinalizeCapturing has every member of an OPEN epoch deal on-chain, finalizes the
// round at finalH, and returns the installed active key plus each member's derived Shamir
// share X_m (= Σ_{i∈QUAL} f_i(m)) — needed to produce decryption shares for a ciphertext
// encrypted to that epoch's key.
func dealAndFinalizeCapturing(t *testing.T, k keeper.Keeper, ms types.MsgServer, ctx sdk.Context, dealH, finalH int64, members []member, epoch uint64, thr int) (types.ActiveThresholdKey, map[uint64]*secp256k1.ModNScalar) {
	t.Helper()
	round, ok := k.GetDkgRound(ctx, epoch)
	if !ok {
		t.Fatalf("epoch %d is not open", epoch)
	}
	idxByAcc := map[string]uint64{}
	allIdx := make([]uint64, 0, len(round.Members))
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
		allIdx = append(allIdx, rm.Index)
	}
	type pm struct {
		m   member
		idx uint64
	}
	present := make([]pm, 0, len(members))
	for _, m := range members {
		if idx, ok := idxByAcc[m.acc]; ok {
			present = append(present, pm{m, idx})
		}
	}

	dealCtx := ctx.WithBlockHeight(dealH)
	shareTo := map[uint64]map[uint64]*threshold.Ciphertext{} // [dealerIdx][recipIdx]
	for _, d := range present {
		commitments, shares, err := dkg.Deal(d.idx, allIdx, thr, rand.Reader)
		if err != nil {
			t.Fatalf("deal: %v", err)
		}
		shareTo[d.idx] = map[uint64]*threshold.Ciphertext{}
		encShares := make([]*types.DkgEncShare, 0, len(present))
		for _, r := range present {
			cs, err := dkg.EncryptShareTo(r.m.pub, shares[r.idx])
			if err != nil {
				t.Fatalf("encrypt share: %v", err)
			}
			shareTo[d.idx][r.idx] = cs
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: r.idx, A: cs.A, Nonce: cs.Nonce, Body: cs.Body})
		}
		if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{Dealer: d.m.acc, Epoch: epoch, Commitments: commitments, EncShares: encShares}); err != nil {
			t.Fatalf("DkgDeal(%s): %v", d.m.acc, err)
		}
	}

	k.EndBlockDKG(ctx.WithBlockHeight(finalH).WithEventManager(sdk.NewEventManager()))
	ak, ok := k.GetActiveKey(ctx, epoch)
	if !ok {
		t.Fatalf("epoch %d did not finalize to an active key", epoch)
	}

	derived := map[uint64]*secp256k1.ModNScalar{}
	for _, r := range present {
		X := new(secp256k1.ModNScalar)
		first := true
		for _, dealer := range ak.Qual {
			s, err := dkg.DecryptShareFrom(r.m.priv, r.idx, shareTo[dealer][r.idx])
			if err != nil {
				t.Fatalf("member %d derive share from dealer %d: %v", r.idx, dealer, err)
			}
			if first {
				X.Set(s)
				first = false
			} else {
				X.Add(s)
			}
		}
		derived[r.idx] = X
	}
	return ak, derived
}

func countEncTx(k keeper.Keeper, ctx sdk.Context) int {
	n := 0
	k.IterateEncTxUpTo(ctx, ^uint64(0)>>1, func(types.EncTx) { n++ })
	return n
}

func countEvents(ctx sdk.Context, typ string) int {
	n := 0
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type == typ {
			n++
		}
	}
	return n
}
