// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// DKG-GC-ACTIVE regression suite: dealings are LIVE state on the transparent path.
//
// Pre-fix, both rekey branches (member_change and stake_drift) called purgeDealings on the
// superseded-but-still-ACTIVE epoch unconditionally, on the pre-transparent assumption that
// "the old dealing bulk is dead weight once the round finalized".
//
// That assumption does not hold on the transparent path. A node persists NO Shamir share:
// evmd.deriveEpochShares re-derives the whole set from the COMMITTED DEALINGS on every block,
// and dkgnode.DeriveShares hard-fails on the first absent QUAL dealer. So purging the dealings
// of an epoch that is still the serving key makes EVERY node on the network unable to mint a
// decryption share for it, while SubmitEncrypted keeps stamping new ciphertexts onto that same
// epoch until the fresh round finalizes. Those ciphertexts are born undecryptable.
//
// The existing in-flight test (TestOnChainDKG_InFlightCiphertextSurvivesRekey) does NOT catch
// this: it captures the derived shares in Go memory before the rekey and replays them through
// the legacy MsgSubmitDecryptionShare path, so it never asks the chain to re-derive anything.
// These tests assert on the DEALINGS themselves, which is what the transparent path reads.
// ============================================================================

// countDealings returns how many dealings remain stored for an epoch.
func countDealings(k keeper.Keeper, ctx sdk.Context, epoch uint64) int {
	n := 0
	k.IterateDealings(ctx, epoch, func(types.Dealing) { n++ })
	return n
}

// TestOnChainDKG_DealingsRetainedWhileCiphertextInFlight locks in the fix: a member-change
// rekey must NOT shed the superseded epoch's dealings while an un-matured ciphertext is still
// stamped to it, and MUST reclaim them once that ciphertext drains.
func TestOnChainDKG_DealingsRetainedWhileCiphertextInFlight(t *testing.T) {
	const thr = 2
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	all := []member{A, B, C, D}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: 100,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0, DkgRetainActiveDealings: true,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// epoch 1: open @1 (DD=3, CD=5), deal @2, finalize @5.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	ak1, derived1 := dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, []member{A, B, C}, 1, thr)

	dealt := countDealings(k, ctx, 1)
	if dealt == 0 {
		t.Fatal("setup: epoch 1 stored no dealings")
	}

	// Put a ciphertext in flight against epoch 1, with a far decrypt height.
	plain := []byte("dealings are live state while this ciphertext is pinned to epoch 1")
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
	e, ok := k.GetEncTx(ctx, resp.DecryptHeight, resp.Seq)
	if !ok || e.Epoch != 1 {
		t.Fatalf("enc tx not stored against epoch 1: ok=%v epoch=%d", ok, e.Epoch)
	}

	// Member-change rekey to epoch 2. Epoch 1 stays the SERVING key until epoch 2 finalizes,
	// and it is pinned by the in-flight ciphertext, so its dealings must survive.
	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	openCtx := ctx.WithBlockHeight(7).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(openCtx) // open epoch 2 (DD=9, CD=11)

	if got := countDealings(k, ctx, 1); got != dealt {
		t.Fatalf("DKG-GC-ACTIVE: epoch 1 dealings purged while a ciphertext is in flight and the epoch is still serving: had %d, now %d.\n"+
			"On the transparent path a node re-derives its share from these dealings every block, so this makes the ciphertext permanently undecryptable on EVERY node.", dealt, got)
	}
	// The retention must be observable by operators, not silent.
	var sawRetained bool
	for _, ev := range openCtx.EventManager().Events() {
		if ev.Type == "encmempool_dkg_dealings_retained" {
			sawRetained = true
		}
	}
	if !sawRetained {
		t.Error("expected an encmempool_dkg_dealings_retained event when the purge is deferred")
	}

	// Finalize epoch 2. Epoch 1 is now superseded but STILL pinned: dealings stay.
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(8), all, 2, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager()))
	if k.GetActiveEpoch(ctx) != 2 {
		t.Fatalf("epoch 2 must be active, got %d", k.GetActiveEpoch(ctx))
	}
	if got := countDealings(k, ctx, 1); got != dealt {
		t.Fatalf("DKG-GC-ACTIVE: epoch 1 dealings purged after supersede while still pinned: had %d, now %d", dealt, got)
	}
	if n := k.GetEpochEncCount(ctx, 1); n != 1 {
		t.Fatalf("setup: expected epoch 1 to be pinned by exactly 1 ciphertext, got %d", n)
	}

	// Drain it: threshold members post shares and the ciphertext matures.
	round1, _ := k.GetDkgRound(ctx, 1)
	for _, rm := range round1.Members[:thr] {
		ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: rm.Index, Xi: derived1[rm.Index]}, ct)
		if err != nil {
			t.Fatalf("ProveDecryptShare: %v", err)
		}
		if _, err := ms.SubmitDecryptionShare(ctx.WithBlockHeight(int64(e.DecryptHeight)), &types.MsgSubmitDecryptionShare{
			Keyper: rm.AccountAddr, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: rm.Index,
			D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		}); err != nil {
			t.Fatalf("SubmitDecryptionShare(%s): %v", rm.AccountAddr, err)
		}
	}
	bctx := ctx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := decryptedLen(bctx); !ok {
		t.Fatal("ciphertext pinned to the superseded epoch failed to decrypt")
	}

	// Drained: the dealing bulk is reclaimed with the rest of the epoch, so the HIGH-2
	// state bound is preserved — the fix DEFERS the purge, it does not skip it.
	if got := countDealings(k, ctx, 1); got != 0 {
		t.Fatalf("epoch 1 dealings must be reclaimed once drained, still have %d", got)
	}
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("epoch 1 DkgRound should be pruned once its last ciphertext matured")
	}
}

// TestOnChainDKG_DealingsSurviveRekeyWindowThenReclaimed covers the case an earlier version of
// this suite got WRONG. With nothing in flight it is tempting to purge at the rekey block, but the
// superseded epoch is STILL the serving key until the fresh round finalizes, and SubmitEncrypted
// keeps stamping it for that whole window. Purging there makes every ciphertext accepted in the
// window undecryptable on every node - the quiet-chain case, which is the common one.
//
// So: dealings must survive the rekey, a ciphertext submitted INSIDE the window must still be
// derivable, and the bulk must be reclaimed once the successor takes over (the state bound is
// deferred, not abandoned).
func TestOnChainDKG_DealingsSurviveRekeyWindowThenReclaimed(t *testing.T) {
	const thr = 2
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	all := []member{A, B, C, D}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: 100,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0, DkgRetainActiveDealings: true,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	k.EndBlockDKG(ctx.WithBlockHeight(1))
	ak1, _ := dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, []member{A, B, C}, 1, thr)
	dealt := countDealings(k, ctx, 1)
	if dealt == 0 {
		t.Fatal("setup: epoch 1 stored no dealings")
	}
	if n := k.GetEpochEncCount(ctx, 1); n != 0 {
		t.Fatalf("setup: epoch 1 must have nothing in flight, got %d", n)
	}

	// Member-change rekey at h=7 with an EMPTY epoch. Epoch 1 is still ActiveEpoch here.
	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(7).WithEventManager(sdk.NewEventManager())) // open epoch 2 (DD=9, CD=11)

	if k.GetActiveEpoch(ctx) != 1 {
		t.Fatalf("precondition: epoch 1 must still be the SERVING key during the rekey window, got %d", k.GetActiveEpoch(ctx))
	}
	if got := countDealings(k, ctx, 1); got != dealt {
		t.Fatalf("DKG-GC-ACTIVE: dealings of the STILL-SERVING epoch purged at the rekey block: had %d, now %d.\n"+
			"SubmitEncrypted keeps stamping this epoch until the fresh round finalizes, so anything accepted in this window would be undecryptable on every node.", dealt, got)
	}

	// A ciphertext submitted INSIDE the rekey window is stamped to epoch 1 and must be derivable.
	plain := []byte("submitted during the rekey window; must still be decryptable")
	ct, ctR, err := threshold.EncryptWithR(ak1.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ms.SubmitEncrypted(ctx.WithBlockHeight(8), &types.MsgSubmitEncrypted{
		Submitter: "acc1", A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
		Pok: dkg.ProveEncKeyPoK(ctR, ctx.ChainID(), "acc1", ct.A, ct.Nonce, ct.Body).Marshal(),
	})
	if err != nil {
		t.Fatalf("SubmitEncrypted inside the rekey window: %v", err)
	}
	e, ok := k.GetEncTx(ctx, resp.DecryptHeight, resp.Seq)
	if !ok || e.Epoch != 1 {
		t.Fatalf("expected the in-window submission to be stamped to the serving epoch 1, got ok=%v epoch=%d", ok, e.Epoch)
	}
	if got := countDealings(k, ctx, e.Epoch); got == 0 {
		t.Fatal("DKG-GC-ACTIVE: a ciphertext was accepted against an epoch with no dealings - it can never be decrypted by anyone")
	}

	// Finalize epoch 2. Epoch 1 stops serving but is now PINNED by the in-window ciphertext.
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(8), all, 2, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager()))
	if k.GetActiveEpoch(ctx) != 2 {
		t.Fatalf("epoch 2 must be active, got %d", k.GetActiveEpoch(ctx))
	}
	if got := countDealings(k, ctx, 1); got != dealt {
		t.Fatalf("epoch 1 is pinned by the in-window ciphertext; dealings must survive, had %d now %d", dealt, got)
	}
}

// TestOnChainDKG_DealingsPurgedOnceNoLongerServing is the state-bound control: the fix DEFERS the
// purge, it must not abandon it. Once the successor epoch takes over and nothing is pinned, the
// superseded epoch's dealing bulk has to be reclaimed.
func TestOnChainDKG_DealingsPurgedOnceNoLongerServing(t *testing.T) {
	const thr = 2
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
	all := []member{A, B, C, D}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: 100,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0, DkgRetainActiveDealings: true,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	k.EndBlockDKG(ctx.WithBlockHeight(1))
	dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, []member{A, B, C}, 1, thr)
	if countDealings(k, ctx, 1) == 0 {
		t.Fatal("setup: epoch 1 stored no dealings")
	}
	if n := k.GetEpochEncCount(ctx, 1); n != 0 {
		t.Fatalf("setup: epoch 1 must have nothing in flight, got %d", n)
	}

	// Member-change rekey: epoch 1 is still serving, so the bulk is retained for now.
	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(7).WithEventManager(sdk.NewEventManager()))

	// Epoch 2 finalizes and takes over. Epoch 1 no longer serves and nothing is pinned to it,
	// so it must now be fully reclaimed - dealings included.
	dealAllMembers(t, k, ms, ctx.WithBlockHeight(8), all, 2, thr)
	k.EndBlockDKG(ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager()))
	if k.GetActiveEpoch(ctx) != 2 {
		t.Fatalf("epoch 2 must be active, got %d", k.GetActiveEpoch(ctx))
	}
	if got := countDealings(k, ctx, 1); got != 0 {
		t.Fatalf("STATE BOUND: a drained, no-longer-serving epoch must shed its dealings, still have %d", got)
	}
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("STATE BOUND: epoch 1 round record should be reclaimed once it is drained and superseded")
	}
}

// TestOnChainDKG_RetentionGateOffReplaysLegacyPurge is the REPLAY-SAFETY control. The fix changes
// committed state, and the legacy rule already produced live history (every past rekey deleted the
// still-serving epoch's dealings). So a node replaying those heights MUST reproduce the old
// behaviour exactly, or sync-from-genesis and any state sync whose replay window contains a rekey
// diverge on app hash. The gate param is absent in a pre-upgrade params blob, which unmarshals to
// false - this asserts false really does mean "purge exactly like the old binary".
func TestOnChainDKG_RetentionGateOffReplaysLegacyPurge(t *testing.T) {
	const thr = 2
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, EncExecEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: 100,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0,
		DkgRetainActiveDealings: false, // pre-upgrade: the field is absent from the stored JSON
		DkgMembers:              declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// A stored params blob written by an older binary has no such key. Confirm it round-trips to
	// false rather than to the DefaultParams value, which is what makes replay safe.
	if got := k.GetParams(ctx); got.DkgRetainActiveDealings {
		t.Fatal("REPLAY SAFETY: a params blob without dkg_retain_active_dealings must read as false")
	}
	if !types.DefaultParams().DkgRetainActiveDealings {
		t.Fatal("a FRESH genesis must default to the fixed behaviour, so mainnet never runs the legacy rule")
	}

	k.EndBlockDKG(ctx.WithBlockHeight(1))
	ak1, _ := dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, []member{A, B, C}, 1, thr)
	if countDealings(k, ctx, 1) == 0 {
		t.Fatal("setup: epoch 1 stored no dealings")
	}

	// Pin epoch 1 with an in-flight ciphertext: even THAT must not stop the legacy purge, because
	// the old binary did not check.
	ct, ctR, err := threshold.EncryptWithR(ak1.Pub, []byte("legacy replay path"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.SubmitEncrypted(ctx.WithBlockHeight(6), &types.MsgSubmitEncrypted{
		Submitter: "acc1", A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
		Pok: dkg.ProveEncKeyPoK(ctR, ctx.ChainID(), "acc1", ct.A, ct.Nonce, ct.Body).Marshal(),
	}); err != nil {
		t.Fatalf("SubmitEncrypted: %v", err)
	}
	if n := k.GetEpochEncCount(ctx, 1); n != 1 {
		t.Fatalf("setup: expected epoch 1 pinned by 1 ciphertext, got %d", n)
	}

	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(7).WithEventManager(sdk.NewEventManager()))

	if got := countDealings(k, ctx, 1); got != 0 {
		t.Fatalf("REPLAY SAFETY: with the gate off the rekey must purge exactly as the pre-fix binary did, still have %d dealings.\n"+
			"Any divergence here changes the app hash of historical blocks and breaks sync-from-genesis.", got)
	}

	// And the ingress belt must stay dormant too, or historical tx acceptance (and gas) would differ.
	if !k.ActiveEpochCanDeriveShares(ctx, k.GetParams(ctx)) {
		t.Fatal("REPLAY SAFETY: the ingress belt must be inert while the gate is off")
	}
}

// TestMissingShareOperators_NamesOnlyRealWithholders locks in the attribution rules: the legacy
// share path keys shares by ACCOUNT address while the round lists OPERATOR addresses, and a
// zero-eval-point member cannot contribute at all. Naming either as a withholder is a false
// accusation baked permanently into the event log, which is the one thing this attribute must
// never do.
func TestMissingShareOperators_NamesOnlyRealWithholders(t *testing.T) {
	const thr = 2
	A, B, C := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1, DecryptDelay: 100,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: thr, DkgMinRekeyGap: 0, DkgRetainActiveDealings: true,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	dealAndFinalizeCapturing(t, k, ms, ctx, 2, 5, []member{A, B, C}, 1, thr)

	round, ok := k.GetDkgRound(ctx, 1)
	if !ok {
		t.Fatal("setup: no round 1")
	}
	byOp := map[string]types.RoundMember{}
	for _, m := range round.Members {
		byOp[m.OperatorAddr] = m
	}
	m1, m2, m3 := byOp["op1"], byOp["op2"], byOp["op3"]
	if m1.AccountAddr == "" || m1.AccountAddr == m1.OperatorAddr {
		t.Fatalf("setup: legacy members must carry a distinct account address, got %q/%q", m1.OperatorAddr, m1.AccountAddr)
	}

	// LEGACY path: shares are keyed by ACCOUNT address. op1 and op2 contributed, op3 withheld.
	legacy := []types.EncShare{
		{Keyper: m1.AccountAddr, Index: m1.Index},
		{Keyper: m2.AccountAddr, Index: m2.Index},
	}
	if got := k.MissingShareOperators(ctx, 1, legacy); got != "op3" {
		t.Fatalf("legacy share path: want only the real withholder %q, got %q\n"+
			"(matching operator addresses against account-keyed shares names the whole committee)", "op3", got)
	}

	// TRANSPARENT path: shares are keyed by OPERATOR address. Same expectation.
	transparent := []types.EncShare{
		{Keyper: m1.OperatorAddr, Index: m1.Index},
		{Keyper: m2.OperatorAddr, Index: m2.Index},
	}
	if got := k.MissingShareOperators(ctx, 1, transparent); got != "op3" {
		t.Fatalf("transparent share path: want %q, got %q", "op3", got)
	}

	// Everyone contributed: nobody is named.
	full := append(append([]types.EncShare{}, transparent...), types.EncShare{Keyper: m3.OperatorAddr, Index: m3.Index})
	if got := k.MissingShareOperators(ctx, 1, full); got != "" {
		t.Fatalf("full participation must name nobody, got %q", got)
	}

	// A member that owns NO eval point is structurally unable to contribute and must be skipped.
	zero := round
	zero.Members = append(append([]types.RoundMember{}, round.Members...),
		types.RoundMember{Index: 99, OperatorAddr: "opzero", AccountAddr: "acczero", Weighted: true})
	zero.Epoch = 2
	if err := k.SetDkgRound(ctx, zero); err != nil {
		t.Fatal(err)
	}
	if got := k.MissingShareOperators(ctx, 2, full); got != "" {
		t.Fatalf("a zero-eval-point member cannot withhold and must not be named, got %q", got)
	}

	// Unknown epoch: no round, no accusation.
	if got := k.MissingShareOperators(ctx, 999, nil); got != "" {
		t.Fatalf("unknown epoch must name nobody, got %q", got)
	}
}
