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
// CYCLE-7 FIX VERIFICATION — UNVERIFIED-SHARE COUNT PADDING is CLOSED.
//
// THE CLOSED HOLE (was a <=1/3-stake liveness DoS that weakened the cycle-3 H-B grace):
//   decryptMatured() routes recoverSharedSecret()'s result:
//     - errNotEnoughShares || errStakeMinority  -> DEFER within the 32-block grace (heal-eligible)
//     - ANY OTHER err (incl. RecoverVerified "only X/need passed DLEQ") -> HARD DROP now
//   IngestDecryptShareFromVE USED to store decryption shares WITHOUT verifying their DLEQ proof,
//   so a committee member could store structurally-valid-but-cryptographically-invalid CHAFF
//   shares at its OWN owned eval points via a vote extension. Those chaff shares (1) inflated the
//   RAW count past `need` (count gate passed) and (2) marked that member present (stake gate
//   passed), after which RecoverVerified dropped the chaff (verified < need) and returned a
//   NON-errNotEnoughShares error -> the ciphertext was HARD-DROPPED instead of deferred to heal.
//
// THE FIX (belt-and-suspenders), asserted here:
//   #1 IngestDecryptShareFromVE now DLEQ-VERIFIES each share before SetEncShare, so a chaff share
//      NEVER enters state (never inflates the count, never marks its member present).
//   #2 the count gate + memberPresent stake map therefore govern on the DLEQ-VERIFIED count.
//   #3 even a share that reached state WITHOUT ingest verification is caught: RecoverVerified
//      returns dkg.ErrInsufficientVerified, which recoverSharedSecret routes into the SAME
//      within-grace DEFER branch as errNotEnoughShares (not the hard-drop branch).
//
// RESULT: a matured-but-short ciphertext under a chaff attack DEFERS and HEALS from late honest
// shares — it can no longer be forced to drop by stake-minority chaff.
// ============================================================================

// setValidShares derives member `op`'s REAL shares for the committee's active epoch and stores
// them (proved) DIRECTLY via SetEncShare against (e.DecryptHeight, e.Seq) — i.e. bypassing the
// vote-extension ingest path. Used to model honest shares that reach state and (in the fix-#3
// probe) to inject unverified padding the ingest gate would otherwise reject.
func setValidShares(t *testing.T, c h3Committee, ctx sdk.Context, e types.EncTx, ct *threshold.Ciphertext, op string) int {
	t.Helper()
	m := c.byOp[op]
	shares, err := deriveOK(c.k, ctx, c.round, c.ak, m)
	if err != nil {
		t.Fatalf("derive %s: %v", op, err)
	}
	n := 0
	for _, sh := range shares {
		ds, proof, perr := dkg.ProveDecryptShare(sh, ct)
		if perr != nil {
			t.Fatalf("prove %s: %v", op, perr)
		}
		if err := c.k.SetEncShare(ctx, types.EncShare{
			Keyper: op, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
			Index: ds.Index, D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		}); err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n
}

// veSharesFor builds member `op`'s REAL, DLEQ-PROVED decryption shares for ciphertext ct as
// vote-extension payloads (the exact wire a live node emits in ExtendVote).
func veSharesFor(t *testing.T, c h3Committee, ctx sdk.Context, e types.EncTx, ct *threshold.Ciphertext, op string) []types.VoteExtShare {
	t.Helper()
	m := c.byOp[op]
	shares, err := deriveOK(c.k, ctx, c.round, c.ak, m)
	if err != nil {
		t.Fatalf("derive %s: %v", op, err)
	}
	out := make([]types.VoteExtShare, 0, len(shares))
	for _, sh := range shares {
		ds, proof, perr := dkg.ProveDecryptShare(sh, ct)
		if perr != nil {
			t.Fatalf("prove %s: %v", op, perr)
		}
		out = append(out, types.VoteExtShare{
			Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
			Index: ds.Index, D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		})
	}
	return out
}

// chaffVESharesAt builds structurally-valid but cryptographically-GARBAGE shares (non-empty D,
// absent proof) at every eval point `op` owns — the padding a Byzantine member would spray.
func chaffVESharesAt(c h3Committee, e types.EncTx, op string) []types.VoteExtShare {
	var out []types.VoteExtShare
	for _, p := range c.memberPoints(op) {
		out = append(out, types.VoteExtShare{
			Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: p,
			D: []byte("garbage-D-not-a-real-partial"), // non-empty; no valid proof
		})
	}
	return out
}

// c7Committee builds the canonical cycle-7 committee: 4 equal-stake members (each 25% stake, each
// owns 8 of the S=32 eval points), t = floor(2*32/3) + 1 = 22. honest_A + honest_B own 16
// points (< t): their VALID shares alone cannot yet decrypt (the exact transient the grace
// protects). honest_C is a lagging honest member. attacker is a single 25%-stake member — a
// strict stake MINORITY (25% < 1/3).
func c7Committee(t *testing.T) h3Committee {
	t.Helper()
	stakes := map[string]int64{"honest_A": 100, "honest_B": 100, "honest_C": 100, "attacker": 100}
	c := runTransparentDKG(t, stakes, 32) // S=32=8n, n=4 -> t=22, each owns 8 points
	if int(c.ak.Threshold) != 22 {
		t.Fatalf("precondition: expected t=22, got %d", c.ak.Threshold)
	}
	for _, op := range []string{"honest_A", "honest_B", "honest_C", "attacker"} {
		if len(c.memberPoints(op)) != 8 {
			t.Fatalf("precondition: %s should own 8 points, owns %d", op, len(c.memberPoints(op)))
		}
	}
	total := c.coalitionStake([]string{"honest_A", "honest_B", "honest_C", "attacker"})
	if 3*c.coalitionStake([]string{"attacker"}) >= total {
		t.Fatalf("precondition: attacker must be < 1/3 stake")
	}
	return c
}

// TestC7_ChaffRejectedAtIngest_DefersAndHeals is the primary fix assertion (fix #1 + #2). A
// stake-minority attacker sprays chaff at its own owned points via a vote extension; the ingest
// gate REJECTS every chaff share (it never enters state, never inflates the count, never marks
// the attacker present), so the matured-but-short ciphertext DEFERS within grace and HEALS from
// a late honest share — the outcome is identical to the no-attacker control.
func TestC7_ChaffRejectedAtIngest_DefersAndHeals(t *testing.T) {
	c := c7Committee(t)
	plain := []byte("victim swap kept sealed until fairly ordered")

	ctx := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1) // matures @12

	// Honest A + B contribute their 16 REAL points through the VOTE-EXTENSION ingest path
	// (proving valid shares ARE accepted by the new ingest verification); the attacker sprays 8
	// chaff shares at its OWN owned points on the same block.
	ing := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
		{Operator: "honest_A", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_A")}},
		{Operator: "honest_B", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_B")}},
		{Operator: "attacker", VE: types.VoteExtension{Shares: chaffVESharesAt(c, e, "attacker")}},
	})

	// FIX #1: chaff was REJECTED at ingest — only the 16 verified honest shares are in state.
	stored := c.k.CollectShares(ctx, e.DecryptHeight, e.Seq)
	if len(stored) != 16 {
		t.Fatalf("FIX #1 REGRESSION: expected 16 verified shares stored (chaff rejected), got %d", len(stored))
	}
	if n := countEvents(ing, "encmempool_dkg_ve_share_rejected"); n != 8 {
		t.Fatalf("expected 8 chaff shares rejected at ingest with a loud event, got %d", n)
	}
	// The attacker owns none of the stored points (never marked present).
	attackerIdx := idxByOp(c.round, "attacker")
	for _, s := range stored {
		if types.EvalPointOwner(c.round.Members, s.Index) == attackerIdx {
			t.Fatal("FIX #1 REGRESSION: an attacker-owned point entered state via chaff")
		}
	}

	// FIX #2: matured @12 with 16 < t=22 VERIFIED shares -> DEFER (heal-eligible), NOT hard-drop.
	b12 := c.ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if _, ok := decryptedLen(b12); ok {
		t.Fatal("chaff must not enable decryption (verified < t)")
	}
	if hasEvent(b12, "encmempool_decrypt_failed") {
		t.Fatal("FIX REGRESSION: chaff padding forced a HARD DROP (encmempool_decrypt_failed) instead of a grace DEFER")
	}
	if !hasEvent(b12, "encmempool_decrypt_missed") {
		t.Fatal("matured-but-short ciphertext must DEFER (encmempool_decrypt_missed)")
	}
	if _, ok := c.k.GetEncTx(c.ctx, e.DecryptHeight, e.Seq); !ok {
		t.Fatal("deferred ciphertext must stay in state to heal")
	}

	// HEAL: the lagging honest member's real shares land inside the grace via a vote extension.
	heal := b12.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	c.k.ConsumeVoteExtensions(heal, []keeper.VEEntry{
		{Operator: "honest_C", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_C")}},
	})
	if n := len(c.k.CollectShares(c.ctx, e.DecryptHeight, e.Seq)); n != 24 {
		t.Fatalf("after healing VE, expected 24 verified shares (16+8), got %d", n)
	}
	b13 := c.ctx.WithBlockHeight(13).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b13); err != nil {
		t.Fatal(err)
	}
	got, ok := decryptedLen(b13)
	if !ok || got != len(plain) {
		t.Fatalf("late honest share within grace must HEAL+decrypt; ok=%v", ok)
	}
	t.Log("CLOSED: a 25pct-stake minority's chaff is rejected at ingest; the short ciphertext deferred and healed from the late honest share")
}

// TestC7_IngestVerifiesDLEQ_Unit is the focused unit test on IngestDecryptShareFromVE: a valid
// proved share is stored, a chaff share at an owned point is rejected, and a re-sent valid share
// is first-wins-deduped (never re-verified, never duplicated).
func TestC7_IngestVerifiesDLEQ_Unit(t *testing.T) {
	c := c7Committee(t)
	// Ingest at the ciphertext's maturity (submit 10 + delay 2 = 12): shares are only stored at/
	// after decrypt_height (the anti-MEV maturity gate).
	ctx := c.ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("unit"))
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1)

	valid := veSharesFor(t, c, ctx, e, ct, "honest_A")
	if len(valid) != 8 {
		t.Fatalf("precondition: honest_A should have 8 shares, got %d", len(valid))
	}

	// (a) a VALID proved share is accepted and stored.
	u := ctx.WithEventManager(sdk.NewEventManager())
	if !c.k.IngestDecryptShareFromVE(u, "honest_A", valid[0]) {
		t.Fatal("a valid DLEQ-proved share must be accepted at ingest")
	}
	if n := len(c.k.CollectShares(ctx, e.DecryptHeight, e.Seq)); n != 1 {
		t.Fatalf("expected 1 stored share, got %d", n)
	}

	// (b) a re-sent valid share is first-wins-deduped (not stored twice).
	if c.k.IngestDecryptShareFromVE(u, "honest_A", valid[0]) {
		t.Fatal("a re-sent share must be rejected by first-wins, not stored twice")
	}
	if n := len(c.k.CollectShares(ctx, e.DecryptHeight, e.Seq)); n != 1 {
		t.Fatalf("first-wins must keep the stored count at 1, got %d", n)
	}

	// (c) a CHAFF share at an owned point (bad D, no proof) is rejected — never stored.
	chaff := types.VoteExtShare{
		Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
		Index: c.memberPoints("attacker")[0], D: []byte("garbage"), // non-empty, no proof
	}
	rej := ctx.WithEventManager(sdk.NewEventManager())
	if c.k.IngestDecryptShareFromVE(rej, "attacker", chaff) {
		t.Fatal("FIX #1 REGRESSION: a chaff share (no valid DLEQ proof) must be rejected at ingest")
	}
	if !hasEvent(rej, "encmempool_dkg_ve_share_rejected") {
		t.Fatal("a rejected chaff share must emit encmempool_dkg_ve_share_rejected")
	}
	if n := len(c.k.CollectShares(ctx, e.DecryptHeight, e.Seq)); n != 1 {
		t.Fatalf("chaff must not enter state; stored count should still be 1, got %d", n)
	}

	// (d) a share with a WELL-FORMED-LENGTH but wrong (tampered) proof is also rejected.
	ds1, proof1, perr := dkg.ProveDecryptShare(deriveShareFor(t, c, ctx, "honest_A", valid[1].Index), ct)
	if perr != nil {
		t.Fatal(perr)
	}
	pb := dkg.MarshalDLEQProof(proof1)
	pb[0] ^= 0xff // corrupt the challenge scalar -> verification must fail
	tampered := types.VoteExtShare{
		Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
		Index: ds1.Index, D: ds1.D, Proof: pb,
	}
	tj := ctx.WithEventManager(sdk.NewEventManager())
	if c.k.IngestDecryptShareFromVE(tj, "honest_A", tampered) {
		t.Fatal("a share with a tampered DLEQ proof must be rejected at ingest")
	}
}

// deriveShareFor returns member op's threshold.Share sitting at eval point `index`.
func deriveShareFor(t *testing.T, c h3Committee, ctx sdk.Context, op string, index uint64) threshold.Share {
	t.Helper()
	shares, err := deriveOK(c.k, ctx, c.round, c.ak, c.byOp[op])
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range shares {
		if sh.Index == index {
			return sh
		}
	}
	t.Fatalf("member %s owns no share at point %d", op, index)
	return threshold.Share{}
}

// TestC7_UnverifiedShareBypassingIngest_DefersNotDrops is the fix-#3 belt-and-suspenders probe:
// it injects unverified chaff DIRECTLY into state (via SetEncShare, bypassing the ingest gate) to
// pad the RAW count past t and mark the attacker present, so BOTH on-chain gates pass and control
// reaches RecoverVerified. RecoverVerified drops the chaff and returns ErrInsufficientVerified;
// the decrypt path must route THAT into the within-grace DEFER branch (not a hard drop), and the
// ciphertext must then heal from late honest shares.
func TestC7_UnverifiedShareBypassingIngest_DefersNotDrops(t *testing.T) {
	c := c7Committee(t)
	plain := []byte("bypass-ingest padding must still only defer")

	ctx := c.ctx.WithBlockHeight(20).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user2", 20, 2, ct.A, ct.Nonce, ct.Body, 1) // matures @22

	// 16 REAL verified honest points (A+B) ...
	if got := setValidShares(t, c, ctx, e, ct, "honest_A") + setValidShares(t, c, ctx, e, ct, "honest_B"); got != 16 {
		t.Fatalf("expected 16 honest points, got %d", got)
	}
	// ... + 8 UNVERIFIED chaff at the attacker's own points, injected past the ingest gate.
	for _, p := range c.memberPoints("attacker") {
		if err := c.k.SetEncShare(ctx, types.EncShare{
			Keyper: "attacker", DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: p,
			D: []byte("garbage-D-not-a-real-partial"), // non-empty; no proof
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(c.k.CollectShares(ctx, e.DecryptHeight, e.Seq)); n != 24 {
		t.Fatalf("precondition: raw count must be padded to 24 (16 honest + 8 chaff), got %d", n)
	}

	// Matured @22: raw count 24 >= t=22 (count gate passes) and the attacker is present (stake
	// gate passes), so control reaches RecoverVerified — which drops the chaff (16 verified < 18)
	// and returns ErrInsufficientVerified. Fix #3 routes that into the grace DEFER branch.
	b22 := c.ctx.WithBlockHeight(22).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b22); err != nil {
		t.Fatal(err)
	}
	if hasEvent(b22, "encmempool_decrypt_failed") {
		t.Fatal("FIX #3 REGRESSION: insufficient-VERIFIED count HARD-DROPPED instead of deferring")
	}
	if !hasEvent(b22, "encmempool_decrypt_missed") {
		t.Fatal("insufficient-VERIFIED count must DEFER within grace (encmempool_decrypt_missed)")
	}
	if _, ok := c.k.GetEncTx(c.ctx, e.DecryptHeight, e.Seq); !ok {
		t.Fatal("deferred ciphertext must stay in state to heal")
	}

	// HEAL: the lagging honest member's real shares land inside the grace -> next block decrypts.
	_ = setValidShares(t, c, b22, e, ct, "honest_C") // +8 verified -> 24 verified >= t=22
	b23 := c.ctx.WithBlockHeight(23).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b23); err != nil {
		t.Fatal(err)
	}
	got, ok := decryptedLen(b23)
	if !ok || got != len(plain) {
		t.Fatalf("late honest share within grace must HEAL+decrypt even with stale chaff in state; ok=%v", ok)
	}
	t.Log("CLOSED: even chaff that bypasses ingest only DEFERS the ciphertext (fix #3); it healed from the late honest share")
}
