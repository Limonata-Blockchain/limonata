package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// TestSubmitEncrypted_AdmissionCeilings locks in the INGRESS admission control that closes the
// unbounded-state HIGH: SubmitEncrypted REJECTS a ciphertext once the per-submitter OR the
// global in-flight ceiling is reached, so a flooder can never grow EncTx state without bound.
// Pre-fix SubmitEncrypted accepted every ciphertext (no ceiling), so this FAILS pre-fix.
func TestSubmitEncrypted_AdmissionCeilings(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, Threshold: 1, DecryptDelay: 100, // long delay: nothing matures during the test
		MaxInFlightEncTx: 20, MaxInFlightPerSubmitter: 5,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	body := []byte("x")
	submit := func(sub string) error {
		_, err := ms.SubmitEncrypted(ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager()),
			&types.MsgSubmitEncrypted{Submitter: sub, A: a, Nonce: nonce, Body: body})
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
		EncEnabled: true, DkgEnabled: true, DecryptDelay: 2,
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

	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	body := []byte("x")
	for i := 0; i < n; i++ {
		k.SubmitEncTx(ctx, "attacker", 10, 2, a, nonce, body, 1) // stamped to superseded epoch 1
	}
	if got := k.GetEpochEncCount(ctx, 1); got != n {
		t.Fatalf("epoch-1 ref-count should be %d, got %d", n, got)
	}

	// Block 12: all mature. Global (200) > ceiling (50) => the drop path sheds the excess.
	b12 := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(b12, "encmempool_enc_dropped_ceiling") {
		t.Fatal("expected the last-resort ceiling drop to fire (in-flight 200 >> ceiling 50)")
	}
	// Everything left state this block (150 dropped + 50 decrypt-missed), so the superseded
	// epoch drained and MUST have been pruned via the drop path's decEpochEncCount+maybePrune.
	if got := k.GetEpochEncCount(ctx, 1); got != 0 {
		t.Fatalf("HIGH-2 REGRESSION: drop path leaked epoch ref-count (epoch-1 count=%d, want 0)", got)
	}
	if _, ok := k.GetActiveKey(ctx, 1); ok {
		t.Fatal("HIGH-2 REGRESSION: superseded epoch 1 ActiveThresholdKey survived a drop-drain (ref-count leaked)")
	}
	if _, ok := k.GetDkgRound(ctx, 1); ok {
		t.Fatal("HIGH-2 REGRESSION: superseded epoch 1 DkgRound survived a drop-drain (ref-count leaked)")
	}
	if g := k.GetGlobalEncCount(b12); g != 0 {
		t.Fatalf("global in-flight should be 0 after full drop+drain, got %d", g)
	}
	if got := countEncTx(k, b12); got != 0 {
		t.Fatalf("state not bounded: %d EncTx remain after the ceiling drop", got)
	}
}

// TestCollectMaturedUpTo_BoundedWindow locks in the BOUNDED-SCAN primitive: the matured scan
// materializes at most `limit` entries and reports truncation, so per-block decrypt cost is
// O(cap), not O(backlog). Pre-fix decryptMatured used an UNBOUNDED IterateEncTxUpTo that read
// the whole backlog into a slice every block.
func TestCollectMaturedUpTo_BoundedWindow(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, types.Params{RevealDelay: 1, MaxRevealWindow: 1_000_000, EncEnabled: true, Threshold: 1, DecryptDelay: 2}); err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 33)
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
