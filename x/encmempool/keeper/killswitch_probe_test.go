// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"encoding/json"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

func pj(t *testing.T, p types.Params) []byte {
	t.Helper()
	bz, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bz
}

func gov() string { return authtypes.NewModuleAddress(govtypes.ModuleName).String() }

// PROBE 1 — DKG->LEGACY transition while an epoch-N ciphertext is in flight.
// Governance flips DkgEnabled=false but keeps EncEnabled=true with a valid LEGACY
// threshold config. BeginBlock then takes the decryptMatured branch (EncEnabled &&
// Threshold>0). For the epoch-N ciphertext recoverSharedSecret routes GetActiveKey(N).
// ATTACK GOAL: strand the epoch-N ciphertext (never decrypted, never GC'd) or halt.
func TestProbe_DkgToLegacyTransition_NoStrandNoHalt(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)

	// Seed a finalized DKG epoch 1 (active+current = 1) with one in-flight ct pinned to it.
	k.SetCurrentEpoch(ctx, 1)
	k.SetActiveEpoch(ctx, 1)
	m1 := newMember("op1", "acc1")
	if err := k.SetDkgRound(ctx, types.DkgRound{
		Epoch: 1, Status: types.DkgStatusActive, Threshold: 1,
		Members: []types.RoundMember{{Index: 1, OperatorAddr: m1.op, AccountAddr: m1.acc, EncPubKey: m1.pub}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: 1, Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	e := k.SubmitEncTx(ctx, "user", 10, 2, []byte("A"), make([]byte, threshold.NonceSize), []byte("body"), 1)
	if k.GetEpochEncCount(ctx, 1) != 1 || k.GetGlobalEncCount(ctx) != 1 {
		t.Fatal("seed ref-counts wrong")
	}

	// Flip to a VALID legacy config (DkgEnabled=false, EncEnabled=true, Threshold>0).
	pub, _, err := threshold.Setup(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	legacy := types.DefaultParams()
	legacy.EncEnabled = true
	legacy.DkgEnabled = false
	legacy.DecryptDelay = 2
	legacy.Threshold = 2
	legacy.Keypers = []string{"k1", "k2", "k3"}
	legacy.ThresholdPub = pub
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov(), Params: pj(t, legacy)}); err != nil {
		t.Fatalf("legacy flip rejected: %v", err)
	}

	// BeginBlock at maturity (height 12): must not halt. Under the cycle-3 H-B semantics the
	// share-less ciphertext is NOT silently dropped at maturity — it is DEFERRED (kept, with a
	// loud decrypt_missed) for the bounded grace, then stranded-dropped LOUDLY. Either way it
	// must leave state by maturity + StrandedDecryptGraceBlocks with every ref-count released.
	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("HALT: BeginBlock returned error: %v", err)
	}
	if _, ok := k.GetEncTx(bctx, e.DecryptHeight, e.Seq); !ok {
		t.Fatal("H-B: a share-less matured ct must be DEFERRED (not silently dropped) within the grace")
	}
	bctx = ctx.WithBlockHeight(12 + int64(keeper.StrandedDecryptGraceBlocks)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("HALT: BeginBlock returned error at grace expiry: %v", err)
	}
	if !hasEvent(bctx, "encmempool_decrypt_stranded") {
		t.Fatal("H-B: the final drop must be LOUD (encmempool_decrypt_stranded)")
	}
	if _, ok := k.GetEncTx(bctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("STRAND: epoch-1 EncTx still present after the deferral grace in legacy mode")
	}
	if c := k.GetGlobalEncCount(bctx); c != 0 {
		t.Fatalf("STRAND: global count = %d, want 0", c)
	}
	if c := k.GetEpochEncCount(bctx, 1); c != 0 {
		t.Fatalf("STRAND: epoch-1 count = %d, want 0", c)
	}
}

// PROBE 2 — LEGACY->DKG transition with Threshold=0 (allowed on the DKG path) while an
// epoch-0 (legacy) ciphertext is in flight. BeginBlock takes decryptMatured (DkgEnabled),
// and the epoch-0 ct routes the legacy recover with need=Threshold=0 => threshold.Recover
// on an empty share set. ATTACK GOAL: panic/halt or strand.
func TestProbe_LegacyToDkgThreshold0_NoPanicNoStrand(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)

	// An epoch-0 (legacy) ciphertext already in flight (leftover from a legacy phase).
	e := k.SubmitEncTx(ctx, "user", 10, 2, []byte("A"), make([]byte, threshold.NonceSize), []byte("body"), 0)
	if k.GetGlobalEncCount(ctx) != 1 {
		t.Fatal("seed wrong")
	}

	// Flip to a VALID DKG config with Threshold=0 (Validate returns nil before the
	// Threshold check on the DKG path). Need a valid member set.
	m1, m2 := newMember("op1", "acc1"), newMember("op2", "acc2")
	dkgp := types.DefaultParams()
	dkgp.EncEnabled = true
	dkgp.DkgEnabled = true
	dkgp.DkgStartHeight = 1
	dkgp.DecryptDelay = 2
	dkgp.Threshold = 0 // legacy threshold left at 0 — smuggled onto the DKG path
	dkgp.DkgMembers = []types.DkgMember{
		{OperatorAddr: m1.op, AccountAddr: m1.acc, EncPubKey: m1.pub},
		{OperatorAddr: m2.op, AccountAddr: m2.acc, EncPubKey: m2.pub},
	}
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov(), Params: pj(t, dkgp)}); err != nil {
		t.Fatalf("dkg flip rejected: %v", err)
	}

	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("HALT: BeginBlock returned error: %v", err)
	}
	if _, ok := k.GetEncTx(bctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("STRAND: epoch-0 EncTx still present after maturity")
	}
	if c := k.GetGlobalEncCount(bctx); c != 0 {
		t.Fatalf("STRAND: global count = %d, want 0", c)
	}
}

// PROBE 3 — full ENABLE -> DISABLE -> RE-ENABLE through the real EndBlock DKG machine.
// ATTACK GOAL: a disabled EndBlock still mutating round state, or a re-enable that fails
// to reopen / diverges / panics.
func TestProbe_EnableDisableReEnable_RealMachine(t *testing.T) {
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)

	m1, m2, m3 := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")
	enabled := types.DefaultParams()
	enabled.EncEnabled = true
	enabled.DkgEnabled = true
	enabled.DkgStartHeight = 1
	enabled.DkgThreshold = 2
	enabled.DecryptDelay = 2
	enabled.DkgDealWindow = 2
	enabled.DkgComplaintWindow = 2
	enabled.DkgMembers = []types.DkgMember{
		{OperatorAddr: m1.op, AccountAddr: m1.acc, EncPubKey: m1.pub},
		{OperatorAddr: m2.op, AccountAddr: m2.acc, EncPubKey: m2.pub},
		{OperatorAddr: m3.op, AccountAddr: m3.acc, EncPubKey: m3.pub},
	}
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov(), Params: pj(t, enabled)}); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// EndBlock opens epoch 1.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	if _, ok := k.GetDkgRound(ctx, 1); !ok {
		t.Fatal("epoch 1 not opened on enable")
	}
	epochAfterEnable := k.GetCurrentEpoch(ctx)

	// DISABLE. EndBlock over many heights must NOT open/advance any round.
	disabled := enabled
	disabled.EncEnabled = false
	disabled.DkgEnabled = false
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov(), Params: pj(t, disabled)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	for h := int64(2); h <= 40; h++ {
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
	}
	if got := k.GetCurrentEpoch(ctx); got != epochAfterEnable {
		t.Fatalf("DISABLED EndBlock advanced the epoch: %d -> %d", epochAfterEnable, got)
	}

	// RE-ENABLE. EndBlock must resume the machine without panic/divergence.
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov(), Params: pj(t, enabled)}); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	// The round opened before the disable timed out during the outage; re-enabled EndBlock
	// must finalize/fail+retry it and keep the machine live (never wedged).
	progressed := false
	for h := int64(41); h <= 120; h++ {
		ec := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		k.EndBlockDKG(ec)
		if k.GetCurrentEpoch(ec) > epochAfterEnable {
			progressed = true
			break
		}
	}
	if !progressed {
		t.Fatal("RE-ENABLE WEDGED: EndBlock never reopened a fresh round after re-enable")
	}
}

// PROBE 4 — HIGH-2 epoch ref-count must survive a toggle: a SUPERSEDED epoch with an
// in-flight (immature) ciphertext must NOT be pruned while disabled (else the ct could
// never decrypt on re-enable), and MUST prune once it drains. ATTACK GOAL: toggle-induced
// premature prune (strand the key) or a leaked pin (unbounded state).
func TestProbe_ToggleDoesNotBreakEpochRefcount(t *testing.T) {
	k, ctx := newKeeper(t, 10)

	// Superseded epoch 1 (active/current advanced to 2), IMMATURE ct pinned to epoch 1.
	k.SetCurrentEpoch(ctx, 2)
	k.SetActiveEpoch(ctx, 2)
	if err := k.SetDkgRound(ctx, types.DkgRound{Epoch: 1, Status: types.DkgStatusActive, Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	if err := k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: 1, Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	// decrypt height 20 (immature at 11..19).
	e := k.SubmitEncTx(ctx, "user", 10, 10, []byte("A"), make([]byte, threshold.NonceSize), []byte("body"), 1)

	// Disabled module: drain runs each block but the ct is IMMATURE, so epoch 1 must stay pinned.
	for h := int64(11); h <= 19; h++ {
		bctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := k.BeginBlock(bctx); err != nil {
			t.Fatalf("HALT at h=%d: %v", h, err)
		}
	}
	if _, ok := k.GetActiveKey(ctx, 1); !ok {
		t.Fatal("PREMATURE PRUNE: epoch-1 key gone while an immature ct still references it")
	}
	if c := k.GetEpochEncCount(ctx, 1); c != 1 {
		t.Fatalf("epoch-1 pin lost: count=%d want 1", c)
	}

	// At maturity (20) it drains and the epoch is reclaimed.
	bctx := ctx.WithBlockHeight(20).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("HALT at maturity: %v", err)
	}
	if _, ok := k.GetEncTx(bctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("STRAND: ct not drained at maturity")
	}
	if _, ok := k.GetActiveKey(bctx, 1); ok {
		t.Fatal("LEAK: epoch-1 key not reclaimed after drain")
	}
	if c := k.GetEpochEncCount(bctx, 1); c != 0 {
		t.Fatalf("LEAK: epoch-1 count=%d want 0", c)
	}
}

// PROBE 5 — authority gating edges: empty authority, the module's own account, and a
// bech32-shaped non-gov address must all be rejected; only the gov module account passes.
func TestProbe_AuthorityGatingEdges(t *testing.T) {
	k, ctx := newKeeper(t, 5)
	ms := keeper.NewMsgServerImpl(k)

	np := types.DefaultParams()
	np.MaxRevealWindow = 777
	body := pj(t, np)

	bad := []string{
		"",
		"cosmos1xyz",
		authtypes.NewModuleAddress(types.ModuleName).String(),           // encmempool's own module acct
		authtypes.NewModuleAddress(authtypes.FeeCollectorName).String(), // some other module acct
	}
	for _, a := range bad {
		if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: a, Params: body}); err == nil {
			t.Fatalf("authority %q must be rejected", a)
		}
	}
	if k.GetParams(ctx).MaxRevealWindow == 777 {
		t.Fatal("BROKEN GATING: a non-gov update mutated params")
	}
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov(), Params: body}); err != nil {
		t.Fatalf("gov must pass: %v", err)
	}
	if k.GetParams(ctx).MaxRevealWindow != 777 {
		t.Fatal("gov update not applied")
	}
}
