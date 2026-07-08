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

// govAuthority is the x/gov module account — the only signer MsgUpdateParams accepts.
func govAuthority() string { return authtypes.NewModuleAddress(govtypes.ModuleName).String() }

func mustParamsJSON(t *testing.T, p types.Params) []byte {
	t.Helper()
	bz, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return bz
}

// The kill-switch is AUTHORITY-GATED: only the x/gov module account may update params;
// any other signer is rejected and the stored params are left untouched.
func TestUpdateParams_AuthorityGated(t *testing.T) {
	k, ctx := newKeeper(t, 5)
	ms := keeper.NewMsgServerImpl(k)

	np := types.DefaultParams()
	np.MaxRevealWindow = 250 // a detectable change
	pj := mustParamsJSON(t, np)

	before := k.GetParams(ctx)
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: "cosmos1notgov", Params: pj}); err == nil {
		t.Fatal("expected a non-gov signer to be rejected")
	}
	if k.GetParams(ctx).MaxRevealWindow != before.MaxRevealWindow {
		t.Fatal("a rejected update must NOT mutate params")
	}

	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: pj}); err != nil {
		t.Fatalf("gov authority update should succeed: %v", err)
	}
	if got := k.GetParams(ctx).MaxRevealWindow; got != 250 {
		t.Fatalf("expected params applied (MaxRevealWindow=250), got %d", got)
	}
}

// FULL validation on update: params that would strand state or wedge the round machine
// (the exact footguns Params.Validate blocks at genesis) are rejected, and every rejected
// update leaves the stored params unchanged.
func TestUpdateParams_InvalidRejected(t *testing.T) {
	k, ctx := newKeeper(t, 5)
	ms := keeper.NewMsgServerImpl(k)
	gov := govAuthority()

	base := types.DefaultParams()
	if err := k.SetParams(ctx, base); err != nil {
		t.Fatal(err)
	}

	// (a) reveal_delay=0
	badRevealDelay := types.DefaultParams()
	badRevealDelay.RevealDelay = 0
	// (b) enc_enabled with NO key path (Threshold=0, DKG off) — the state-leak footgun.
	badEnc := types.DefaultParams()
	badEnc.EncEnabled = true
	badEnc.DecryptDelay = 1
	// (c) dkg_enabled with an empty member set
	badDkg := types.DefaultParams()
	badDkg.DkgEnabled = true
	// (d) dkg_enabled but a zero deal window (ValidateDkgWindows rejects it)
	badWindow := types.DefaultParams()
	badWindow.DkgEnabled = true
	m := newMember("op1", "acc1")
	badWindow.DkgMembers = []types.DkgMember{{OperatorAddr: m.op, AccountAddr: m.acc, EncPubKey: m.pub}}
	badWindow.DkgDealWindow = 0

	for name, bad := range map[string]types.Params{
		"reveal_delay_0": badRevealDelay, "enc_no_keypath": badEnc,
		"dkg_no_members": badDkg, "dkg_zero_window": badWindow,
	} {
		if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: mustParamsJSON(t, bad)}); err == nil {
			t.Fatalf("%s: expected invalid params to be rejected", name)
		}
	}

	// malformed JSON is rejected too (never panics, never writes).
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: []byte("{not json")}); err == nil {
		t.Fatal("expected malformed params json to be rejected")
	}

	if got := k.GetParams(ctx); got.RevealDelay != base.RevealDelay || got.EncEnabled != base.EncEnabled || got.DkgEnabled != base.DkgEnabled {
		t.Fatalf("rejected updates must leave params unchanged, got %+v", got)
	}
}

// The core kill-switch behaviour: governance can ENABLE the encrypted+DKG path, DISABLE
// it, and RE-ENABLE it, with the stored params reflecting each transition.
func TestUpdateParams_EnableDisableReEnableCycle(t *testing.T) {
	k, ctx := newKeeper(t, 5)
	ms := keeper.NewMsgServerImpl(k)
	gov := govAuthority()

	if p := k.GetParams(ctx); p.EncEnabled || p.DkgEnabled {
		t.Fatal("default params must be dormant (both switches off)")
	}

	m1, m2 := newMember("op1", "acc1"), newMember("op2", "acc2")
	enabled := types.DefaultParams()
	enabled.EncEnabled = true
	enabled.DkgEnabled = true
	enabled.DkgStartHeight = 1
	enabled.DkgThreshold = 2
	enabled.DecryptDelay = 2
	enabled.DkgMembers = []types.DkgMember{
		{OperatorAddr: m1.op, AccountAddr: m1.acc, EncPubKey: m1.pub},
		{OperatorAddr: m2.op, AccountAddr: m2.acc, EncPubKey: m2.pub},
	}

	// ENABLE
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: mustParamsJSON(t, enabled)}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if p := k.GetParams(ctx); !p.EncEnabled || !p.DkgEnabled {
		t.Fatal("enable must set EncEnabled && DkgEnabled")
	}

	// DISABLE (kill-switch) — both OFF. Must pass validation (threshold path inert).
	disabled := enabled
	disabled.EncEnabled = false
	disabled.DkgEnabled = false
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: mustParamsJSON(t, disabled)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if p := k.GetParams(ctx); p.EncEnabled || p.DkgEnabled {
		t.Fatal("disable must clear EncEnabled && DkgEnabled")
	}

	// RE-ENABLE
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: mustParamsJSON(t, enabled)}); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if p := k.GetParams(ctx); !p.EncEnabled || !p.DkgEnabled {
		t.Fatal("re-enable must restore EncEnabled && DkgEnabled")
	}
}

// SAFE DISABLE: disabling the module mid-flight must NOT strand already-submitted EncTx
// forever and must NOT halt. BeginBlock drains the matured in-flight ciphertext via the
// existing releaseEncTx/prune path (GC, not decrypt), releasing every ref-count.
func TestUpdateParams_DisableDrainsInFlight_NoStrand(t *testing.T) {
	pub, _, err := threshold.Setup(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)
	gov := govAuthority()

	// enable the legacy encrypted path (valid threshold config)
	enabled := types.DefaultParams()
	enabled.EncEnabled = true
	enabled.DecryptDelay = 2
	enabled.Threshold = 2
	enabled.Keypers = []string{"k1", "k2", "k3"}
	enabled.ThresholdPub = pub
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: mustParamsJSON(t, enabled)}); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// an in-flight ciphertext maturing at height 12
	ct, _ := threshold.Encrypt(pub, []byte("secret in flight"))
	e := k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 0)
	if e.DecryptHeight != 12 {
		t.Fatalf("want decrypt height 12, got %d", e.DecryptHeight)
	}
	if k.GetGlobalEncCount(ctx) != 1 {
		t.Fatalf("want 1 in-flight, got %d", k.GetGlobalEncCount(ctx))
	}

	// DISABLE while the ct is still in-flight
	disabled := enabled
	disabled.EncEnabled = false
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: mustParamsJSON(t, disabled)}); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// BeginBlock at maturity: no halt, no decrypt, clean GC.
	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("BeginBlock must not error on a disabled module: %v", err)
	}
	if _, ok := decryptedLen(bctx); ok {
		t.Fatal("a disabled module must not decrypt")
	}
	if !hasEvent(bctx, "encmempool_enc_drained_disabled") {
		t.Fatal("expected the in-flight ciphertext to be drained")
	}
	if _, ok := k.GetEncTx(bctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("STRAND: EncTx still present after drain")
	}
	if c := k.GetGlobalEncCount(bctx); c != 0 {
		t.Fatalf("STRAND: global in-flight count = %d, want 0", c)
	}
	if c := k.GetSubmitterEncCount(bctx, "user"); c != 0 {
		t.Fatalf("STRAND: per-submitter count = %d, want 0", c)
	}
}

// SAFE DISABLE (DKG epoch): draining a DKG-stamped in-flight ct while disabled must go
// through releaseEncTx -> maybePruneEpoch, so a SUPERSEDED epoch's pinned DkgRound +
// ActiveThresholdKey are reclaimed (no stranded per-epoch state).
func TestUpdateParams_DisableDrains_DkgEpochPruned(t *testing.T) {
	k, ctx := newKeeper(t, 10)

	// Module is dormant (default: EncEnabled=false). Seed a SUPERSEDED epoch 1 (active/current
	// have advanced to 2) with one in-flight ct pinned to it.
	k.SetCurrentEpoch(ctx, 2)
	k.SetActiveEpoch(ctx, 2)
	if err := k.SetDkgRound(ctx, types.DkgRound{Epoch: 1, Status: types.DkgStatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: 1, Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	e := k.SubmitEncTx(ctx, "user", 10, 1, []byte("a"), make([]byte, threshold.NonceSize), []byte("body"), 1)
	if k.GetEpochEncCount(ctx, 1) != 1 {
		t.Fatal("epoch 1 ref-count should be 1")
	}

	// Disabled module: BeginBlock drains the matured ct and prunes the superseded epoch.
	bctx := ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatalf("BeginBlock: %v", err)
	}
	if _, ok := k.GetEncTx(bctx, e.DecryptHeight, e.Seq); ok {
		t.Fatal("STRAND: EncTx not drained")
	}
	if c := k.GetEpochEncCount(bctx, 1); c != 0 {
		t.Fatalf("STRAND: epoch ref-count = %d, want 0", c)
	}
	if _, ok := k.GetActiveKey(bctx, 1); ok {
		t.Fatal("superseded epoch 1 active key not pruned")
	}
	if _, ok := k.GetDkgRound(bctx, 1); ok {
		t.Fatal("superseded epoch 1 round not pruned")
	}
}
