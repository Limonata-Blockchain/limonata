// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// HIGH-1 — enabling the transparent DKG can never HALT the chain because the two switches
// (module param DkgTransparent + consensus param VoteExtensionsEnableHeight) are coupled at
// BOTH the activation gate (MsgUpdateParams) and the runtime gate (veActive, whose core
// predicate is VoteExtEnabledAt).

// The runtime predicate that veActive keys off: no vote-extension handler acts unless VE is
// genuinely active at this height. It mirrors baseapp.ValidateVoteExtensions' own gate
// (enableHeight != 0 && height > enableHeight), so we can never inject/validate an extended
// commit that ValidateVoteExtensions would then reject -> no rejected-every-proposal halt.
//
// PRE-FIX: veActive keyed only off the module params with NO consensus-param coupling, so
// this predicate did not exist and a VE-disabled height would still run the handlers.
func TestReg_H1_VoteExtEnabledAtGate(t *testing.T) {
	cases := []struct {
		enableHeight, blockHeight int64
		want                      bool
	}{
		{0, 100, false},   // VE unscheduled (enableHeight 0): never active
		{50, 49, false},   // below the enable height
		{50, 50, false},   // AT the enable height: not yet active (matches baseapp's strict >)
		{50, 51, true},    // above the enable height: active
		{1, 2, true},      // enabled from height 1, active at 2
		{100, 100, false}, // boundary
	}
	for _, c := range cases {
		if got := types.VoteExtEnabledAt(c.enableHeight, c.blockHeight); got != c.want {
			t.Fatalf("VoteExtEnabledAt(%d,%d)=%v, want %v", c.enableHeight, c.blockHeight, got, c.want)
		}
	}
}

// The activation gate: governance cannot enable DkgTransparent while CometBFT vote
// extensions are not scheduled (VoteExtensionsEnableHeight == 0), so the misconfiguration
// that could halt the chain is refused up-front. Once VE is scheduled the same update
// succeeds.
//
// PRE-FIX: MsgUpdateParams performed no VE-coupling check, so it accepted DkgTransparent=true
// with VE disabled (the arm-then-halt footgun).
func TestReg_H1_UpdateParamsRejectsTransparentWithoutVE(t *testing.T) {
	k, ctx := newKeeper(t, 5)
	ms := keeper.NewMsgServerImpl(k)
	gov := govAuthority()
	raw := mustParamsJSON(t, transparentParams(1, 0)) // DkgEnabled && DkgTransparent

	// VE NOT scheduled (default consensus params: Abci nil) -> REJECT.
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: gov, Params: raw}); err == nil {
		t.Fatal("HIGH-1: enabling dkg_transparent with vote extensions unscheduled must be rejected")
	}
	if k.GetParams(ctx).DkgTransparent {
		t.Fatal("a rejected activation must NOT enable the transparent path")
	}

	// VE scheduled (enable height set) -> ACCEPT.
	ctxVE := ctx.WithConsensusParams(cmtproto.ConsensusParams{
		Abci: &cmtproto.ABCIParams{VoteExtensionsEnableHeight: 10},
	})
	if _, err := ms.UpdateParams(ctxVE, &types.MsgUpdateParams{Authority: gov, Params: raw}); err != nil {
		t.Fatalf("HIGH-1: with vote extensions scheduled the activation must succeed: %v", err)
	}
	if !k.GetParams(ctxVE).DkgTransparent {
		t.Fatal("expected the transparent path to be enabled once VE is scheduled")
	}
}
