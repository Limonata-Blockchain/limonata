// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// TestOnChainDKG_FinalizeDeterministic locks the #1 multi-node halt-safety property:
// the EndBlocker finalize must be BYTE-IDENTICAL across nodes regardless of the order
// in which dealings arrived. Two independent keepers are fed the EXACT same dealings
// in opposite insertion order; the installed active key (pub, aggregate commitments,
// QUAL, threshold) must match bit-for-bit. This would break if finalize ever ranged a
// Go map to produce output instead of iterating sorted committed state.
func TestOnChainDKG_FinalizeDeterministic(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}

	// Build one fixed set of dealing payloads (shared by both keepers) so any output
	// difference can ONLY come from nondeterministic finalize, not different inputs.
	type payload struct {
		acc         string
		commitments [][]byte
		encShares   []*types.DkgEncShare
	}
	// Assign indices the same way the keeper does (rank by operator addr, 1-based).
	idxByAcc := map[string]uint64{"acc1": 1, "acc2": 2, "acc3": 3}
	allIdx := []uint64{1, 2, 3}
	payloads := make([]payload, 0, len(members))
	for _, dealer := range members {
		di := idxByAcc[dealer.acc]
		commitments, shares, err := dkg.Deal(di, allIdx, thr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encShares := make([]*types.DkgEncShare, 0, len(members))
		for _, recip := range members {
			ri := idxByAcc[recip.acc]
			ct, err := dkg.EncryptShareTo(recip.pub, shares[ri])
			if err != nil {
				t.Fatal(err)
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: ri, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
		payloads = append(payloads, payload{acc: dealer.acc, commitments: commitments, encShares: encShares})
	}

	run := func(order []int) types.ActiveThresholdKey {
		k, ctx := newKeeper(t, 1)
		ms := keeper.NewMsgServerImpl(k)
		p := types.Params{
			EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
			DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: thr, DkgMembers: declaredFrom(members),
		}
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		k.EndBlockDKG(ctx.WithBlockHeight(1)) // epoch 1, ComplaintDeadline = 5
		dealCtx := ctx.WithBlockHeight(2)
		for _, i := range order {
			if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{
				Dealer: payloads[i].acc, Epoch: 1, Commitments: payloads[i].commitments, EncShares: payloads[i].encShares,
			}); err != nil {
				t.Fatalf("DkgDeal(%s): %v", payloads[i].acc, err)
			}
		}
		k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
		ak, ok := k.GetActiveKey(ctx, 1)
		if !ok {
			t.Fatal("finalize did not install a key")
		}
		return ak
	}

	forward := run([]int{0, 1, 2})
	reversed := run([]int{2, 1, 0})

	if !bytes.Equal(forward.Pub, reversed.Pub) {
		t.Fatalf("nondeterministic pub:\n forward=%x\nreversed=%x", forward.Pub, reversed.Pub)
	}
	if forward.Threshold != reversed.Threshold {
		t.Fatalf("nondeterministic threshold: %d vs %d", forward.Threshold, reversed.Threshold)
	}
	if len(forward.Qual) != len(reversed.Qual) {
		t.Fatalf("nondeterministic QUAL length: %v vs %v", forward.Qual, reversed.Qual)
	}
	for i := range forward.Qual {
		if forward.Qual[i] != reversed.Qual[i] {
			t.Fatalf("nondeterministic QUAL order: %v vs %v", forward.Qual, reversed.Qual)
		}
	}
	if len(forward.PublicCommitments) != len(reversed.PublicCommitments) {
		t.Fatalf("nondeterministic commitment count")
	}
	for j := range forward.PublicCommitments {
		if !bytes.Equal(forward.PublicCommitments[j], reversed.PublicCommitments[j]) {
			t.Fatalf("nondeterministic aggregate commitment %d:\n forward=%x\nreversed=%x",
				j, forward.PublicCommitments[j], reversed.PublicCommitments[j])
		}
	}
}
