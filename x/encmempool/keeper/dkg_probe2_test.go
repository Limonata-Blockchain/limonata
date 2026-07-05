// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

func jm(v any) string { b, _ := json.Marshal(v); return string(b) }

// PROBE 4 — after two byzantine dealers force an infinity/garbage active key, is the
// feature stuck forever? The EndBlocker only re-runs on member-change or a FAILED
// round; an Active-but-unusable key is steady state.
func TestProbe_InfinityKey_StuckAndDownstreamSafe(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2")}
	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	openEpoch1(t, k, ctx, members, thr)

	s := randScalarP()
	negS := new(secp256k1.ModNScalar)
	negS.Set(s).Negate()
	deal := func(acc string, c0 []byte) {
		if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), &types.MsgDkgDeal{
			Dealer: acc, Epoch: 1, Commitments: [][]byte{c0, baseMul(randScalarP())}, EncShares: dummyEncShares(members),
		}); err != nil {
			t.Fatalf("deal(%s): %v", acc, err)
		}
	}
	deal(members[0].acc, baseMul(s))
	deal(members[1].acc, baseMul(negS))
	k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))

	ak, ok := k.GetActiveKey(ctx, 1)
	if !ok {
		t.Fatal("expected an (invalid) active key to be installed")
	}
	if _, err := secp256k1.ParsePubKey(ak.Pub); err == nil {
		t.Fatalf("expected Pub to be an INVALID point; got a parseable key %x", ak.Pub)
	}
	t.Logf("installed INVALID active key Pub=%x, activeEpoch=%d", ak.Pub, k.GetActiveEpoch(ctx))

	for h := int64(6); h <= 46; h++ {
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
	}
	if ce := k.GetCurrentEpoch(ctx); ce != 1 {
		t.Fatalf("unexpected re-run: current epoch advanced to %d", ce)
	}
	r, _ := k.GetDkgRound(ctx, 1)
	if r.Status != types.DkgStatusActive {
		t.Fatalf("round stuck-active expected; got %q", r.Status)
	}
	t.Log("CONFIRMED: garbage active key is permanent (no auto re-run); anti-MEV feature bricked for the epoch")
}

func roundFingerprint(t *testing.T, k keeper.Keeper, ctx sdk.Context, epoch uint64) string {
	t.Helper()
	out := ""
	if r, ok := k.GetDkgRound(ctx, epoch); ok {
		out += jm(r)
	}
	if ak, ok := k.GetActiveKey(ctx, epoch); ok {
		out += "|AK:" + jm(ak)
	}
	k.IterateDealings(ctx, epoch, func(d types.Dealing) { out += "|D:" + jm(d) })
	k.IterateComplaints(ctx, epoch, func(c types.DkgComplaintRec) { out += "|C:" + jm(c) })
	return out
}

// PROBE 5 — full-state determinism under reordered dealings. Build ONE shared set of
// dealing payloads, then feed two keepers the same payloads in opposite orders; the
// finalized round record + active key + stored dealings must be byte-identical.
func TestProbe_FullStateDeterminism(t *testing.T) {
	const thr = 2
	members := []member{newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3")}
	idxByAcc := map[string]uint64{"acc1": 1, "acc2": 2, "acc3": 3}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
	// Shared payloads (identical across both runs).
	payloads := make([]*types.MsgDkgDeal, 0, len(members))
	for _, dealer := range members {
		c, shares, err := dkg.Deal(dealer.index, []uint64{1, 2, 3}, thr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encShares := make([]*types.DkgEncShare, 0, len(members))
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatal(err)
			}
			encShares = append(encShares, &types.DkgEncShare{MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
		payloads = append(payloads, &types.MsgDkgDeal{Dealer: dealer.acc, Epoch: 1, Commitments: c, EncShares: encShares})
	}

	run := func(order []int) string {
		k, ctx := newKeeper(t, 1)
		ms := keeper.NewMsgServerImpl(k)
		p := types.Params{
			EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
			DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: thr, DkgMembers: declaredFrom(members),
			DkgRetryBackoff: 2, DkgMaxAttempts: 8,
		}
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		k.EndBlockDKG(ctx.WithBlockHeight(1))
		for _, i := range order {
			if _, err := ms.DkgDeal(ctx.WithBlockHeight(2), payloads[i]); err != nil {
				t.Fatalf("deal %d: %v", i, err)
			}
		}
		k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
		return roundFingerprint(t, k, ctx, 1)
	}
	a := run([]int{0, 1, 2})
	b := run([]int{2, 1, 0})
	if a != b {
		t.Fatalf("NON-DETERMINISM across insertion order:\nA=%s\nB=%s", a, b)
	}
	t.Logf("full round state identical across reordered inputs (len=%d)", len(a))
}
