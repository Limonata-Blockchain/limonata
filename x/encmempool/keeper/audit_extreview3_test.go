// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// TestCommitAdmission_Refcount locks in external-review #4: CommitTx now ref-counts in-flight commits
// (global + per-sender) so it can reject at a ceiling, and DeleteCommit decrements — without underflow on
// a double-delete (the reveal path and the GC path can both fire).
func TestCommitAdmission_Refcount(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)
	hash := make([]byte, 32) // sha256.Size

	for i := 0; i < 3; i++ {
		if _, err := ms.CommitTx(ctx.WithBlockHeight(int64(10+i)).WithEventManager(sdk.NewEventManager()),
			&types.MsgCommitTx{Sender: "s1", CommitHash: hash}); err != nil {
			t.Fatalf("commit %d rejected early: %v", i, err)
		}
	}
	if g := k.GetGlobalCommitCount(ctx); g != 3 {
		t.Fatalf("global commit count = %d, want 3", g)
	}
	if s := k.GetSubmitterCommitCount(ctx, "s1"); s != 3 {
		t.Fatalf("s1 commit count = %d, want 3", s)
	}

	// Delete one commit (as the reveal / GC path does): both counters decrement.
	k.DeleteCommit(ctx, 10, "s1", 0) // heights 10/11/12 -> seqs 0/1/2
	if g := k.GetGlobalCommitCount(ctx); g != 2 {
		t.Fatalf("after delete, global = %d, want 2", g)
	}
	if s := k.GetSubmitterCommitCount(ctx, "s1"); s != 2 {
		t.Fatalf("after delete, s1 = %d, want 2", s)
	}
	// Double-delete of the SAME commit must NOT underflow (idempotent — guarded by an existence check).
	k.DeleteCommit(ctx, 10, "s1", 0)
	if g := k.GetGlobalCommitCount(ctx); g != 2 {
		t.Fatalf("double-delete underflowed the count: global = %d, want 2", g)
	}
}

// TestDkgTxHandlers_RejectedUnderTransparent locks in external-review #7: the legacy signed-tx DKG
// handlers (member-index based) MUST reject once the transparent (weighted, vote-extension) path is
// active, so a stale/imported tx can never write semantically-wrong state into a weighted round.
func TestDkgTxHandlers_RejectedUnderTransparent(t *testing.T) {
	k, ctx := newKeeperSK(t, 10, &mockStaking{})
	ms := keeper.NewMsgServerImpl(k)
	if err := k.SetParams(ctx, transparentParams(1, 0)); err != nil { // DkgEnabled && DkgTransparent && EncEnabled
		t.Fatal(err)
	}
	if _, err := ms.DkgDeal(ctx, &types.MsgDkgDeal{Dealer: "acc", Epoch: 1}); err == nil {
		t.Fatal("MsgDkgDeal must be rejected under DkgTransparent")
	}
	if _, err := ms.DkgComplaint(ctx, &types.MsgDkgComplaint{Epoch: 1}); err == nil {
		t.Fatal("MsgDkgComplaint must be rejected under DkgTransparent")
	}
	if _, err := ms.SubmitDecryptionShare(ctx, &types.MsgSubmitDecryptionShare{D: []byte{1}}); err == nil {
		t.Fatal("MsgSubmitDecryptionShare must be rejected under DkgTransparent")
	}
}

// TestSubmitEncrypted_BodyCap locks in external-review #2: SubmitEncrypted caps the ciphertext body size at
// ingress (a body over maxCiphertextBodyBytes=16384 is padding; one at the cap is accepted).
func TestSubmitEncrypted_BodyCap(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	ms := keeper.NewMsgServerImpl(k)
	if err := k.SetParams(ctx, types.Params{EncEnabled: true, Threshold: 1, DecryptDelay: 2}); err != nil {
		t.Fatal(err)
	}
	a := validCtA()
	nonce := make([]byte, threshold.NonceSize)

	over := make([]byte, 16385) // > maxCiphertextBodyBytes
	if _, err := ms.SubmitEncrypted(ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager()),
		&types.MsgSubmitEncrypted{Submitter: "u", A: a, Nonce: nonce, Body: over}); err == nil {
		t.Fatal("a body over the cap must be rejected")
	}
	atCap := make([]byte, 16384) // == maxCiphertextBodyBytes
	if _, err := ms.SubmitEncrypted(ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager()),
		&types.MsgSubmitEncrypted{Submitter: "u", A: a, Nonce: nonce, Body: atCap}); err != nil {
		t.Fatalf("a body exactly at the cap must be accepted: %v", err)
	}
}
