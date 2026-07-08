// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// member is a test DKG participant: a declared {operator, account} identity plus a
// secp256k1 encryption keypair that shares are sealed to.
type member struct {
	op, acc string
	priv    *secp256k1.ModNScalar
	pub     []byte
	index   uint64 // filled from the opened round
}

func newMember(op, acc string) member {
	pk, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	priv := new(secp256k1.ModNScalar)
	priv.Set(&pk.Key)
	return member{op: op, acc: acc, priv: priv, pub: pk.PubKey().SerializeCompressed()}
}

// TestOnChainDKG_FinalizeAndDecrypt drives the FULL on-chain validator-DKG loop
// through the real message handlers + EndBlocker + BeginBlocker:
//
//	open round -> N validators post dealings -> deterministic Finalize installs the
//	master pubkey -> each member derives its share locally from the ciphertexts
//	addressed to it -> a message encrypted to the DKG pubkey is decrypted on-chain
//	via dkg.RecoverVerified (per-share DLEQ enforced).
//
// It asserts the finalized pubkey equals the independently-recomputed Σ C_{i,0} and
// that the exact plaintext comes back out — i.e. "given N dealings, correct pubkey +
// a member can decrypt".
func TestOnChainDKG_FinalizeAndDecrypt(t *testing.T) {
	const n = 3
	const thr = 2

	members := []member{
		newMember("op1", "acc1"),
		newMember("op2", "acc2"),
		newMember("op3", "acc3"),
	}
	declared := make([]types.DkgMember, n)
	for i, m := range members {
		declared[i] = types.DkgMember{OperatorAddr: m.op, AccountAddr: m.acc, EncPubKey: m.pub}
	}

	k, ctx := newKeeper(t, 1)
	ms := keeper.NewMsgServerImpl(k)
	p := types.Params{
		RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: true, DecryptDelay: 2,
		DkgEnabled: true, DkgStartHeight: 1, DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: thr,
		DkgMembers: declared,
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}

	// --- height 1: EndBlocker opens epoch 1 ---
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok {
		t.Fatal("epoch 1 round was not opened")
	}
	if round.Status != types.DkgStatusOpen || round.Threshold != thr || len(round.Members) != n {
		t.Fatalf("unexpected round: status=%s t=%d members=%d", round.Status, round.Threshold, len(round.Members))
	}
	// learn each member's assigned index
	memberIdx := map[string]uint64{}
	for _, rm := range round.Members {
		memberIdx[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = memberIdx[members[i].acc]
	}
	allIdx := []uint64{1, 2, 3}

	// --- height 2: every member deals on-chain (dealings kept so a member can later
	// reconstruct its own share from the ciphertexts addressed to it) ---
	dealCtx := ctx.WithBlockHeight(2)
	// shareTo[dealerIndex][memberIndex] = ciphertext of f_dealer(member) to that member
	shareTo := map[uint64]map[uint64]*threshold.Ciphertext{}
	for _, dealerM := range members {
		commitments, shares, err := dkg.Deal(dealerM.index, allIdx, thr, rand.Reader)
		if err != nil {
			t.Fatalf("deal: %v", err)
		}
		shareTo[dealerM.index] = map[uint64]*threshold.Ciphertext{}
		encShares := make([]*types.DkgEncShare, 0, n)
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			if err != nil {
				t.Fatalf("encrypt share: %v", err)
			}
			shareTo[dealerM.index][recip.index] = ct
			encShares = append(encShares, &types.DkgEncShare{
				MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
			})
		}
		if _, err := ms.DkgDeal(dealCtx, &types.MsgDkgDeal{
			Dealer: dealerM.acc, Epoch: 1, Commitments: commitments, EncShares: encShares,
		}); err != nil {
			t.Fatalf("DkgDeal(%s): %v", dealerM.acc, err)
		}
	}

	// --- height 5 (== complaint deadline): EndBlocker finalizes ---
	finCtx := ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	if !ok {
		t.Fatal("no active threshold key after finalize")
	}
	if len(ak.Qual) != n {
		t.Fatalf("expected QUAL=%d, got %v", n, ak.Qual)
	}
	if k.GetActiveEpoch(finCtx) != 1 {
		t.Fatalf("active epoch should be 1, got %d", k.GetActiveEpoch(finCtx))
	}

	// independently recompute the expected master pubkey = Σ_{qual} C_{i,0} and check
	// the chain agrees (the finalize is not trusting any single proposer).
	wantPub := sumFirstCommitments(t, k, finCtx)
	if !bytes.Equal(ak.Pub, wantPub) {
		t.Fatalf("finalized pub mismatch:\n got %s\nwant %s", hex.EncodeToString(ak.Pub), hex.EncodeToString(wantPub))
	}

	// --- each member derives its final share X_m = Σ_{i∈QUAL} f_i(m) by decrypting
	// the ciphertexts addressed to it (no secret ever left its node). ---
	derived := map[uint64]*secp256k1.ModNScalar{}
	for _, m := range members {
		X := new(secp256k1.ModNScalar)
		first := true
		for _, dealer := range ak.Qual {
			ct := shareTo[dealer][m.index]
			s, err := dkg.DecryptShareFrom(m.priv, m.index, ct)
			if err != nil {
				t.Fatalf("member %d decrypt share from dealer %d: %v", m.index, dealer, err)
			}
			if first {
				X.Set(s)
				first = false
			} else {
				X.Add(s)
			}
		}
		derived[m.index] = X
	}

	// --- encrypt a secret to the DKG pubkey, submit it, have t members post their
	// DLEQ-proved decryption shares, and let BeginBlock decrypt it. ---
	plain := []byte("validator-DKG anti-MEV: no dealer, no trusted setup, no single key holder")
	ct, ctR, err := threshold.EncryptWithR(ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	submitCtx := ctx.WithBlockHeight(6)
	if _, err := ms.SubmitEncrypted(submitCtx, &types.MsgSubmitEncrypted{
		Submitter: "acc1", A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
		Pok: dkg.ProveEncKeyPoK(ctR, "acc1", ct.A, ct.Nonce, ct.Body).Marshal(),
	}); err != nil {
		t.Fatalf("SubmitEncrypted: %v", err)
	}
	// find the stored enc tx (decrypt height = 6 + 2 = 8)
	e, ok := k.GetEncTx(submitCtx, 8, findSeq(t, k, submitCtx))
	if !ok {
		t.Fatal("enc tx not stored")
	}
	if e.Epoch != 1 {
		t.Fatalf("enc tx epoch should be 1, got %d", e.Epoch)
	}

	// members 1 and 2 (any t) post proved shares. Shares may only be submitted at/after the
	// ciphertext's maturity (the anti-MEV maturity gate), so post them at decrypt_height.
	shareCtx := ctx.WithBlockHeight(int64(e.DecryptHeight))
	for _, m := range members[:thr] {
		ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: m.index, Xi: derived[m.index]}, ct)
		if err != nil {
			t.Fatalf("ProveDecryptShare: %v", err)
		}
		if _, err := ms.SubmitDecryptionShare(shareCtx, &types.MsgSubmitDecryptionShare{
			Keyper: m.acc, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: m.index,
			D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		}); err != nil {
			t.Fatalf("SubmitDecryptionShare(%s): %v", m.acc, err)
		}
	}

	// BeginBlock at the decrypt height decrypts via dkg.RecoverVerified.
	bctx := ctx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatal(err)
	}
	got, ok := decryptedLen(bctx)
	if !ok {
		t.Fatal("no encmempool_decrypted event — DKG decrypt path failed")
	}
	if got != len(plain) {
		t.Fatalf("decrypted plaintext length mismatch: got %d want %d", got, len(plain))
	}
}

// sumFirstCommitments recomputes Σ_{i∈QUAL} C_{i,0} straight from the stored
// dealings (independent of the finalize code path) to cross-check the pubkey.
func sumFirstCommitments(t *testing.T, k keeper.Keeper, ctx sdk.Context) []byte {
	t.Helper()
	ak, _ := k.GetActiveKey(ctx, 1)
	first := [][]byte{}
	qual := map[uint64]bool{}
	for _, q := range ak.Qual {
		qual[q] = true
	}
	k.IterateDealings(ctx, 1, func(d types.Dealing) {
		if qual[d.DealerIndex] {
			first = append(first, d.Commitments[0])
		}
	})
	pubs, err := dkg.ParseCommitmentPoints(first)
	if err != nil {
		t.Fatal(err)
	}
	var acc secp256k1.JacobianPoint
	acc = pubs[0]
	for i := 1; i < len(pubs); i++ {
		var sum secp256k1.JacobianPoint
		secp256k1.AddNonConst(&acc, &pubs[i], &sum)
		acc = sum
	}
	acc.ToAffine()
	return secp256k1.NewPublicKey(&acc.X, &acc.Y).SerializeCompressed()
}

// findSeq returns the seq of the single enc tx stored at decrypt height 8.
func findSeq(t *testing.T, k keeper.Keeper, ctx sdk.Context) uint64 {
	t.Helper()
	var seq uint64
	found := false
	k.IterateEncTxAtHeight(ctx, 8, func(e types.EncTx) { seq = e.Seq; found = true })
	if !found {
		t.Fatal("no enc tx at height 8")
	}
	return seq
}
