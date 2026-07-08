package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// Finding 8: on the legacy (non-transparent) tx share path, SubmitDecryptionShare has no
// ingress DLEQ check and SetEncShare overwrites the eval-point slot. Without write-once,
// an authorized keyper could post a valid share, then OVERWRITE it with garbage before
// maturity to retract its contribution and strand the ciphertext. This pins first-wins:
// the first submit is stored, the overwrite is rejected, and the stored value is unchanged.
func TestLegacyDecryptionShareWriteOnce(t *testing.T) {
	k, ctx := newKeeper(t, 12)
	keypers := []string{"cosmosKEYPER1", "cosmosKEYPER2", "cosmosKEYPER3"}
	// Legacy keyper path: EncEnabled, DkgEnabled=false, DkgTransparent=false. SetParams does
	// not run Validate, so the exact threshold-pub bytes are irrelevant to this path.
	if err := k.SetParams(ctx, enableParams([]byte{0x02, 0x01}, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}
	ms := keeper.NewMsgServerImpl(k)

	first := &types.MsgSubmitDecryptionShare{
		Keyper: keypers[0], DecryptHeight: 12, Seq: 0, Index: 1, D: []byte{0x01, 0x02, 0x03},
	}
	if _, err := ms.SubmitDecryptionShare(ctx, first); err != nil {
		t.Fatalf("first submit must succeed: %v", err)
	}

	// Overwrite attempt with different bytes at the SAME (height, seq, index): must be rejected.
	overwrite := &types.MsgSubmitDecryptionShare{
		Keyper: keypers[0], DecryptHeight: 12, Seq: 0, Index: 1, D: []byte{0x09, 0x09, 0x09},
	}
	if _, err := ms.SubmitDecryptionShare(ctx, overwrite); err == nil {
		t.Fatal("overwrite of an already-recorded share must be rejected (write-once)")
	}

	// The stored share must still be the FIRST one.
	shares := k.CollectShares(ctx, 12, 0)
	if len(shares) != 1 {
		t.Fatalf("expected exactly 1 stored share, got %d", len(shares))
	}
	if string(shares[0].D) != string([]byte{0x01, 0x02, 0x03}) {
		t.Fatalf("stored share was overwritten: got D=%x, want 010203", shares[0].D)
	}
}

// CRITICAL maturity gate (anti-MEV confidentiality): a decryption share for a ciphertext that
// has NOT matured (decrypt_height > current height) must be REJECTED at ingress. A stored share
// is public state and t of them reconstruct the AES key, so accepting an early share would let
// any observer decrypt the body before its decrypt_height. The same share is accepted once the
// height reaches maturity.
func TestDecryptionShareRejectedBeforeMaturity(t *testing.T) {
	keypers := []string{"cosmosKEYPER1", "cosmosKEYPER2", "cosmosKEYPER3"}
	share := &types.MsgSubmitDecryptionShare{
		Keyper: keypers[0], DecryptHeight: 12, Seq: 0, Index: 1, D: []byte{0x01},
	}

	// At height 10, a share for a ciphertext maturing at 12 is too early -> rejected, nothing stored.
	kEarly, ctxEarly := newKeeper(t, 10)
	if err := kEarly.SetParams(ctxEarly, enableParams([]byte{0x02, 0x01}, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}
	msEarly := keeper.NewMsgServerImpl(kEarly)
	if _, err := msEarly.SubmitDecryptionShare(ctxEarly, share); err == nil {
		t.Fatal("a share for a not-yet-matured ciphertext (decrypt_height 12 > height 10) must be rejected")
	}
	if n := len(kEarly.CollectShares(ctxEarly, 12, 0)); n != 0 {
		t.Fatalf("no share may be stored before maturity, got %d", n)
	}

	// At height 12 (maturity), the same share is accepted.
	kMature, ctxMature := newKeeper(t, 12)
	if err := kMature.SetParams(ctxMature, enableParams([]byte{0x02, 0x01}, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}
	msMature := keeper.NewMsgServerImpl(kMature)
	if _, err := msMature.SubmitDecryptionShare(ctxMature, share); err != nil {
		t.Fatalf("a share at/after maturity must be accepted: %v", err)
	}
	if n := len(kMature.CollectShares(ctxMature, 12, 0)); n != 1 {
		t.Fatalf("matured share must be stored, got %d", n)
	}
}

// CRITICAL same-A binding at ingress: SubmitEncrypted rejects a ciphertext without a valid
// submitter-bound PoK, and rejects a copied A + PoK submitted under a different address (the
// same-A replay). A genuine submission is accepted.
func TestSubmitEncryptedRequiresSubmitterBoundPoK(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, enableParams(throwawayThresholdPub(t), 1, 1, []string{"kp1"})); err != nil {
		t.Fatal(err)
	}
	ms := keeper.NewMsgServerImpl(k)
	pub := throwawayThresholdPub(t)

	// (a) missing PoK -> rejected.
	good := encWithPoK(t, pub, "hi", "cosmos1victim")
	noPoK := &types.MsgSubmitEncrypted{Submitter: good.Submitter, A: good.A, Nonce: good.Nonce, Body: good.Body}
	if _, err := ms.SubmitEncrypted(ctx, noPoK); err == nil {
		t.Fatal("a submission without a PoK must be rejected")
	}

	// (b) the victim's genuine submission is accepted.
	if _, err := ms.SubmitEncrypted(ctx, good); err != nil {
		t.Fatalf("a genuine submission must be accepted: %v", err)
	}

	// (c) SAME-A REPLAY: attacker copies the victim's A + PoK under its own address -> rejected.
	replay := &types.MsgSubmitEncrypted{Submitter: "cosmos1attacker", A: good.A, Nonce: good.Nonce, Body: good.Body, Pok: good.Pok}
	if _, err := ms.SubmitEncrypted(ctx, replay); err == nil {
		t.Fatal("same-A replay (copied A+PoK under a different submitter) must be rejected")
	}
}

// Sanity: the same guard does not block DISTINCT slots (a keyper legitimately owning
// several eval-points, or different ciphertexts, still stores each once).
func TestLegacyDecryptionShareDistinctSlotsOK(t *testing.T) {
	k, ctx := newKeeper(t, 12)
	keypers := []string{"cosmosKEYPER1", "cosmosKEYPER2", "cosmosKEYPER3"}
	if err := k.SetParams(ctx, enableParams([]byte{0x02, 0x01}, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}
	ms := keeper.NewMsgServerImpl(k)
	submit := func(kp string, h, seq, idx uint64) error {
		_, err := ms.SubmitDecryptionShare(ctx, &types.MsgSubmitDecryptionShare{
			Keyper: kp, DecryptHeight: h, Seq: seq, Index: idx, D: []byte{0xAA},
		})
		return err
	}
	if err := submit(keypers[0], 12, 0, 1); err != nil {
		t.Fatalf("slot (12,0,1): %v", err)
	}
	if err := submit(keypers[1], 12, 0, 2); err != nil {
		t.Fatalf("distinct index (12,0,2): %v", err)
	}
	if err := submit(keypers[0], 12, 1, 1); err != nil {
		t.Fatalf("distinct seq (12,1,1): %v", err)
	}
	var _ sdk.Context = ctx
}
