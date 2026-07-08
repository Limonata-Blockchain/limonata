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
	k, ctx := newKeeper(t, 10)
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

// Sanity: the same guard does not block DISTINCT slots (a keyper legitimately owning
// several eval-points, or different ciphertexts, still stores each once).
func TestLegacyDecryptionShareDistinctSlotsOK(t *testing.T) {
	k, ctx := newKeeper(t, 10)
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
