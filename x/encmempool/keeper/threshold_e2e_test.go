package keeper_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// newKeeper wires a keeper over an in-memory store with a test context at the
// given block height.
func newKeeper(t *testing.T, height int64) (keeper.Keeper, sdk.Context) {
	t.Helper()
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_encmempool")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)
	k := keeper.NewKeeper(runtime.NewKVStoreService(key), nil)
	ctx := testCtx.Ctx.WithBlockHeight(height).WithEventManager(sdk.NewEventManager()).
		WithConsensusParams(cmtproto.ConsensusParams{Abci: &cmtproto.ABCIParams{VoteExtensionsEnableHeight: 1}})
	return k, ctx
}

func enableParams(pub []byte, t, delay uint64, keypers []string) types.Params {
	return types.Params{
		RevealDelay: 1, MaxRevealWindow: 100,
		EncEnabled: true, ThresholdPub: pub, Threshold: uint32(t),
		Keypers: keypers, DecryptDelay: delay,
	}
}

// Full path: encrypt -> submit -> keypers post >= t shares -> BeginBlock decrypts
// and emits the exact plaintext, in order. This is the encrypted mempool working.
func TestEncryptedMempool_EndToEnd(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2) // 3 keypers, need 2
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("buy 1000 ETH at market — searchers can't front-run this")
	ct, err := threshold.Encrypt(pub, plain)
	if err != nil {
		t.Fatal(err)
	}

	keypers := []string{"cosmosKEYPER1", "cosmosKEYPER2", "cosmosKEYPER3"}
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, enableParams(pub, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}

	// submit the ciphertext at height 10 -> matures at height 12
	e := k.SubmitEncTx(ctx, "cosmosUSER", 10, 2, ct.A, ct.Nonce, ct.Body, 0)
	if e.DecryptHeight != 12 {
		t.Fatalf("expected decrypt height 12, got %d", e.DecryptHeight)
	}

	// keypers 1 and 3 each compute + post their share (any 2 of 3)
	for _, i := range []int{0, 2} {
		ds, err := threshold.ComputeShare(shares[i], ct)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.SetEncShare(ctx, types.EncShare{
			Keyper: keypers[i], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// run BeginBlock at the decrypt height
	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bctx); err != nil {
		t.Fatal(err)
	}

	// the chain must have decrypted the body and emitted the exact plaintext
	got, ok := decryptedPlaintext(bctx)
	if !ok {
		t.Fatal("no encmempool_decrypted event — BeginBlock did not decrypt")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted plaintext mismatch:\n got %q\nwant %q", got, plain)
	}
}

// With fewer than t shares, the chain MUST NOT decrypt (the anti-MEV guarantee at
// the module level).
func TestEncryptedMempool_InsufficientSharesNotDecrypted(t *testing.T) {
	pub, shares, _ := threshold.Setup(3, 2)
	ct, _ := threshold.Encrypt(pub, []byte("still secret"))
	keypers := []string{"k1", "k2", "k3"}

	k, ctx := newKeeper(t, 10)
	_ = k.SetParams(ctx, enableParams(pub, 2, 2, keypers))
	e := k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 0)

	// only ONE share (< t=2)
	ds, _ := threshold.ComputeShare(shares[0], ct)
	_ = k.SetEncShare(ctx, types.EncShare{Keyper: keypers[0], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D})

	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	_ = k.BeginBlock(bctx)

	if _, ok := decryptedPlaintext(bctx); ok {
		t.Fatal("SECURITY FAILURE: decrypted with < t shares")
	}
	if !hasEvent(bctx, "encmempool_decrypt_missed") {
		t.Fatal("expected encmempool_decrypt_missed event")
	}
}

// When disabled (EncEnabled=false), BeginBlock must ignore the encrypted path.
func TestEncryptedMempool_DisabledIsInert(t *testing.T) {
	pub, shares, _ := threshold.Setup(3, 2)
	ct, _ := threshold.Encrypt(pub, []byte("x"))
	k, ctx := newKeeper(t, 10)
	p := enableParams(pub, 2, 2, []string{"k1", "k2", "k3"})
	p.EncEnabled = false // OFF
	_ = k.SetParams(ctx, p)
	e := k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 0)
	for _, i := range []int{0, 1} {
		ds, _ := threshold.ComputeShare(shares[i], ct)
		_ = k.SetEncShare(ctx, types.EncShare{Keyper: "k", DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D})
	}
	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	_ = k.BeginBlock(bctx)
	if _, ok := decryptedPlaintext(bctx); ok {
		t.Fatal("disabled module must not decrypt")
	}
}

func decryptedPlaintext(ctx sdk.Context) ([]byte, bool) {
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type != "encmempool_decrypted" {
			continue
		}
		for _, a := range ev.Attributes {
			if a.Key == "plaintext_hex" {
				b, err := hex.DecodeString(a.Value)
				if err == nil {
					return b, true
				}
			}
		}
	}
	return nil, false
}

func hasEvent(ctx sdk.Context, typ string) bool {
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type == typ {
			return true
		}
	}
	return false
}
