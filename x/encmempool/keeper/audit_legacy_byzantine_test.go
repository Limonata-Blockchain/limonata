package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// round-12 #4: the legacy trusted-setup path must tolerate a BYZANTINE keyper. A bad first share
// (valid point, wrong value) previously poisoned the first-`need` combine -> wrong AES key -> the
// ciphertext was consumed on decrypt failure. Robust recovery now tries share combinations and uses
// the one whose GCM decryption authenticates, so the two honest shares still decrypt the tx.
func TestLegacyRecover_ToleratesByzantineFirstShare(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2) // 3 keypers, need 2
	require.NoError(t, err)
	plain := []byte("legacy byzantine-safe decrypt path")
	ct, err := threshold.Encrypt(pub, plain)
	require.NoError(t, err)

	keypers := []string{"kp1", "kp2", "kp3"}
	k, ctx := newKeeper(t, 10)
	require.NoError(t, k.SetParams(ctx, enableParams(pub, 2, 2, keypers)))
	e := k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 0)

	// a valid-but-WRONG point for the byzantine keyper's share.
	badPriv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	badD := badPriv.PubKey().SerializeCompressed()

	for i := 0; i < 3; i++ {
		ds, derr := threshold.ComputeShare(shares[i], ct)
		require.NoError(t, derr)
		D := ds.D
		if i == 0 {
			D = badD // keyper 1 is byzantine: submits a well-formed but wrong share
		}
		require.NoError(t, k.SetEncShare(ctx, types.EncShare{
			Keyper: keypers[i], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: D,
		}))
	}

	bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	require.NoError(t, k.BeginBlock(bctx))

	n, ok := decryptedLen(bctx)
	require.True(t, ok, "must decrypt via the two honest shares despite a byzantine first share")
	require.Equal(t, len(plain), n)
}
