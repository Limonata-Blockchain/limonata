package encmempool_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/math"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	evmd "github.com/cosmos/evm/evmd"
	"github.com/cosmos/evm/testutil"
	testconstants "github.com/cosmos/evm/testutil/constants"
	"github.com/cosmos/evm/x/encmempool/dkg"
	encmempoolkeeper "github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// The EVM global-config singleton can be configured only ONCE per process, so evmd.Setup runs once
// and every subtest shares the app with its own fresh context + random keys (state does not bleed:
// each subtest re-sets params and uses a distinct sender). These tests drive the REAL BeginBlock
// decrypt->execute path on the full evmd app - the P4 validation of the re-injection pipeline.

func newExecCtx(app *evmd.EVMD) sdk.Context {
	// A fresh test ctx carries no consensus params; the re-injection gas ceiling needs a block
	// MaxGas or it computes 0 and skips execution.
	return app.NewContext(false).
		WithBlockHeight(10).
		WithChainID(testconstants.ExampleChainID.ChainID).
		WithConsensusParams(cmtproto.ConsensusParams{Block: &cmtproto.BlockParams{MaxGas: 100_000_000}})
}

func encParams(pub []byte, keypers []string, exec bool) encmempooltypes.Params {
	return encmempooltypes.Params{
		RevealDelay: 1, MaxRevealWindow: 1_000_000,
		EncEnabled: true, EncExecEnabled: exec,
		ThresholdPub: pub, Threshold: 2, Keypers: keypers, DecryptDelay: 2,
		MaxInFlightEncTx: 1024,
	}
}

// submitAndShare encrypts `rlp` to `pub`, submits it (with the submitter-bound PoK), and stores
// t=2 legacy decryption shares at the maturity height. Returns the matured EncTx.
func submitAndShare(t *testing.T, app *evmd.EVMD, ctx sdk.Context, pub []byte, shares []threshold.Share, keypers []string, rlp []byte, submitter string) encmempooltypes.EncTx {
	t.Helper()
	ct, pok, err := dkg.EncryptWithPoK(pub, rlp, submitter)
	require.NoError(t, err)
	ms := encmempoolkeeper.NewMsgServerImpl(app.EncMempoolKeeper)
	resp, err := ms.SubmitEncrypted(ctx, &encmempooltypes.MsgSubmitEncrypted{
		Submitter: submitter, A: ct.A, Nonce: ct.Nonce, Body: ct.Body, Pok: pok.Marshal(),
	})
	require.NoError(t, err)
	// Seq is a GLOBAL counter that persists across subtests sharing the app, so use the returned one.
	e, ok := app.EncMempoolKeeper.GetEncTx(ctx, resp.DecryptHeight, resp.Seq)
	require.True(t, ok, "ciphertext must be stored")
	require.Equal(t, uint64(0), e.Epoch)
	for _, i := range []int{0, 2} {
		ds, err := threshold.ComputeShare(shares[i], &threshold.Ciphertext{A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		require.NoError(t, err)
		require.NoError(t, app.EncMempoolKeeper.SetEncShare(ctx, encmempooltypes.EncShare{
			Keyper: keypers[i], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D,
		}))
	}
	return e
}

func reinjectAttr(ctx sdk.Context, key string) (string, bool) {
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type == "encmempool_tx_reinjected" {
			for _, a := range ev.Attributes {
				if a.Key == key {
					return a.Value, true
				}
			}
		}
	}
	return "", false
}

func TestReinjection(t *testing.T) {
	c := testconstants.ExampleChainID
	app := evmd.Setup(t, c.ChainID, c.EVMChainID) // ONCE per process
	denom := evmtypes.GetEVMCoinDenom()
	keypers := []string{"kp1", "kp2", "kp3"}
	ethSigner := ethtypes.LatestSignerForChainID(evmtypes.GetEthChainConfig().ChainID)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000ff")

	// fundSender generates a fresh EOA and funds it 1e18.
	fundSender := func(ctx sdk.Context) (common.Address, string, func(nonce uint64, value *big.Int) []byte) {
		key, err := crypto.GenerateKey()
		require.NoError(t, err)
		addr := crypto.PubkeyToAddress(key.PublicKey)
		require.NoError(t, testutil.FundAccount(ctx, app.BankKeeper, sdk.AccAddress(addr.Bytes()),
			sdk.NewCoins(sdk.NewCoin(denom, math.NewInt(1_000_000_000_000_000_000)))))
		mkTx := func(nonce uint64, value *big.Int) []byte {
			txdata := &ethtypes.LegacyTx{Nonce: nonce, To: &recipient, Value: value, Gas: 21000, GasPrice: big.NewInt(1_000_000_000)}
			ethTx, err := ethtypes.SignTx(ethtypes.NewTx(txdata), ethSigner, key)
			require.NoError(t, err)
			rlp, err := ethTx.MarshalBinary()
			require.NoError(t, err)
			return rlp
		}
		return addr, sdk.AccAddress(addr.Bytes()).String(), mkTx
	}

	// (1) HAPPY PATH: a decrypted transfer executes, fees are sound, nonce increments, no re-run.
	t.Run("end_to_end_execute_and_fee_accounting", func(t *testing.T) {
		ctx := newExecCtx(app)
		pub, shares, err := threshold.Setup(3, 2)
		require.NoError(t, err)
		require.NoError(t, app.EncMempoolKeeper.SetParams(ctx, encParams(pub, keypers, true)))
		sender, submitter, mkTx := fundSender(ctx)
		value := big.NewInt(1000)
		gasPrice := big.NewInt(1_000_000_000)

		e := submitAndShare(t, app, ctx, pub, shares, keypers, mkTx(0, value), submitter)

		feeColl := authtypes.NewModuleAddress(authtypes.FeeCollectorName)
		recipBefore := app.EVMKeeper.GetBalance(ctx, recipient).ToBig()
		senderBefore := app.EVMKeeper.GetBalance(ctx, sender).ToBig()
		feeBefore := app.BankKeeper.GetBalance(ctx, feeColl, denom).Amount.BigInt()
		require.Equal(t, uint64(0), app.EVMKeeper.GetNonce(ctx, sender))

		bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
		require.NoError(t, app.EncMempoolKeeper.BeginBlock(bctx))

		exec, _ := reinjectAttr(bctx, "executed")
		rev, _ := reinjectAttr(bctx, "reverted")
		require.Equal(t, "true", exec, "the decrypted tx must execute")
		require.Equal(t, "false", rev, "a simple transfer must not revert")

		recipAfter := app.EVMKeeper.GetBalance(bctx, recipient).ToBig()
		require.Equal(t, value, new(big.Int).Sub(recipAfter, recipBefore), "recipient credited the value")
		require.Equal(t, uint64(1), app.EVMKeeper.GetNonce(bctx, sender), "nonce increments (no replay)")

		spent := new(big.Int).Sub(senderBefore, app.EVMKeeper.GetBalance(bctx, sender).ToBig())
		expected := new(big.Int).Add(value, new(big.Int).Mul(big.NewInt(21000), gasPrice))
		require.Equal(t, expected, spent, "sender charged exactly value + gasUsed*gasPrice")
		feeAfter := app.BankKeeper.GetBalance(bctx, feeColl, denom).Amount.BigInt()
		require.True(t, feeAfter.Cmp(feeBefore) >= 0, "fee collector NOT drained (%s -> %s)", feeBefore, feeAfter)

		_, stillThere := app.EncMempoolKeeper.GetEncTx(bctx, e.DecryptHeight, e.Seq)
		require.False(t, stillThere, "ciphertext consumed after execution")
		b13 := ctx.WithBlockHeight(13).WithEventManager(sdk.NewEventManager())
		require.NoError(t, app.EncMempoolKeeper.BeginBlock(b13))
		require.Equal(t, recipAfter, app.EVMKeeper.GetBalance(b13, recipient).ToBig(), "no double execution")
	})

	// (2) A wrong nonce is rejected (replay / strict-ordering guard) - no execution, no state change.
	t.Run("wrong_nonce_rejected", func(t *testing.T) {
		ctx := newExecCtx(app)
		pub, shares, _ := threshold.Setup(3, 2)
		require.NoError(t, app.EncMempoolKeeper.SetParams(ctx, encParams(pub, keypers, true)))
		sender, submitter, mkTx := fundSender(ctx)

		submitAndShare(t, app, ctx, pub, shares, keypers, mkTx(5, big.NewInt(1000)), submitter) // nonce 5, seq 0

		recipBefore := app.EVMKeeper.GetBalance(ctx, recipient).ToBig()
		bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
		require.NoError(t, app.EncMempoolKeeper.BeginBlock(bctx))

		tag, found := reinjectAttr(bctx, "outcome")
		require.True(t, found)
		require.Equal(t, "bad_nonce", tag)
		require.Equal(t, uint64(0), app.EVMKeeper.GetNonce(bctx, sender), "nonce unchanged on reject")
		require.Equal(t, recipBefore, app.EVMKeeper.GetBalance(bctx, recipient).ToBig(), "no transfer on reject")
	})

	// (3) EncExecEnabled=false: decrypt + consume, NEVER execute, NEVER reveal plaintext.
	t.Run("disabled_does_not_execute", func(t *testing.T) {
		ctx := newExecCtx(app)
		pub, shares, _ := threshold.Setup(3, 2)
		require.NoError(t, app.EncMempoolKeeper.SetParams(ctx, encParams(pub, keypers, false))) // exec OFF
		sender, submitter, mkTx := fundSender(ctx)

		e := submitAndShare(t, app, ctx, pub, shares, keypers, mkTx(0, big.NewInt(1000)), submitter)

		bctx := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
		require.NoError(t, app.EncMempoolKeeper.BeginBlock(bctx))

		if _, found := reinjectAttr(bctx, "outcome"); found {
			t.Fatal("execution disabled: no encmempool_tx_reinjected event may fire")
		}
		require.Equal(t, uint64(0), app.EVMKeeper.GetNonce(bctx, sender), "no execution => nonce unchanged")
		_, stillThere := app.EncMempoolKeeper.GetEncTx(bctx, e.DecryptHeight, e.Seq)
		require.False(t, stillThere, "ciphertext consumed even without execution")
	})
}
