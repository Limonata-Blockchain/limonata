package encmempool_readiness_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	evmd "github.com/cosmos/evm/evmd"
	"github.com/cosmos/evm/testutil"
	testconstants "github.com/cosmos/evm/testutil/constants"
	"github.com/cosmos/evm/x/encmempool/dkg"
	encmempoolkeeper "github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

type dkgMember struct {
	op, acc string
	priv    *secp256k1.ModNScalar
	pub     []byte
	index   uint64
}

func newDkgMember(op, acc string) dkgMember {
	pk, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	priv := new(secp256k1.ModNScalar)
	priv.Set(&pk.Key)
	return dkgMember{op: op, acc: acc, priv: priv, pub: pk.PubKey().SerializeCompressed()}
}

// TestReadiness_FullValidatorDKGThenExecute is the READINESS proof for v0.3.0 activation of the full
// path: a validator committee runs the DKG (no trusted setup, no single key holder) to install a
// threshold key, a user submits a REAL signed EVM transaction encrypted to that key, t committee
// members post DLEQ-proved decryption shares, and BeginBlock DECRYPTS AND EXECUTES the tx on the live
// evmd app. Unlike the keeper-level DKG test (decrypt only, nil evmKeeper) and the legacy re-injection
// test (trusted key), this exercises the whole activated stack end to end: DKG key + threshold decrypt
// + EncExec re-injection.
func TestReadiness_FullValidatorDKGThenExecute(t *testing.T) {
	c := testconstants.ExampleChainID
	app := evmd.Setup(t, c.ChainID, c.EVMChainID)
	denom := evmtypes.GetEVMCoinDenom()
	k := app.EncMempoolKeeper
	ms := encmempoolkeeper.NewMsgServerImpl(k)

	ctx := app.NewContext(false).WithBlockHeight(1).WithChainID(c.ChainID)

	// The DKG committee is the chain's BONDED VALIDATOR SET (ActiveMembers intersects declared members
	// with the bonded set). evmd.Setup bonds ONE validator, so this runs a 1-member committee on the
	// REAL app - proving the DKG-key -> decrypt -> EXECUTE bridge end to end. The multi-party threshold
	// crypto (3-of-2, dealer/complaint/finalize) is proven separately at the keeper level in
	// x/encmempool/keeper TestOnChainDKG_FinalizeAndDecrypt; here the point is the full activated stack
	// on the live evmd app (DKG key + EncExec), which neither that test (nil evmKeeper) nor the legacy
	// re-injection test (trusted key) exercises.
	var valOper string
	require.NoError(t, app.StakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		valOper = v.GetOperator()
		return true // first one
	}))
	require.NotEmpty(t, valOper, "the test app must have a bonded validator to form the committee")

	const n, thr = 1, 1
	m0 := newDkgMember(valOper, "acc1")
	members := []dkgMember{m0}
	declared := []encmempooltypes.DkgMember{{OperatorAddr: valOper, AccountAddr: "acc1", EncPubKey: m0.pub}}
	require.NoError(t, k.SetParams(ctx, encmempooltypes.Params{
		RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: true, EncExecEnabled: true, DecryptDelay: 2,
		MaxInFlightEncTx: 1024,
		DkgEnabled:       true, DkgStartHeight: 1, DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: thr,
		DkgMembers: declared,
	}))

	// height 1: EndBlocker opens epoch 1.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	require.True(t, ok, "epoch 1 must open")
	require.Equal(t, encmempooltypes.DkgStatusOpen, round.Status)
	idxByAcc := map[string]uint64{}
	for _, rm := range round.Members {
		idxByAcc[rm.AccountAddr] = rm.Index
	}
	for i := range members {
		members[i].index = idxByAcc[members[i].acc]
	}
	allIdx := []uint64{1}

	// height 2: every member deals on-chain; keep the ciphertexts each member is addressed so it can
	// later derive its own share (the exact production flow, no secret leaves a node).
	dealCtx := ctx.WithBlockHeight(2)
	shareTo := map[uint64]map[uint64]*threshold.Ciphertext{}
	for _, dealer := range members {
		commitments, shares, err := dkg.Deal(dealer.index, allIdx, thr, rand.Reader)
		require.NoError(t, err)
		shareTo[dealer.index] = map[uint64]*threshold.Ciphertext{}
		enc := make([]*encmempooltypes.DkgEncShare, 0, n)
		for _, recip := range members {
			ct, err := dkg.EncryptShareTo(recip.pub, shares[recip.index])
			require.NoError(t, err)
			shareTo[dealer.index][recip.index] = ct
			enc = append(enc, &encmempooltypes.DkgEncShare{MemberIndex: recip.index, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
		}
		_, err = ms.DkgDeal(dealCtx, &encmempooltypes.MsgDkgDeal{Dealer: dealer.acc, Epoch: 1, Commitments: commitments, EncShares: enc})
		require.NoError(t, err)
	}

	// height 5 (complaint deadline): finalize -> the aggregate threshold key is installed.
	finCtx := ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(finCtx)
	ak, ok := k.GetActiveKey(finCtx, 1)
	require.True(t, ok, "no active threshold key after finalize")
	require.Len(t, ak.Qual, n, "all honest dealers must be QUAL")
	require.Equal(t, uint64(1), k.GetActiveEpoch(finCtx))

	// each member derives its final share X_m = sum over QUAL of f_dealer(m).
	derived := map[uint64]*secp256k1.ModNScalar{}
	for _, m := range members {
		X := new(secp256k1.ModNScalar)
		first := true
		for _, dealer := range ak.Qual {
			s, err := dkg.DecryptShareFrom(m.priv, m.index, shareTo[dealer][m.index])
			require.NoError(t, err)
			if first {
				X.Set(s)
				first = false
			} else {
				X.Add(s)
			}
		}
		derived[m.index] = X
	}

	// A funded EOA + a REAL signed EVM value transfer (this is the tx we will encrypt to the DKG key).
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	sender := crypto.PubkeyToAddress(key.PublicKey)
	require.NoError(t, testutil.FundAccount(finCtx, app.BankKeeper, sdk.AccAddress(sender.Bytes()),
		sdk.NewCoins(sdk.NewCoin(denom, math.NewInt(1_000_000_000_000_000_000)))))
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000ff")
	value := big.NewInt(12345)
	ethSigner := ethtypes.LatestSignerForChainID(evmtypes.GetEthChainConfig().ChainID)
	ethTx, err := ethtypes.SignTx(ethtypes.NewTx(&ethtypes.LegacyTx{
		Nonce: 0, To: &recipient, Value: value, Gas: 21000, GasPrice: big.NewInt(1_000_000_000),
	}), ethSigner, key)
	require.NoError(t, err)
	rlp, err := ethTx.MarshalBinary()
	require.NoError(t, err)

	// Encrypt the tx to the DKG THRESHOLD key + submit it (the anti-MEV submission).
	submitter := sdk.AccAddress(sender.Bytes()).String()
	ct, ctR, err := threshold.EncryptWithR(ak.Pub, rlp)
	require.NoError(t, err)
	submitCtx := finCtx.WithBlockHeight(6)
	_, err = ms.SubmitEncrypted(submitCtx, &encmempooltypes.MsgSubmitEncrypted{
		Submitter: submitter, A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
		Pok: dkg.ProveEncKeyPoK(ctR, submitCtx.ChainID(), submitter, ct.A, ct.Nonce, ct.Body).Marshal(),
	})
	require.NoError(t, err, "encrypted submit to the DKG key must be accepted (committee is balanced/declared)")

	e, ok := k.GetEncTx(submitCtx, 8, findEncSeq(t, k, submitCtx, 8))
	require.True(t, ok, "enc tx must be stored")
	require.Equal(t, uint64(1), e.Epoch, "stamped to the DKG epoch")

	// t committee members post DLEQ-proved decryption shares at maturity.
	shareCtx := finCtx.WithBlockHeight(int64(e.DecryptHeight))
	for _, m := range members[:thr] {
		ds, proof, err := dkg.ProveDecryptShare(threshold.Share{Index: m.index, Xi: derived[m.index]}, ct)
		require.NoError(t, err)
		_, err = ms.SubmitDecryptionShare(shareCtx, &encmempooltypes.MsgSubmitDecryptionShare{
			Keyper: m.acc, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: m.index,
			D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
		})
		require.NoError(t, err)
	}

	// BeginBlock at maturity: decrypt via the DKG committee AND EXECUTE the EVM tx.
	senderBefore := app.EVMKeeper.GetBalance(shareCtx, sender).ToBig()
	recipBefore := app.EVMKeeper.GetBalance(shareCtx, recipient).ToBig()
	require.Equal(t, uint64(0), app.EVMKeeper.GetNonce(shareCtx, sender))

	bctx := shareCtx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
	require.NoError(t, k.BeginBlock(bctx))

	// THE readiness assertion: the tx decrypted from the DKG key EXECUTED on the EVM.
	exec, _ := reinjectAttr(bctx, "executed")
	require.Equal(t, "true", exec, "the decrypted tx must EXECUTE (full DKG + EncExec path)")
	require.Equal(t, value, new(big.Int).Sub(app.EVMKeeper.GetBalance(bctx, recipient).ToBig(), recipBefore),
		"recipient credited the value via the DKG-decrypted tx")
	require.Equal(t, uint64(1), app.EVMKeeper.GetNonce(bctx, sender), "sender nonce incremented")
	spent := new(big.Int).Sub(senderBefore, app.EVMKeeper.GetBalance(bctx, sender).ToBig())
	require.Equal(t, new(big.Int).Add(value, new(big.Int).Mul(big.NewInt(21000), big.NewInt(1_000_000_000))), spent,
		"sender charged exactly value + gas")
	_, still := k.GetEncTx(bctx, e.DecryptHeight, e.Seq)
	require.False(t, still, "ciphertext consumed after execution")
}

// findEncSeq returns the seq of the single enc tx stored at decryptHeight (test helper).
func findEncSeq(t *testing.T, k encmempoolkeeper.Keeper, ctx sdk.Context, decryptHeight uint64) uint64 {
	t.Helper()
	var seq uint64
	found := false
	k.IterateEncTxAtHeight(ctx, decryptHeight, func(e encmempooltypes.EncTx) {
		seq = e.Seq
		found = true
	})
	require.True(t, found, "no enc tx at height %d", decryptHeight)
	return seq
}

// reinjectAttr returns an attribute of the encmempool_tx_reinjected event, if present.
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
