package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/types"
)

// round-8 #5: a full DKG/threshold state must survive a genesis export -> import losslessly, and
// the in-flight ref-counts (global / per-submitter / per-epoch) must be RECOMPUTED consistently
// from the imported EncTx set - never imported out of sync. This is the consistency guarantee that
// makes the genesis path safe.
func TestGenesisRoundTrip_DKGState(t *testing.T) {
	src, ctx := newKeeper(t, 10)
	require.NoError(t, src.SetParams(ctx, enableParams([]byte{0x02, 0x01}, 2, 2, []string{"kp1", "kp2"})))

	// in-flight ciphertexts: 2 submitters, epochs {0, 5}
	e1 := src.SubmitEncTx(ctx, "alice", 10, 2, []byte("a1"), []byte("n1"), []byte("b1"), 0)
	e2 := src.SubmitEncTx(ctx, "alice", 10, 2, []byte("a2"), []byte("n2"), []byte("b2"), 5)
	e3 := src.SubmitEncTx(ctx, "bob", 11, 2, []byte("a3"), []byte("n3"), []byte("b3"), 5)
	require.NoError(t, src.SetEncShare(ctx, types.EncShare{Keyper: "kp1", DecryptHeight: e1.DecryptHeight, Seq: e1.Seq, Index: 1, D: []byte("d1")}))
	require.NoError(t, src.SetEncShare(ctx, types.EncShare{Keyper: "kp2", DecryptHeight: e2.DecryptHeight, Seq: e2.Seq, Index: 2, D: []byte("d2")}))

	// a DKG round + installed key + epochs
	require.NoError(t, src.SetDkgRound(ctx, types.DkgRound{
		Epoch: 5, OpenHeight: 1, DealDeadline: 3, ComplaintDeadline: 5, Threshold: 2, Status: "active",
		Members: []types.RoundMember{{Index: 1, OperatorAddr: "op1", AccountAddr: "acc1"}},
	}))
	require.NoError(t, src.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: 5, Pub: []byte("pub5"), Threshold: 2, Qual: []uint64{1, 2}}))
	src.SetCurrentEpoch(ctx, 5)
	src.SetActiveEpoch(ctx, 5)

	// an announced committee enc key (via the real PoP path)
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	encKey := priv.PubKey().SerializeCompressed()
	require.True(t, src.RecordEncPubKey(ctx, "op1", encKey, dkg.SignEncKeyPoP(&priv.Key, "op1")))

	// snapshot the source ref-counts
	wantGlobal := src.GetGlobalEncCount(ctx)
	wantAlice := src.GetSubmitterEncCount(ctx, "alice")
	wantBob := src.GetSubmitterEncCount(ctx, "bob")
	wantEpoch5 := src.GetEpochEncCount(ctx, 5)
	require.Equal(t, uint64(3), wantGlobal)
	require.Equal(t, uint64(2), wantAlice)
	require.Equal(t, uint64(1), wantBob)
	require.Equal(t, uint64(2), wantEpoch5)

	// export (must NOT panic even with in-flight ciphertexts) -> import into a FRESH keeper
	gs := src.ExportGenesis(ctx)
	require.Equal(t, 3, len(gs.EncTxs))
	require.Equal(t, 2, len(gs.EncShares))
	require.Equal(t, 1, len(gs.DkgRounds))
	require.Equal(t, 1, len(gs.ActiveKeys))
	require.Equal(t, 1, len(gs.EncKeys))

	dst, ctx2 := newKeeper(t, 20)
	require.NoError(t, dst.InitGenesis(ctx2, *gs))

	// state preserved
	got1, ok := dst.GetEncTx(ctx2, e1.DecryptHeight, e1.Seq)
	require.True(t, ok)
	require.Equal(t, "alice", got1.Submitter)
	require.Len(t, dst.CollectShares(ctx2, e2.DecryptHeight, e2.Seq), 1)
	r, ok := dst.GetDkgRound(ctx2, 5)
	require.True(t, ok)
	require.Equal(t, "active", r.Status)
	ak, ok := dst.GetActiveKey(ctx2, 5)
	require.True(t, ok)
	require.Equal(t, []byte("pub5"), ak.Pub)
	require.Equal(t, uint64(5), dst.GetCurrentEpoch(ctx2))
	require.Equal(t, uint64(5), dst.GetActiveEpoch(ctx2))
	gotKey, ok := dst.GetEncPubKey(ctx2, "op1")
	require.True(t, ok)
	require.Equal(t, encKey, gotKey)
	owner, ok := dst.GetEncKeyOwner(ctx2, encKey)
	require.True(t, ok)
	require.Equal(t, "op1", owner)

	// THE consistency guarantee: recomputed ref-counts match the source EXACTLY.
	require.Equal(t, wantGlobal, dst.GetGlobalEncCount(ctx2), "global ref-count must be recomputed consistently")
	require.Equal(t, wantAlice, dst.GetSubmitterEncCount(ctx2, "alice"))
	require.Equal(t, wantBob, dst.GetSubmitterEncCount(ctx2, "bob"))
	require.Equal(t, wantEpoch5, dst.GetEpochEncCount(ctx2, 5))

	// the seq counter resumes past the imported max (no collision on the next submit).
	e4 := dst.SubmitEncTx(ctx2, "carol", 20, 2, []byte("a4"), []byte("n4"), []byte("b4"), 0)
	require.Greater(t, e4.Seq, e3.Seq, "seq counter must resume past the imported max seq")
}

// round-11 #5 (SECURITY): a genesis must NEVER be able to assert a decryption share is already
// DLEQ-verified - recovery would then skip the crypto check and a bad imported share would corrupt
// decryption. Validate rejects Verified=true, and InitGenesis force-clears it as belt-and-suspenders.
func TestGenesis_NeverTrustsImportedVerifiedShare(t *testing.T) {
	gs := types.DefaultGenesisState()
	gs.EncShares = []types.EncShare{{Keyper: "k", DecryptHeight: 12, Seq: 0, Index: 1, D: []byte("d"), Verified: true}}
	require.Error(t, gs.Validate(), "a genesis asserting a pre-verified share must be rejected")

	// Even if Validate is bypassed, InitGenesis must force Verified=false so recovery re-verifies.
	dst, ctx := newKeeper(t, 20)
	require.NoError(t, dst.InitGenesis(ctx, *gs))
	got := dst.CollectShares(ctx, 12, 0)
	require.Len(t, got, 1)
	require.False(t, got[0].Verified, "an imported share must never be trusted as pre-verified")
}
