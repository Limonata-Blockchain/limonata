package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// round-9 #4: when a single operator owns >= the reconstruction threshold of eval-points (it can
// decrypt alone), SubmitEncrypted must FAIL CLOSED - refusing a "confidential" submission the whale
// would read - rather than offer false confidentiality. A distributed committee accepts normally.
func TestSubmitEncrypted_FailsClosedOnConcentratedCommittee(t *testing.T) {
	k, ctx := newKeeper(t, 10)
	pub := throwawayThresholdPub(t)
	p := enableParams(pub, 2, 2, []string{"kp1", "kp2"})
	p.DkgEnabled = true // DkgTransparent stays false, so the VE-scheduling guard does not apply
	require.NoError(t, k.SetParams(ctx, p))

	const epoch uint64 = 5
	const thr uint32 = 3
	k.SetActiveEpoch(ctx, epoch)
	require.NoError(t, k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: epoch, Pub: pub, Threshold: thr}))
	srv := keeper.NewMsgServerImpl(k)

	// CONCENTRATED: op1 owns 3 (>= threshold 3) points -> it alone can reconstruct -> reject.
	require.NoError(t, k.SetDkgRound(ctx, types.DkgRound{
		Epoch: epoch, Threshold: thr, Status: "active",
		Members: []types.RoundMember{
			{Index: 1, OperatorAddr: "op1", Weighted: true, EvalPoints: []uint64{1, 2, 3}},
			{Index: 2, OperatorAddr: "op2", Weighted: true, EvalPoints: []uint64{4}},
		},
	}))
	require.True(t, k.CommitteeConcentrationBreached(ctx, epoch), "op1 owning 3>=t must count as breached")
	if _, err := srv.SubmitEncrypted(ctx, encWithPoK(t, pub, "front-run me", "cosmos1u")); err == nil {
		t.Fatal("a concentrated committee (op1 owns >= t) must fail closed on SubmitEncrypted")
	}

	// DISTRIBUTED: no member owns >= 3 points -> confidentiality holds -> accept.
	require.NoError(t, k.SetDkgRound(ctx, types.DkgRound{
		Epoch: epoch, Threshold: thr, Status: "active",
		Members: []types.RoundMember{
			{Index: 1, OperatorAddr: "op1", Weighted: true, EvalPoints: []uint64{1, 2}},
			{Index: 2, OperatorAddr: "op2", Weighted: true, EvalPoints: []uint64{3, 4}},
		},
	}))
	require.False(t, k.CommitteeConcentrationBreached(ctx, epoch))
	if _, err := srv.SubmitEncrypted(ctx, encWithPoK(t, pub, "safely private", "cosmos1v")); err != nil {
		t.Fatalf("a distributed committee must accept the submission: %v", err)
	}
}
