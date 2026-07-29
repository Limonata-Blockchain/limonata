package keeper_test

import (
	"testing"

	sdkmath "cosmossdk.io/math"
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
	require.True(t, k.CommitteeConcentrationBreached(ctx, epoch, k.GetParams(ctx).DkgStrictConcentration), "op1 owning 3>=t must count as breached")
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
	require.False(t, k.CommitteeConcentrationBreached(ctx, epoch, k.GetParams(ctx).DkgStrictConcentration))
	if _, err := srv.SubmitEncrypted(ctx, encWithPoK(t, pub, "safely private", "cosmos1v")); err != nil {
		t.Fatalf("a distributed committee must accept the submission: %v", err)
	}
}

// TestCommitteeConcentrationBreached_StrandClauseGated is the focused probe for the v0.3.6 two-clause
// guard's CLAUSE 2 (single-operator strand / liveness) AND its gating on DkgStrictConcentration.
//
// A member that alone owns >= S-t+1 eval points cannot DECRYPT alone (it owns < t) but CAN unilaterally
// WITHHOLD its shares and freeze reconstruction for the whole epoch (the remaining t-1 < t points can
// never recover). The strand clause fails closed on exactly that operator. It is gated: with the flag
// OFF (legacy) the committee is NOT breached (byte-identical pre-v0.3.6 behaviour); with it ON the
// strand is caught. Committee: S=8, t=6 -> strandBar = S-t+1 = 3. op1 owns 5 (3 <= 5 < 6): strands but
// does not decrypt alone; op1's stake is 60% (< 2/3) so the confidentiality coalition clause (1b) does
// NOT fire, isolating clause 2 as the only trigger.
func TestCommitteeConcentrationBreached_StrandClauseGated(t *testing.T) {
	k, ctx := newKeeper(t, 10)

	const epoch uint64 = 7
	const thr uint32 = 6 // S=8 -> strandBar = 8-6+1 = 3
	k.SetActiveEpoch(ctx, epoch)
	pub := throwawayThresholdPub(t)
	require.NoError(t, k.SetActiveKey(ctx, types.ActiveThresholdKey{Epoch: epoch, Pub: pub, Threshold: thr}))
	require.NoError(t, k.SetDkgRound(ctx, types.DkgRound{
		Epoch: epoch, Threshold: thr, Status: "active",
		Members: []types.RoundMember{
			// op1 owns 5 of 8 points (>= strandBar 3, < t 6) and holds 60% stake (< 2/3).
			{Index: 1, OperatorAddr: "op1", Weighted: true, Weight: sdkmath.NewInt(60), EvalPoints: []uint64{1, 2, 3, 4, 5}},
			{Index: 2, OperatorAddr: "op2", Weighted: true, Weight: sdkmath.NewInt(40), EvalPoints: []uint64{6, 7, 8}},
		},
	}))

	// Gate OFF (legacy): no member owns >= t, and no <=2/3-stake coalition can reach t, so NOT breached.
	pOff := enableParams(pub, 2, 2, []string{"kp1", "kp2"})
	pOff.DkgEnabled = true
	pOff.DkgStrictConcentration = false
	require.NoError(t, k.SetParams(ctx, pOff))
	require.False(t, k.CommitteeConcentrationBreached(ctx, epoch, k.GetParams(ctx).DkgStrictConcentration),
		"with the strand clause GATED OFF, an op owning 5<t points must NOT be flagged (legacy behaviour preserved)")

	// Gate ON: op1 owns 5 >= S-t+1 = 3 -> it can freeze decryption -> fail closed.
	pOn := pOff
	pOn.DkgStrictConcentration = true
	require.NoError(t, k.SetParams(ctx, pOn))
	require.True(t, k.CommitteeConcentrationBreached(ctx, epoch, k.GetParams(ctx).DkgStrictConcentration),
		"with the strand clause ON, an op owning >= S-t+1 points (can unilaterally freeze decryption) must fail closed")
}
