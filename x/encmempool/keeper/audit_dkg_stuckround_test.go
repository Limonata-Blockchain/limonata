package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/types"
)

// round-12 #3: a STUCK DKG round (no dealings ingested - whether nobody dealt or a proposer censored
// the vote-extension consumption) must NOT freeze rekey/retry until the far-off complaint deadline.
// EndBlockDKG force-advances it (failed_early) once the DEAL window closes, because the ingested
// dealing weight is below threshold, bounding the freeze to the deal window (itself capped at
// maxDkgPhaseWindow). This pins that existing mechanism so it cannot silently regress.
func TestDkg_StuckRound_ForceAdvancesAtDealDeadline(t *testing.T) {
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	vals := make([]stakingtypes.Validator, len(mem))
	for i, m := range mem {
		vals[i] = bondedVal(m.op, 100)
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(2, 3)
	p.DkgShareBudget = 24
	require.NoError(t, k.SetParams(ctx, p))
	for _, m := range mem {
		require.True(t, k.RecordEncPubKey(ctx, m.op, m.pub, encPoP(m)))
	}

	// Open epoch 1.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	require.True(t, ok)
	require.Equal(t, types.DkgStatusOpen, round.Status)
	// There must be at least one block strictly between the deal deadline and the complaint deadline
	// for this test to prove EARLY advance (before the complaint deadline).
	require.Less(t, round.DealDeadline+1, round.ComplaintDeadline, "need a gap to prove pre-complaint-deadline advance")

	// Advance PAST the deal deadline with ZERO dealings ingested, but BEFORE the complaint deadline.
	h := int64(round.DealDeadline + 1)
	require.Less(t, uint64(h), round.ComplaintDeadline)
	fctx := ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(fctx)

	// The stuck round is force-advanced (failed early), NOT left Open waiting for the complaint
	// deadline: the freeze is bounded to the deal window, not the full round.
	require.True(t, hasEvent(fctx, "encmempool_dkg_failed_early"),
		"a no-dealing round must be force-advanced at the deal deadline, not frozen until the complaint deadline")
	r2, ok := k.GetDkgRound(fctx, 1)
	require.True(t, ok)
	require.NotEqual(t, types.DkgStatusOpen, r2.Status, "epoch 1 must no longer be an open, frozen round")
}
