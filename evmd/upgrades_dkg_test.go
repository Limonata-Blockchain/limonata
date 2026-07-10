package evmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	testconstants "github.com/cosmos/evm/testutil/constants"
)

// TestApplyDkgActivation_TransparentDKG proves the v0.3.0 upgrade handler body (applyDkgActivation)
// runs cleanly on the REAL evmd app: it enables CometBFT vote extensions at a FUTURE height and
// activates the transparent validator DKG + encrypted mempool + EncExec with params that PASS
// validation. This is the in-place-upgrade activation path (previously only genesis activation was
// tested). A bad activation must return an error (halting the upgrade), never install broken params.
func TestApplyDkgActivation_TransparentDKG(t *testing.T) {
	c := testconstants.ExampleChainID
	app := Setup(t, c.ChainID, c.EVMChainID)

	const H = int64(1000)
	ctx := app.NewContext(false).WithBlockHeight(H).WithChainID(c.ChainID)

	// Pre-condition: the module is inert (DKG off) and vote extensions are not enabled.
	pBefore := app.EncMempoolKeeper.GetParams(ctx)
	require.False(t, pBefore.DkgEnabled, "DKG must start off")
	cpBefore, err := app.ConsensusParamsKeeper.ParamsStore.Get(ctx)
	require.NoError(t, err)
	if cpBefore.Abci != nil {
		require.Zero(t, cpBefore.Abci.VoteExtensionsEnableHeight, "VE must start disabled")
	}

	// Run the activation (the upgrade handler body).
	require.NoError(t, app.applyDkgActivation(ctx), "activation must apply cleanly, not halt")

	// Vote extensions enabled at a FUTURE height (VoteExtEnabledAt requires height > enableHeight).
	cp, err := app.ConsensusParamsKeeper.ParamsStore.Get(ctx)
	require.NoError(t, err)
	require.NotNil(t, cp.Abci)
	require.Equal(t, H+dkgVoteExtLeadBlocks, cp.Abci.VoteExtensionsEnableHeight)
	require.Greater(t, cp.Abci.VoteExtensionsEnableHeight, H, "VE enable height must be in the future")

	// Transparent DKG + encrypted mempool + EncExec activated, with VALID params.
	p := app.EncMempoolKeeper.GetParams(ctx)
	require.True(t, p.EncEnabled)
	require.True(t, p.EncExecEnabled)
	require.True(t, p.DkgEnabled)
	require.True(t, p.DkgTransparent)
	require.Equal(t, uint64(H+dkgVoteExtLeadBlocks+dkgStartLeadBlocks), p.DkgStartHeight,
		"DKG must open only after VE is live")
	require.Positive(t, p.EncSubmitBond)
	require.Equal(t, "aLIMO", p.EncSubmitBondDenom)
	require.Positive(t, p.EncSubmitBondBurnBps)
	require.NoError(t, p.Validate(), "activated params must pass validation")

	// The DKG supplies the active key, so the trusted-setup keyper fields stay empty.
	require.Nil(t, p.ThresholdPub)
	require.Zero(t, p.Threshold)
	require.Empty(t, p.Keypers)

	// Idempotent: re-running is a no-op, not a double-activation error.
	require.NoError(t, app.applyDkgActivation(ctx))
}
