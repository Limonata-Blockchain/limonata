package evmd

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	testconstants "github.com/cosmos/evm/testutil/constants"
	valgrantkeeper "github.com/cosmos/evm/x/valgrant/keeper"
	valgranttypes "github.com/cosmos/evm/x/valgrant/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Exercise the real SDK hooks and transaction cache, not a staking mock: the
// legacy probe's escaping redelegation must now fail before the cache is written.
func TestMainnetGrantCannotEscapeAndAdminRecovers(t *testing.T) {
	configurator := evmtypes.NewEVMConfigurator()
	configurator.ResetTestConfig()
	t.Cleanup(configurator.ResetTestConfig)
	c := testconstants.ExampleChainID
	app := Setup(t, c.ChainID, c.EVMChainID)
	ctx := app.NewContext(false).WithChainID(MainnetChainID).WithBlockHeight(2).
		WithBlockTime(time.Unix(1_800_000_000, 0))
	denom, err := app.StakingKeeper.BondDenom(ctx)
	require.NoError(t, err)
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0xB8}, 20))
	admin := sdk.AccAddress(bytes.Repeat([]byte{0xB7}, 20))
	operator := sdk.ValAddress(grantee)
	principal := mainnetMinSelfBond.MulRaw(10)
	oneLimo := mainnetMinSelfBond.QuoRaw(100_000)
	coins := func(amount math.Int) sdk.Coins { return sdk.NewCoins(sdk.NewCoin(denom, amount)) }
	mintToModule := func(module string, amount math.Int) {
		require.NoError(t, app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, coins(amount)))
		require.NoError(t, app.BankKeeper.SendCoinsFromModuleToModule(ctx, minttypes.ModuleName, module, coins(amount)))
	}
	mintToModule(valgranttypes.ModuleName, principal.Add(oneLimo))
	require.NoError(t, app.ValGrantKeeper.SetParams(ctx, valgranttypes.Params{Admin: admin.String()}))
	server := valgrantkeeper.NewMsgServerImpl(app.ValGrantKeeper)
	_, err = server.IssueLocked(ctx, &valgranttypes.MsgIssueLocked{
		Admin: admin.String(), Grantee: grantee.String(), LockedAmount: principal.String(), GasAllowance: oneLimo.String(),
	})
	require.NoError(t, err)
	var other sdk.ValAddress
	require.NoError(t, app.StakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		other, _ = sdk.ValAddressFromBech32(v.GetOperator())
		return true
	}))
	require.NotEmpty(t, other)
	otherValidator, err := app.StakingKeeper.GetValidator(ctx, other)
	require.NoError(t, err)
	// No first-delegation escape to an unrelated validator, nor liquid transfer.
	cached, _ := ctx.CacheContext()
	_, err = app.StakingKeeper.Delegate(cached, grantee, principal, stakingtypes.Unbonded, otherValidator, true)
	require.ErrorContains(t, err, "bond the locked grant")
	cached, _ = ctx.CacheContext()
	require.Error(t, app.BankKeeper.SendCoins(cached, grantee, admin, coins(oneLimo.MulRaw(2))))

	msg, err := stakingtypes.NewMsgCreateValidator(operator.String(), ed25519.GenPrivKey().PubKey(),
		sdk.NewCoin(denom, principal), stakingtypes.Description{Moniker: "protected-mainnet-seat"},
		stakingtypes.NewCommissionRates(math.LegacyMustNewDecFromStr("0.05"), math.LegacyMustNewDecFromStr("0.20"), math.LegacyMustNewDecFromStr("0.01")), mainnetMinSelfBond)
	require.NoError(t, err)
	_, err = stakingkeeper.NewMsgServerImpl(app.StakingKeeper).CreateValidator(ctx, msg)
	require.NoError(t, err)
	initial, err := app.StakingKeeper.GetDelegation(ctx, grantee, operator)
	require.NoError(t, err)
	for _, action := range []string{"undelegate-part", "undelegate-all", "redelegate"} {
		t.Run(action, func(t *testing.T) {
			cache, _ := ctx.CacheContext()
			shares := math.LegacyNewDecFromInt(oneLimo)
			var attemptErr error
			switch action {
			case "undelegate-part":
				_, _, attemptErr = app.StakingKeeper.Undelegate(cache, grantee, operator, shares)
			case "undelegate-all":
				_, _, attemptErr = app.StakingKeeper.Undelegate(cache, grantee, operator, initial.Shares)
			case "redelegate":
				_, attemptErr = app.StakingKeeper.BeginRedelegation(cache, grantee, operator, other, shares)
			}
			require.ErrorContains(t, attemptErr, "locked grant shares must remain")
			unchanged, getErr := app.StakingKeeper.GetDelegation(ctx, grantee, operator)
			require.NoError(t, getErr)
			require.True(t, unchanged.Shares.Equal(initial.Shares))
			v, getErr := app.StakingKeeper.GetValidator(ctx, operator)
			require.NoError(t, getErr)
			require.False(t, v.Jailed, "failed transaction must also roll back minimum-self-delegation jailing")
		})
	}

	// Personal stake above the grant remains movable. Leave some on the same
	// validator to prove the subsequent clawback preserves commingled own shares.
	own := mainnetMinSelfBond.MulRaw(3)
	require.NoError(t, app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, coins(own)))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, grantee, coins(own)))
	v, err := app.StakingKeeper.GetValidator(ctx, operator)
	require.NoError(t, err)
	_, err = app.StakingKeeper.Delegate(ctx, grantee, own, stakingtypes.Unbonded, v, true)
	require.NoError(t, err)
	_, err = app.StakingKeeper.BeginRedelegation(ctx, grantee, operator, other, math.LegacyNewDecFromInt(mainnetMinSelfBond))
	require.NoError(t, err)
	otherBefore, err := app.StakingKeeper.GetDelegation(ctx, grantee, other)
	require.NoError(t, err)
	_, err = server.Clawback(ctx, &valgranttypes.MsgClawback{Admin: grantee.String(), Grantee: grantee.String()})
	require.Error(t, err)
	response, err := server.Clawback(ctx, &valgranttypes.MsgClawback{Admin: admin.String(), Grantee: grantee.String()})
	require.NoError(t, err)
	require.Equal(t, principal.String(), response.PendingAmount)
	remaining, err := app.StakingKeeper.GetDelegation(ctx, grantee, operator)
	require.NoError(t, err)
	require.True(t, remaining.Shares.Equal(math.LegacyNewDecFromInt(mainnetMinSelfBond.MulRaw(2))))
	otherAfter, err := app.StakingKeeper.GetDelegation(ctx, grantee, other)
	require.NoError(t, err)
	require.True(t, otherAfter.Shares.Equal(otherBefore.Shares))
	ubd, err := app.StakingKeeper.GetUnbondingDelegation(ctx, grantee, operator)
	require.NoError(t, err)
	cache, _ := ctx.CacheContext()
	_, err = stakingkeeper.NewMsgServerImpl(app.StakingKeeper).CancelUnbondingDelegation(cache, &stakingtypes.MsgCancelUnbondingDelegation{
		DelegatorAddress: grantee.String(), ValidatorAddress: operator.String(), Amount: sdk.NewCoin(denom, principal), CreationHeight: ubd.Entries[0].CreationHeight,
	})
	require.ErrorContains(t, err, "paused until the grant clawback")
	require.NoError(t, app.ValGrantKeeper.SweepMaturedClawbacks(ctx))
	ctx = ctx.WithBlockTime(ubd.Entries[0].CompletionTime.Add(time.Second)).WithBlockHeight(20)
	// Even after maturity, no sweep can consume gas while the UBD is still live.
	require.NoError(t, app.ValGrantKeeper.SweepMaturedClawbacks(ctx))
	require.Equal(t, oneLimo.String(), app.BankKeeper.GetBalance(ctx, grantee, denom).Amount.String())
	_, err = app.StakingKeeper.CompleteUnbonding(ctx, grantee, operator)
	require.NoError(t, err)
	require.NoError(t, app.ValGrantKeeper.SweepMaturedClawbacks(ctx))
	pool := app.AccountKeeper.GetModuleAddress(valgranttypes.ModuleName)
	require.Equal(t, principal.String(), app.BankKeeper.GetBalance(ctx, pool, denom).Amount.String())
	require.Equal(t, oneLimo.String(), app.BankKeeper.GetBalance(ctx, grantee, denom).Amount.String())
}
