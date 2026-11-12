package evmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	testconstants "github.com/cosmos/evm/testutil/constants"
)

type policySupply struct{ supply math.Int }

func (p policySupply) GetSupply(context.Context, string) sdk.Coin {
	return sdk.NewCoin("aLIMO", p.supply)
}

func TestMainnetMintRestriction(t *testing.T) {
	ctx := sdk.Context{}.WithChainID(MainnetChainID)
	one := sdk.NewCoins(sdk.NewInt64Coin("aLIMO", 1))
	require.ErrorContains(t, mainnetMintRestriction(policySupply{mainnetMaxSupply})(ctx, one), "supply cap")
	require.NoError(t, mainnetMintRestriction(policySupply{mainnetMaxSupply.SubRaw(1)})(ctx, one))
	require.NoError(t, mainnetMintRestriction(policySupply{mainnetMaxSupply})(ctx, sdk.NewCoins(sdk.NewInt64Coin("uusdc", 1))))
	require.NoError(t, mainnetMintRestriction(policySupply{mainnetMaxSupply})(ctx.WithChainID("limonata_10777-1"), one))
}

type policyValidator struct {
	minimum math.Int
	err     error
}

func (p policyValidator) GetValidator(context.Context, sdk.ValAddress) (stakingtypes.Validator, error) {
	return stakingtypes.Validator{MinSelfDelegation: p.minimum}, p.err
}

func TestMainnetValidatorMinimum(t *testing.T) {
	ctx := sdk.Context{}.WithChainID(MainnetChainID)
	require.ErrorContains(t, newMainnetStakingHooks(policyValidator{minimum: math.OneInt()}).AfterValidatorCreated(ctx, nil), "100,000 LIMO")
	require.NoError(t, newMainnetStakingHooks(policyValidator{minimum: mainnetMinSelfBond}).AfterValidatorCreated(ctx, nil))
	require.NoError(t, newMainnetStakingHooks(policyValidator{minimum: mainnetMinSelfBond.MulRaw(10)}).AfterValidatorCreated(ctx, nil))
	require.NoError(t, newMainnetStakingHooks(policyValidator{minimum: math.OneInt()}).AfterValidatorCreated(ctx.WithChainID("limonata_10777-1"), nil))
	err := errors.New("validator unavailable")
	require.ErrorIs(t, newMainnetStakingHooks(policyValidator{err: err}).AfterValidatorCreated(ctx, nil), err)
}

func TestMainnetPolicyWiring(t *testing.T) {
	c := testconstants.ExampleChainID
	app := Setup(t, c.ChainID, c.EVMChainID)
	ctx := app.NewContext(false).WithChainID(MainnetChainID).WithBlockHeight(1)
	for _, module := range []string{"mint", "gassponsor", "evm", "erc20", "transfer"} {
		t.Run("mint/"+module, func(t *testing.T) {
			cached, _ := ctx.CacheContext()
			remaining := mainnetMaxSupply.Sub(app.BankKeeper.GetSupply(cached, "aLIMO").Amount)
			require.True(t, remaining.IsPositive())
			require.NoError(t, app.BankKeeper.MintCoins(cached, module, sdk.NewCoins(sdk.NewCoin("aLIMO", remaining))))
			require.ErrorContains(t, app.BankKeeper.MintCoins(cached, module, sdk.NewCoins(sdk.NewInt64Coin("aLIMO", 1))), "supply cap")
			require.Equal(t, mainnetMaxSupply, app.BankKeeper.GetSupply(cached, "aLIMO").Amount)
		})
	}
	var operator sdk.ValAddress
	require.NoError(t, app.StakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		operator, _ = sdk.ValAddressFromBech32(v.GetOperator())
		return true
	}))
	require.NotEmpty(t, operator)
	v, err := app.StakingKeeper.GetValidator(ctx, operator)
	require.NoError(t, err)
	v.MinSelfDelegation = math.OneInt()
	require.NoError(t, app.StakingKeeper.SetValidator(ctx, v))
	require.ErrorContains(t, app.StakingKeeper.Hooks().AfterValidatorCreated(ctx, operator), "100,000 LIMO")
	v.MinSelfDelegation = mainnetMinSelfBond
	require.NoError(t, app.StakingKeeper.SetValidator(ctx, v))
	require.NoError(t, app.StakingKeeper.Hooks().AfterValidatorCreated(ctx, operator))
}
