package evmd

import (
	"bytes"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	testconstants "github.com/cosmos/evm/testutil/constants"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func TestMainnetUpstreamContractStakingProtection(t *testing.T) {
	configurator := evmtypes.NewEVMConfigurator()
	configurator.ResetTestConfig()
	t.Cleanup(configurator.ResetTestConfig)
	c := testconstants.ExampleChainID
	app := Setup(t, c.ChainID, c.EVMChainID)
	ctx := app.NewContext(false).WithChainID(MainnetChainID).WithBlockHeight(2).WithBlockTime(time.Unix(1800000000, 0))
	denom, err := app.StakingKeeper.BondDenom(ctx)
	require.NoError(t, err)
	staker := sdk.AccAddress(bytes.Repeat([]byte{0xC9}, 20))
	eth := common.BytesToAddress(staker)
	amount := mainnetMinSelfBond.QuoRaw(1000)
	coins := sdk.NewCoins(sdk.NewCoin(denom, amount))
	app.AccountKeeper.SetAccount(ctx, app.AccountKeeper.NewAccount(ctx, authtypes.NewBaseAccountWithAddress(staker)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, coins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, staker, coins))
	var operator sdk.ValAddress
	require.NoError(t, app.StakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		operator, _ = sdk.ValAddressFromBech32(v.GetOperator())
		return true
	}))
	validator, err := app.StakingKeeper.GetValidator(ctx, operator)
	require.NoError(t, err)
	shares, err := app.StakingKeeper.Delegate(ctx, staker, amount, stakingtypes.Unbonded, validator, true)
	require.NoError(t, err)
	completion, _, err := app.StakingKeeper.Undelegate(ctx, staker, operator, shares)
	require.NoError(t, err)
	code := []byte{0x00}
	hash := crypto.Keccak256(code)
	app.EVMKeeper.SetCode(ctx, hash, code)
	app.EVMKeeper.SetCodeHash(ctx, eth.Bytes(), hash)
	require.True(t, app.EVMKeeper.IsContract(ctx, eth))
	require.ErrorContains(t, app.EVMKeeper.DeleteAccount(ctx, eth), "staking positions")
	require.NotNil(t, app.AccountKeeper.GetAccount(ctx, staker))
	_, err = app.StakingKeeper.GetUnbondingDelegation(ctx, staker, operator)
	require.NoError(t, err)
	buffer := sdk.NewCoins(sdk.NewCoin(denom, amount.MulRaw(3)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, buffer))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToModule(ctx, minttypes.ModuleName, stakingtypes.NotBondedPoolName, buffer))
	ctx = ctx.WithBlockTime(completion.Add(time.Second)).WithBlockHeight(20)
	pool := app.AccountKeeper.GetModuleAddress(stakingtypes.NotBondedPoolName)
	supply := app.BankKeeper.GetSupply(ctx, denom).Amount
	before := app.BankKeeper.GetBalance(ctx, pool, denom).Amount
	paid, err := app.StakingKeeper.CompleteUnbonding(ctx, staker, operator)
	require.NoError(t, err)
	require.True(t, paid.AmountOf(denom).Equal(amount))
	require.True(t, app.BankKeeper.GetBalance(ctx, staker, denom).Amount.Equal(amount))
	after := app.BankKeeper.GetBalance(ctx, pool, denom).Amount
	require.True(t, before.Sub(after).Equal(amount))
	_, err = app.StakingKeeper.CompleteUnbonding(ctx, staker, operator)
	require.Error(t, err)
	require.True(t, app.BankKeeper.GetBalance(ctx, pool, denom).Amount.Equal(after))
	require.True(t, app.BankKeeper.GetSupply(ctx, denom).Amount.Equal(supply))
	// With all staking claims settled, the normal self-destruct cleanup remains valid.
	require.NoError(t, app.EVMKeeper.DeleteAccount(ctx, eth))
}
