package keeper

import (
	"testing"

	"cosmossdk.io/math"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

func TestMainnetGrantProtectsPrincipalAndAllowsOwnSurplus(t *testing.T) {
	f := newFixture(t)
	f.ctx = f.ctx.WithChainID(protectedGrantChainID)
	f.valBz = sdk.ValAddress(f.granteeBz)
	f.valStr = f.valBz.String()
	f.setGrant(types.Grant{Grantee: f.granteeStr, ValidatorOp: f.valStr, LockedAmount: "1000", GasAllowance: "0", Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	hooks := f.k.Hooks()
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1500))
	require.NoError(t, hooks.AfterDelegationModified(f.ctx, f.granteeBz, f.valBz))
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))
	require.NoError(t, hooks.AfterDelegationModified(f.ctx, f.granteeBz, f.valBz))
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(999))
	require.ErrorContains(t, hooks.AfterDelegationModified(f.ctx, f.granteeBz, f.valBz), "locked grant shares must remain")
	require.ErrorContains(t, hooks.BeforeDelegationRemoved(f.ctx, f.granteeBz, f.valBz), "locked grant shares must remain")
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	require.Equal(t, "1000", g.GrantedShares)
	// Historical chains retain the previously shipped clamp and replay behavior.
	require.NoError(t, hooks.AfterDelegationModified(f.ctx.WithChainID("limonata_10777-1"), f.granteeBz, f.valBz))
	g, _ = f.k.GetGrant(f.ctx, f.granteeStr)
	require.Equal(t, math.LegacyNewDec(999).String(), g.GrantedShares)
}

func TestMainnetBootstrapGrantBindsOwnValidatorAndProtectsFirstDelegation(t *testing.T) {
	f := newFixture(t)
	f.ctx = f.ctx.WithChainID(protectedGrantChainID)
	require.NoError(t, f.k.SetParams(f.ctx, types.Params{Admin: f.granteeStr}))
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewInt64Coin(testDenom, 3000)))
	grantee := acc(0x53)
	server := NewMsgServerImpl(f.k)
	_, err := server.IssueLocked(f.ctx, &types.MsgIssueLocked{Admin: f.granteeStr, Grantee: grantee.String(), LockedAmount: "1000", GasAllowance: "0"})
	require.NoError(t, err)
	g, found := f.k.GetGrant(f.ctx, grantee.String())
	require.True(t, found)
	require.Equal(t, sdk.ValAddress(grantee).String(), g.ValidatorOp)
	require.True(t, parseDecOrZero(g.GrantedShares).Equal(math.LegacyNewDec(1000)))
	require.ErrorContains(t, f.k.Hooks().BeforeDelegationCreated(f.ctx, grantee, f.valBz), "bond the locked grant")
	require.ErrorContains(t, f.k.Hooks().BeforeDelegationSharesModified(f.ctx, grantee, f.valBz), "bond the locked grant")
	require.NoError(t, f.k.Hooks().BeforeDelegationCreated(f.ctx, grantee, sdk.ValAddress(grantee)))
	_, err = server.IssueLocked(f.ctx, &types.MsgIssueLocked{Admin: f.granteeStr, Grantee: acc(0x54).String(), ValidatorOperator: f.valStr, LockedAmount: "1000", GasAllowance: "0"})
	require.ErrorContains(t, err, "grantee's own validator")
	require.Nil(t, f.ak.GetAccount(f.ctx, acc(0x54)))
}

func TestMainnetAuthorizedClawbackCanReclaimProtectedShares(t *testing.T) {
	f := newFixture(t)
	f.ctx = f.ctx.WithChainID(protectedGrantChainID)
	f.valBz = sdk.ValAddress(f.granteeBz)
	f.valStr = f.valBz.String()
	require.NoError(t, f.k.SetParams(f.ctx, types.Params{Admin: f.granteeStr}))
	f.setGrant(types.Grant{Grantee: f.granteeStr, ValidatorOp: f.valStr, LockedAmount: "1000", GasAllowance: "0", Status: "active", GrantedShares: "1000", TrackedShares: "1500"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1500))
	server := NewMsgServerImpl(f.k)
	_, err := server.Clawback(f.ctx, &types.MsgClawback{Admin: acc(0x56).String(), Grantee: f.granteeStr})
	require.Error(t, err)
	require.True(t, f.sk.sharesOf(f.granteeBz, f.valStr).Equal(math.LegacyNewDec(1500)))
	response, err := server.Clawback(f.ctx, &types.MsgClawback{Admin: f.granteeStr, Grantee: f.granteeStr})
	require.NoError(t, err)
	require.Equal(t, "1000", response.PendingAmount)
	require.True(t, f.sk.sharesOf(f.granteeBz, f.valStr).Equal(math.LegacyNewDec(500)))
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	require.Equal(t, "revoked", g.Status)
}
