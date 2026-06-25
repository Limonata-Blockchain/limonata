package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/cosmos/evm/x/valgrant/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns the x/valgrant MsgServer backed by the keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

// IssueLocked creates a PermanentLockedAccount for the grantee and funds it with
// the locked principal + liquid gas allowance from the valgrant pool. Admin-gated.
func (m msgServer) IssueLocked(goCtx context.Context, msg *types.MsgIssueLocked) (*types.MsgIssueLockedResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}
	ctx := sdk.UnwrapSDKContext(goCtx)

	bondDenom, err := m.stakingKeeper.BondDenom(goCtx)
	if err != nil {
		return nil, err
	}

	lockedAmt, ok := math.NewIntFromString(msg.LockedAmount)
	if !ok || !lockedAmt.IsPositive() {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid locked_amount %q", msg.LockedAmount)
	}
	gasAmt, ok := math.NewIntFromString(msg.GasAllowance)
	if !ok || gasAmt.IsNegative() {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid gas_allowance %q", msg.GasAllowance)
	}

	lockedCoins := sdk.NewCoins(sdk.NewCoin(bondDenom, lockedAmt))
	gasCoins := sdk.NewCoins()
	if gasAmt.IsPositive() {
		gasCoins = sdk.NewCoins(sdk.NewCoin(bondDenom, gasAmt))
	}

	if err := m.IssueGrant(goCtx, msg.Grantee, lockedCoins, gasCoins); err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	grant := types.Grant{
		Grantee:      msg.Grantee,
		LockedAmount: lockedAmt.String(),
		GasAllowance: gasAmt.String(),
		ValidatorOp:  msg.ValidatorOperator,
		IssuedHeight: uint64(ctx.BlockHeight()),
		IssuedTime:   ctx.BlockTime().Unix(),
		Status:       "active",
	}
	if err := m.SetGrant(goCtx, grant); err != nil {
		return nil, err
	}

	return &types.MsgIssueLockedResponse{}, nil
}

// Clawback force-undelegates + sweeps the locked principal back to the pool. Admin-gated.
func (m msgServer) Clawback(goCtx context.Context, msg *types.MsgClawback) (*types.MsgClawbackResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}

	undelegated, sweptNow, pending, err := m.Keeper.Clawback(goCtx, msg.Grantee)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	return &types.MsgClawbackResponse{
		UndelegateAmount: undelegated.String(),
		SweptAmount:      sweptNow.String(),
		PendingAmount:    pending.String(),
	}, nil
}

// BurnPool permanently destroys LIMO from the valgrant reserve pool (admin-gated).
// amount "0"/empty burns the entire current pool balance. The coins are removed
// from the module account AND from total supply.
func (m msgServer) BurnPool(goCtx context.Context, msg *types.MsgBurnPool) (*types.MsgBurnPoolResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}

	burned, err := m.Keeper.BurnPool(goCtx, msg.Amount)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	return &types.MsgBurnPoolResponse{Burned: burned.String()}, nil
}

func (m msgServer) requireAdmin(goCtx context.Context, signer string) error {
	admin := m.GetParams(goCtx).Admin
	if admin == "" {
		return errorsmod.Wrap(sdkerrors.ErrUnauthorized, "valgrant admin is not configured")
	}
	if signer != admin {
		return errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "signer %s is not the valgrant admin", signer)
	}
	return nil
}
