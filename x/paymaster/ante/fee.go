// Package ante provides a fee-deduction decorator that adds protocol-level gas
// abstraction: if an x/paymaster policy sponsors a transaction, the fee is paid
// by the sponsor account instead of the user (gasless UX). It is modeled on the
// SDK's DeductFeeDecorator and is a drop-in replacement for it in the Cosmos
// ante chain. Sponsored fees still land in fee_collector and feed the Squeeze split.
package ante

import (
	"bytes"
	"context"

	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

// PaymasterResolver decides whether a transaction is sponsored.
type PaymasterResolver interface {
	ResolveSponsor(ctx context.Context, msgs []sdk.Msg, feePayer sdk.AccAddress, fee sdk.Coins) (sdk.AccAddress, bool)
}

// DeductFeeDecorator deducts the fee from a sponsor (if a policy matches and no
// explicit fee granter was set), else from the fee granter (feegrant), else from
// the fee payer. pm may be nil (disables sponsorship).
type DeductFeeDecorator struct {
	ak  authante.AccountKeeper
	bk  authtypes.BankKeeper
	fk  authante.FeegrantKeeper
	pm  PaymasterResolver
	tfc authante.TxFeeChecker
}

func NewDeductFeeDecorator(ak authante.AccountKeeper, bk authtypes.BankKeeper, fk authante.FeegrantKeeper, pm PaymasterResolver, tfc authante.TxFeeChecker) DeductFeeDecorator {
	return DeductFeeDecorator{ak: ak, bk: bk, fk: fk, pm: pm, tfc: tfc}
}

func (d DeductFeeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		return ctx, errorsmod.Wrap(sdkerrors.ErrTxDecode, "Tx must be a FeeTx")
	}
	if !simulate && ctx.BlockHeight() > 0 && feeTx.GetGas() == 0 {
		return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidGasLimit, "must provide positive gas")
	}

	fee := feeTx.GetFee()
	var priority int64
	var err error
	if !simulate && d.tfc != nil {
		if fee, priority, err = d.tfc(ctx, tx); err != nil {
			return ctx, err
		}
	}
	if err := d.deduct(ctx, tx, fee); err != nil {
		return ctx, err
	}
	return next(ctx.WithPriority(priority), tx, simulate)
}

func (d DeductFeeDecorator) deduct(ctx sdk.Context, tx sdk.Tx, fee sdk.Coins) error {
	feeTx := tx.(sdk.FeeTx)
	if d.ak.GetModuleAddress(authtypes.FeeCollectorName) == nil {
		return errorsmod.Wrap(sdkerrors.ErrLogic, "fee collector module account has not been set")
	}

	feePayer := sdk.AccAddress(feeTx.FeePayer())
	feeGranter := feeTx.FeeGranter()
	deductFrom := feePayer
	sponsored := false

	// Auto-sponsorship applies only when the user set no explicit fee granter.
	if feeGranter == nil && d.pm != nil {
		if sponsor, ok := d.pm.ResolveSponsor(ctx, tx.GetMsgs(), feePayer, fee); ok {
			deductFrom = sponsor
			sponsored = true
		}
	}
	if !sponsored && feeGranter != nil {
		fg := sdk.AccAddress(feeGranter)
		if d.fk == nil {
			return sdkerrors.ErrInvalidRequest.Wrap("fee grants are not enabled")
		}
		if !bytes.Equal(fg, feePayer) {
			if err := d.fk.UseGrantedFees(ctx, fg, feePayer, fee, tx.GetMsgs()); err != nil {
				return errorsmod.Wrapf(err, "%s does not allow to pay fees for %s", fg, feePayer)
			}
		}
		deductFrom = fg
	}

	if d.ak.GetAccount(ctx, deductFrom) == nil {
		return sdkerrors.ErrUnknownAddress.Wrapf("fee payer address: %s does not exist", deductFrom)
	}
	if !fee.IsZero() {
		if err := d.bk.SendCoinsFromAccountToModule(ctx, deductFrom, authtypes.FeeCollectorName, fee); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrInsufficientFunds, "%s", err.Error())
		}
	}

	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(
			sdk.EventTypeTx,
			sdk.NewAttribute(sdk.AttributeKeyFee, fee.String()),
			sdk.NewAttribute(sdk.AttributeKeyFeePayer, deductFrom.String()),
		),
	})
	return nil
}
