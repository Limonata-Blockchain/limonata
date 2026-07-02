package cosmos

import (
	"fmt"
	"math/big"
	"slices"

	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	pmante "github.com/cosmos/evm/x/paymaster/ante"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	errortypes "github.com/cosmos/cosmos-sdk/types/errors"
)

// MinGasPriceDecorator will check if the transaction's fee is at least as large
// as the MinGasPrices param. If fee is too low, decorator returns error and tx
// is rejected. This applies for both CheckTx and DeliverTx
// If fee is high enough, then call next AnteHandler
//
// Sponsorship-aware: before rejecting a tx for insufficient fee, it checks
// whether an x/paymaster policy would sponsor this tx (same resolution the
// DeductFeeDecorator uses further down the chain). If so, the min-gas-price
// floor is skipped and the tx is admitted — the paymaster, not the sender,
// will pay. paymaster may be nil (disables sponsorship, e.g. in unit tests).
//
// CONTRACT: Tx must implement FeeTx to use MinGasPriceDecorator
type MinGasPriceDecorator struct {
	feemarketParams *feemarkettypes.Params
	paymaster       pmante.PaymasterResolver
}

// NewMinGasPriceDecorator creates a new MinGasPriceDecorator instance used only for
// Cosmos transactions. paymaster may be nil to disable sponsorship-aware admission.
func NewMinGasPriceDecorator(feemarketParams *feemarkettypes.Params, paymaster pmante.PaymasterResolver) MinGasPriceDecorator {
	return MinGasPriceDecorator{feemarketParams, paymaster}
}

// sponsored reports whether an x/paymaster policy would cover this tx's fee,
// mirroring exactly how pmante.DeductFeeDecorator resolves sponsorship
// (same msgs, fee payer, and fee inputs) so admission here never diverges
// from who actually ends up paying.
func (mpd MinGasPriceDecorator) sponsored(ctx sdk.Context, tx sdk.Tx, feeTx sdk.FeeTx) bool {
	if mpd.paymaster == nil {
		return false
	}
	feePayer := sdk.AccAddress(feeTx.FeePayer())
	_, ok := mpd.paymaster.ResolveSponsor(ctx, tx.GetMsgs(), feePayer, feeTx.GetFee())
	return ok
}

func (mpd MinGasPriceDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		return ctx, errorsmod.Wrapf(errortypes.ErrInvalidType, "invalid transaction type %T, expected sdk.FeeTx", tx)
	}

	minGasPrice := mpd.feemarketParams.MinGasPrice

	feeCoins := feeTx.GetFee()
	evmDenom := evmtypes.GetEVMCoinDenom()

	// only allow user to pass in aatom and stake native token as transaction fees
	// allow use stake native tokens for fees is just for unit tests to pass
	//
	// TODO: is the handling of stake necessary here? Why not adjust the tests to contain the correct denom?
	validFees := len(feeCoins) == 0 || (len(feeCoins) == 1 && slices.Contains([]string{evmDenom, sdk.DefaultBondDenom}, feeCoins.GetDenomByIndex(0)))
	if !validFees && !simulate {
		return ctx, fmt.Errorf("expected only native token %s for fee, but got %s", evmDenom, feeCoins.String())
	}

	// Short-circuit if min gas price is 0 or if simulating
	if minGasPrice.IsZero() || simulate {
		return next(ctx, tx, simulate)
	}

	minGasPrices := sdk.DecCoins{
		{
			Denom:  evmDenom,
			Amount: minGasPrice,
		},
	}

	gas := feeTx.GetGas()

	requiredFees := make(sdk.Coins, 0)

	// Determine the required fees by multiplying each required minimum gas
	// price by the gas limit, where fee = ceil(minGasPrice * gasLimit).
	gasLimit := math.LegacyNewDecFromBigInt(new(big.Int).SetUint64(gas))

	for _, gp := range minGasPrices {
		fee := gp.Amount.Mul(gasLimit).Ceil().RoundInt()
		if fee.IsPositive() {
			requiredFees = requiredFees.Add(sdk.Coin{Denom: gp.Denom, Amount: fee})
		}
	}

	// Fees not provided (or flag "auto"). Then use the base fee to make the check pass
	if feeCoins == nil {
		if mpd.sponsored(ctx, tx, feeTx) {
			return next(ctx, tx, simulate)
		}
		return ctx, errorsmod.Wrapf(errortypes.ErrInsufficientFee,
			"fee not provided. Please use the --fees flag or the --gas-price flag along with the --gas flag to estimate the fee. The minimum global fee for this tx is: %s",
			requiredFees)
	}

	if !feeCoins.IsAnyGTE(requiredFees) {
		// The fee is below the network floor, but a paymaster policy may still
		// cover it (e.g. a Keplr tx built from an un-updated chain-registry
		// gasPriceStep). Defer to the same sponsorship resolution the
		// DeductFeeDecorator uses — if it would sponsor this tx, admit it and
		// let the paymaster pay instead of rejecting a payable transaction.
		if mpd.sponsored(ctx, tx, feeTx) {
			return next(ctx, tx, simulate)
		}
		return ctx, errorsmod.Wrapf(errortypes.ErrInsufficientFee,
			"provided fee < minimum global fee (%s < %s). Please increase the gas price.",
			feeCoins,
			requiredFees)
	}

	return next(ctx, tx, simulate)
}
