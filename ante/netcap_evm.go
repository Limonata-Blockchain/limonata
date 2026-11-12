package ante

import (
	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	anteinterfaces "github.com/cosmos/evm/ante/interfaces"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// NetCapEVMDecorator enforces the net-seller cap on NATIVE EVM value transfers (eth tx
// with `value`). These commit balance changes via UncheckedSetBalance and therefore
// bypass the x/bank SendRestriction, so they must be checked here. Cosmos sends and the
// ERC20/WERC20 precompiles route through x/bank and are covered by the SendRestriction.
// A nil checker disables enforcement (no-op).
type NetCapEVMDecorator struct {
	checker anteinterfaces.NetCapChecker
}

func NewNetCapEVMDecorator(c anteinterfaces.NetCapChecker) NetCapEVMDecorator {
	return NetCapEVMDecorator{checker: c}
}

func (d NetCapEVMDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if d.checker == nil {
		return next(ctx, tx, simulate)
	}
	for _, msg := range tx.GetMsgs() {
		ethMsg, ethTx, err := evmtypes.UnpackEthMsg(msg)
		if err != nil {
			continue // not an eth msg
		}
		to := ethTx.To()
		val := ethTx.Value()
		if to == nil || val == nil || val.Sign() <= 0 {
			continue // contract creation or zero-value call: not a native send
		}
		from := sdk.AccAddress(ethMsg.GetFrom())
		toAcc := sdk.AccAddress(to.Bytes())
		if err := d.checker.CheckAndRecord(ctx, from, toAcc, sdkmath.NewIntFromBigInt(val)); err != nil {
			return ctx, err
		}
	}
	return next(ctx, tx, simulate)
}
