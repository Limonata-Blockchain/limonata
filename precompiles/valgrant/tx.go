package valgrant

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"

	cmn "github.com/cosmos/evm/precompiles/common"
	valgranttypes "github.com/cosmos/evm/x/valgrant/types"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// cosmosBech32 derives the cosmos bech32 account address that corresponds to the
// 20-byte EVM address. This matches how the chain (and the CLI keyring) derives
// the cosmos address for a given key, so the resulting string can be compared
// against x/valgrant Params.admin by the msg_server's admin gate.
func cosmosBech32(addr common.Address) string {
	return sdk.AccAddress(addr.Bytes()).String()
}

// requireDirectEOACall rejects calls originating from a smart contract (unless an
// EIP-7702 delegated account). The admin must call the precompile directly.
func requireDirectEOACall(stateDB vm.StateDB, caller common.Address) error {
	code := stateDB.GetCode(caller)
	_, delegated := ethtypes.ParseDelegation(code)
	if len(code) > 0 && !delegated {
		return errors.New(ErrCannotCallFromContract)
	}
	return nil
}

// IssueGrant handles issueGrant(address grantee, uint256 lockedAmount, uint256 gasAllowance).
// It builds a MsgIssueLocked with Admin = bech32(caller) and routes it through the
// x/valgrant MsgServer, which enforces admin == Params.admin and performs the
// PermanentLockedAccount creation + pool funding + grant bookkeeping.
func (p Precompile) IssueGrant(
	ctx sdk.Context,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 3, len(args))
	}

	grantee, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf(ErrInvalidGrantee, args[0])
	}
	lockedAmount, ok := args[1].(*big.Int)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidAmount, args[1])
	}
	gasAllowance, ok := args[2].(*big.Int)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidAmount, args[2])
	}

	caller := contract.Caller()
	if err := requireDirectEOACall(stateDB, caller); err != nil {
		return nil, err
	}

	msg := &valgranttypes.MsgIssueLocked{
		Admin:        cosmosBech32(caller),
		Grantee:      cosmosBech32(grantee),
		LockedAmount: math.NewIntFromBigInt(lockedAmount).String(),
		GasAllowance: math.NewIntFromBigInt(gasAllowance).String(),
	}

	p.Logger(ctx).Debug(
		"tx called",
		"method", method.Name,
		"admin", msg.Admin,
		"grantee", msg.Grantee,
		"locked_amount", msg.LockedAmount,
		"gas_allowance", msg.GasAllowance,
	)

	if _, err := p.msgServer.IssueLocked(ctx, msg); err != nil {
		return nil, err
	}

	if err := p.EmitGrantIssuedEvent(ctx, stateDB, grantee, lockedAmount, gasAllowance); err != nil {
		return nil, err
	}

	return method.Outputs.Pack(true)
}

// Clawback handles clawback(address grantee). It builds a MsgClawback with
// Admin = bech32(caller) and routes it through the x/valgrant MsgServer, which
// enforces admin == Params.admin and force-undelegates + sweeps the principal.
func (p Precompile) Clawback(
	ctx sdk.Context,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 1, len(args))
	}

	grantee, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf(ErrInvalidGrantee, args[0])
	}

	caller := contract.Caller()
	if err := requireDirectEOACall(stateDB, caller); err != nil {
		return nil, err
	}

	msg := &valgranttypes.MsgClawback{
		Admin:   cosmosBech32(caller),
		Grantee: cosmosBech32(grantee),
	}

	p.Logger(ctx).Debug(
		"tx called",
		"method", method.Name,
		"admin", msg.Admin,
		"grantee", msg.Grantee,
	)

	res, err := p.msgServer.Clawback(ctx, msg)
	if err != nil {
		return nil, err
	}

	undelegated, _ := math.NewIntFromString(res.UndelegateAmount)
	sweptNow, _ := math.NewIntFromString(res.SweptAmount)
	pending, _ := math.NewIntFromString(res.PendingAmount)

	if err := p.EmitGrantClawedBackEvent(ctx, stateDB, grantee, undelegated.BigInt(), sweptNow.BigInt(), pending.BigInt()); err != nil {
		return nil, err
	}

	return method.Outputs.Pack(true)
}

// BurnPool handles burnPool(uint256 amount) returns (uint256 burned). It builds a
// MsgBurnPool with Admin = bech32(caller) and routes it through the x/valgrant
// MsgServer, which enforces admin == Params.admin and permanently destroys the
// resolved aLIMO amount from the valgrant reserve pool (removed from the module
// account AND from total supply). amount 0 burns the entire current pool balance.
func (p Precompile) BurnPool(
	ctx sdk.Context,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 1, len(args))
	}

	amount, ok := args[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidAmount, args[0])
	}

	caller := contract.Caller()
	if err := requireDirectEOACall(stateDB, caller); err != nil {
		return nil, err
	}

	msg := &valgranttypes.MsgBurnPool{
		Admin:  cosmosBech32(caller),
		Amount: math.NewIntFromBigInt(amount).String(),
	}

	p.Logger(ctx).Debug(
		"tx called",
		"method", method.Name,
		"admin", msg.Admin,
		"amount", msg.Amount,
	)

	res, err := p.msgServer.BurnPool(ctx, msg)
	if err != nil {
		return nil, err
	}

	burned, _ := math.NewIntFromString(res.Burned)

	if err := p.EmitPoolBurnedEvent(ctx, stateDB, caller, burned.BigInt()); err != nil {
		return nil, err
	}

	return method.Outputs.Pack(burned.BigInt())
}
