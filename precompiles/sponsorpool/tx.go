package sponsorpool

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Deposit funds `target`'s gas escrow with `amount` LIMO pulled from the caller's balance via
// x/bank (non-payable: 0x901 is a blocked address and cannot receive msg.value). The attached
// BalanceHandler mirrors the caller's debit into the EVM StateDB so balances stay consistent.
func (p Precompile) Deposit(ctx sdk.Context, contract *vm.Contract, method *abi.Method, args []interface{}) ([]byte, error) {
	target, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid target address: %T", args[0])
	}
	amount, ok := args[1].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid amount: %T", args[1])
	}
	caller := sdk.AccAddress(contract.Caller().Bytes())
	if err := p.keeper.Deposit(ctx, caller, strings.ToLower(target.Hex()), math.NewIntFromBigInt(amount)); err != nil {
		return nil, err
	}
	return method.Outputs.Pack(true)
}

// Withdraw returns up to the caller's unspent contribution to `target` back to the caller.
func (p Precompile) Withdraw(ctx sdk.Context, contract *vm.Contract, method *abi.Method, args []interface{}) ([]byte, error) {
	target, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid target address: %T", args[0])
	}
	amount, ok := args[1].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid amount: %T", args[1])
	}
	caller := sdk.AccAddress(contract.Caller().Bytes())
	if err := p.keeper.Withdraw(ctx, caller, strings.ToLower(target.Hex()), math.NewIntFromBigInt(amount)); err != nil {
		return nil, err
	}
	return method.Outputs.Pack(true)
}

// EscrowOf returns a contract's remaining gas escrow (view).
func (p Precompile) EscrowOf(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	target, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid target address: %T", args[0])
	}
	return method.Outputs.Pack(p.keeper.EscrowOf(ctx, strings.ToLower(target.Hex())).BigInt())
}

// ContributionOf returns a sponsor's withdrawable contribution to a contract (view).
func (p Precompile) ContributionOf(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	sponsor, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid sponsor address: %T", args[0])
	}
	target, ok := args[1].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid target address: %T", args[1])
	}
	return method.Outputs.Pack(p.keeper.ContributionOf(ctx, sdk.AccAddress(sponsor.Bytes()), strings.ToLower(target.Hex())).BigInt())
}
