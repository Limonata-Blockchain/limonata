package sponsorpool

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	_ "embed"

	cmn "github.com/cosmos/evm/precompiles/common"
	sponsorpoolkeeper "github.com/cosmos/evm/x/sponsorpool/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

var _ vm.PrecompiledContract = &Precompile{}

var (
	// Embed abi json file to the executable binary. Needed when importing as dependency.
	//
	//go:embed abi.json
	f   []byte
	ABI abi.ABI
)

func init() {
	var err error
	ABI, err = abi.JSON(bytes.NewReader(f))
	if err != nil {
		panic(err)
	}
}

const (
	// DepositMethod funds a contract's gas escrow (payable; msg.value is the deposit).
	DepositMethod = "deposit"
	// WithdrawMethod reclaims a sponsor's unspent contribution to a contract.
	WithdrawMethod = "withdraw"
	// EscrowOfMethod is a view returning a contract's remaining gas escrow.
	EscrowOfMethod = "escrowOf"
	// ContributionOfMethod is a view returning a sponsor's withdrawable contribution.
	ContributionOfMethod = "contributionOf"
)

// Precompile is the EVM interface to x/sponsorpool: developers deposit native LIMO to fund
// gas for a specific contract (permissionless), and withdraw what has not been spent.
type Precompile struct {
	cmn.Precompile

	abi.ABI
	keeper sponsorpoolkeeper.Keeper
}

// NewPrecompile creates a new sponsorpool Precompile. The BalanceHandlerFactory mirrors the
// keeper's x/bank moves (deposit -> pool, pool -> caller on withdraw) into the EVM StateDB so
// balances stay consistent with the EVM view.
func NewPrecompile(k sponsorpoolkeeper.Keeper, bankKeeper cmn.BankKeeper) *Precompile {
	return &Precompile{
		Precompile: cmn.Precompile{
			KvGasConfig:           storetypes.KVGasConfig(),
			TransientKVGasConfig:  storetypes.TransientGasConfig(),
			ContractAddress:       common.HexToAddress(evmtypes.SponsorPoolPrecompileAddress),
			BalanceHandlerFactory: cmn.NewBalanceHandlerFactory(bankKeeper),
		},
		ABI:    ABI,
		keeper: k,
	}
}

// Name returns the name of the precompile.
func (Precompile) Name() string { return "sponsorpool" }

// RequiredGas returns the minimum gas to execute the precompile.
func (p Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	method, err := p.MethodById(input[:4])
	if err != nil {
		return 0
	}
	return p.Precompile.RequiredGas(input, p.IsTransaction(method))
}

// Run executes the precompile inside a native cosmos action so state writes commit/revert
// atomically with the EVM tx.
func (p Precompile) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	return p.RunNativeAction(evm, contract, func(ctx sdk.Context) ([]byte, error) {
		return p.Execute(ctx, evm.StateDB, contract, readonly)
	})
}

// Execute dispatches the ABI method to its handler.
func (p Precompile) Execute(ctx sdk.Context, stateDB vm.StateDB, contract *vm.Contract, readOnly bool) ([]byte, error) {
	method, args, err := cmn.SetupABI(p.ABI, contract, readOnly, p.IsTransaction)
	if err != nil {
		return nil, err
	}
	switch method.Name {
	case DepositMethod:
		return p.Deposit(ctx, contract, method, args)
	case WithdrawMethod:
		return p.Withdraw(ctx, contract, method, args)
	case EscrowOfMethod:
		return p.EscrowOf(ctx, method, args)
	case ContributionOfMethod:
		return p.ContributionOf(ctx, method, args)
	default:
		return nil, fmt.Errorf(cmn.ErrUnknownMethod, method.Name)
	}
}

// IsTransaction reports whether a method writes state (deposit/withdraw) vs is a view.
func (Precompile) IsTransaction(method *abi.Method) bool {
	switch method.Name {
	case DepositMethod, WithdrawMethod:
		return true
	default:
		return false
	}
}
