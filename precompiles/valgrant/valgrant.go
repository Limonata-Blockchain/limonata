package valgrant

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	_ "embed"

	cmn "github.com/cosmos/evm/precompiles/common"
	valgrantkeeper "github.com/cosmos/evm/x/valgrant/keeper"
	valgranttypes "github.com/cosmos/evm/x/valgrant/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"cosmossdk.io/log/v2"

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
	// IssueGrantMethod is the ABI method name for issuing a locked grant.
	IssueGrantMethod = "issueGrant"
	// ClawbackMethod is the ABI method name for clawing back a grant.
	ClawbackMethod = "clawback"
	// BurnPoolMethod is the ABI method name for permanently burning pool LIMO.
	BurnPoolMethod = "burnPool"
)

// Precompile defines the admin-only precompiled contract for x/valgrant.
//
// It exposes issueGrant/clawback callable directly (EOA only) from the admin
// wallet. Admin gating is enforced by the x/valgrant msg_server: the precompile
// derives the caller's cosmos bech32 address and sets it as the Msg.Admin field,
// then routes through the keeper's MsgServer which checks it against Params.admin.
type Precompile struct {
	cmn.Precompile

	abi.ABI
	valgrantKeeper valgrantkeeper.Keeper
	msgServer      valgranttypes.MsgServer
}

// NewPrecompile creates a new valgrant Precompile instance as a
// PrecompiledContract interface.
func NewPrecompile(
	valgrantKeeper valgrantkeeper.Keeper,
	bankKeeper cmn.BankKeeper,
) *Precompile {
	// NOTE: we intentionally do NOT attach a BalanceHandlerFactory here.
	//
	// The valgrant flows move funds to/from THIRD-PARTY cosmos accounts (the
	// grantee and the valgrant module pool), never the EVM tx sender, and one of
	// them (clawback) converts the grantee's account type (PermanentLockedAccount
	// -> BaseAccount) mid-call. The BalanceHandler mirrors x/bank coin_spent/
	// coin_received events into the EVM StateDB, which then re-serializes those
	// accounts on Commit and clobbers the keeper-level SendCoins (the grantee's
	// principal sweep was being reverted). Without the handler, the precompile's
	// raw multistore writes (the SendCoins + the account conversion) are committed
	// directly via the StateDB writeCache and persist correctly. This is safe here
	// because the tx sender's (admin's) balance is not touched by the module logic
	// beyond normal EVM gas accounting.
	return &Precompile{
		Precompile: cmn.Precompile{
			KvGasConfig:          storetypes.KVGasConfig(),
			TransientKVGasConfig: storetypes.TransientGasConfig(),
			ContractAddress:      common.HexToAddress(evmtypes.ValGrantPrecompileAddress),
		},
		ABI:            ABI,
		valgrantKeeper: valgrantKeeper,
		msgServer:      valgrantkeeper.NewMsgServerImpl(valgrantKeeper),
	}
}

// Name returns the name of the precompile.
func (Precompile) Name() string {
	return "valgrant"
}

// RequiredGas returns the required bare minimum gas to execute the precompile.
func (p Precompile) RequiredGas(input []byte) uint64 {
	// NOTE: This check avoids panicking when trying to decode the method ID.
	if len(input) < 4 {
		return 0
	}

	methodID := input[:4]

	method, err := p.MethodById(methodID)
	if err != nil {
		// This should never happen since this method is going to fail during Run.
		return 0
	}

	return p.Precompile.RequiredGas(input, p.IsTransaction(method))
}

// Run executes the precompile inside a native cosmos action so state writes
// commit/revert atomically with the EVM tx.
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

	var bz []byte

	switch method.Name {
	case IssueGrantMethod:
		bz, err = p.IssueGrant(ctx, contract, stateDB, method, args)
	case ClawbackMethod:
		bz, err = p.Clawback(ctx, contract, stateDB, method, args)
	case BurnPoolMethod:
		bz, err = p.BurnPool(ctx, contract, stateDB, method, args)
	default:
		return nil, fmt.Errorf(cmn.ErrUnknownMethod, method.Name)
	}

	return bz, err
}

// IsTransaction checks if the given method name corresponds to a transaction.
func (Precompile) IsTransaction(method *abi.Method) bool {
	switch method.Name {
	case IssueGrantMethod, ClawbackMethod, BurnPoolMethod:
		return true
	default:
		return false
	}
}

// Logger returns a precompile-specific logger.
func (p Precompile) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("evm extension", "valgrant")
}
