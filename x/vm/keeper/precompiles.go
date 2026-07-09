package keeper

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	evmtrace "github.com/cosmos/evm/trace"
	"github.com/cosmos/evm/x/vm/types"

	sdktypes "github.com/cosmos/cosmos-sdk/types"
)

// blockPrecompilesCtxKey marks a context whose EVM must REJECT every precompile call (round-11 #1).
type blockPrecompilesCtxKey struct{}

// WithBlockedPrecompiles returns a context whose EVM (built via NewEVMWithOverridePrecompiles)
// REJECTS any call whose recipient is a precompile - at ANY call depth, so a contract or constructor
// sub-calling a bank/staking/gov/IBC/... precompile is blocked, not just a top-level call. The
// encrypted-mempool decrypt->execute path uses this so a tx executed in BeginBlock (outside the
// normal ante pipeline) can never reach a native module precompile. The block is deterministic: the
// call hook reads only committed precompile-registry state and returns the same error on every node,
// so the tx (or sub-call) reverts identically everywhere.
func WithBlockedPrecompiles(ctx sdktypes.Context) sdktypes.Context {
	return ctx.WithValue(blockPrecompilesCtxKey{}, true)
}

func precompilesBlocked(ctx sdktypes.Context) bool {
	v, ok := ctx.Value(blockPrecompilesCtxKey{}).(bool)
	return ok && v
}

// GetPrecompileBlockingCallHook returns a call hook that REJECTS any call targeting a precompile
// (round-11 #1). It runs on every CALL frame (the EVM invokes the hook before installing the
// precompile), so it blocks sub-calls, not only the top-level To. Returning an error fails that call
// with full gas and never installs/executes the precompile.
func (k *Keeper) GetPrecompileBlockingCallHook(ctx sdktypes.Context) types.CallHook {
	return func(_ *vm.EVM, _ common.Address, recipient common.Address) error {
		_, found, err := k.GetPrecompileInstance(ctx, recipient)
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("precompile %s is not callable from decrypted-tx execution", recipient.Hex())
		}
		return nil
	}
}

type Precompiles struct {
	Map       map[common.Address]vm.PrecompiledContract
	Addresses []common.Address
}

// GetPrecompileInstance returns the address and instance of the static or dynamic precompile associated with the
// given address, or return nil if not found.
func (k *Keeper) GetPrecompileInstance(
	ctx sdktypes.Context,
	address common.Address,
) (_ *Precompiles, _ bool, err error) {
	ctx, span := ctx.StartSpan(tracer, "GetPrecompileInstance", trace.WithAttributes(
		attribute.String("address", address.Hex()),
	))
	defer func() { evmtrace.EndSpanErr(span, err) }()
	params := k.GetParams(ctx)
	// Get the precompile from the static precompiles
	if precompile, found, err := k.GetStaticPrecompileInstance(&params, address); err != nil {
		return nil, false, err
	} else if found {
		addressMap := make(map[common.Address]vm.PrecompiledContract)
		addressMap[address] = precompile
		return &Precompiles{
			Map:       addressMap,
			Addresses: []common.Address{precompile.Address()},
		}, found, nil
	}

	// Since erc20Keeper is optional, we check if it is nil, in which case we just return that we didn't find the precompile
	if k.erc20Keeper == nil {
		return nil, false, nil
	}

	// Get the precompile from the dynamic precompiles
	precompile, found, err := k.erc20Keeper.GetERC20PrecompileInstance(ctx, address)
	if err != nil || !found {
		return nil, false, err
	}
	addressMap := make(map[common.Address]vm.PrecompiledContract)
	addressMap[address] = precompile
	return &Precompiles{
		Map:       addressMap,
		Addresses: []common.Address{precompile.Address()},
	}, found, nil
}

// GetPrecompilesCallHook returns a closure that can be used to instantiate the EVM with a specific
// precompile instance.
func (k *Keeper) GetPrecompilesCallHook(ctx sdktypes.Context) types.CallHook {
	return func(evm *vm.EVM, _ common.Address, recipient common.Address) (err error) {
		ctx, span := ctx.StartSpan(tracer, "PrecompileCallHook", trace.WithAttributes(
			attribute.String("recipient", recipient.Hex()),
		))
		defer func() { evmtrace.EndSpanErr(span, err) }()
		// Check if the recipient is a precompile contract and if so, load the precompile instance
		precompiles, found, err := k.GetPrecompileInstance(ctx, recipient)
		if err != nil {
			return err
		}

		// If the precompile instance is created, we have to update the EVM with
		// only the recipient precompile and add it's address to the access list.
		if found {
			evm.WithPrecompiles(precompiles.Map)
			evm.StateDB.AddAddressToAccessList(recipient)
		}

		return nil
	}
}

// GetPrecompileRecipientCallHook returns a call hook for use with state overrides.
// It checks active precompiles first, then only dynamic precompiles (not static ones
// which may have been moved/disabled by state overrides).
func (k *Keeper) GetPrecompileRecipientCallHook(ctx sdktypes.Context) types.CallHook {
	return func(evm *vm.EVM, _ common.Address, recipient common.Address) (err error) {
		ctx, span := ctx.StartSpan(tracer, "PrecompileRecipientCallHook", trace.WithAttributes(
			attribute.String("recipient", recipient.Hex()),
		))
		defer func() { evmtrace.EndSpanErr(span, err) }()
		if _, ok := evm.Precompile(recipient); ok {
			evm.StateDB.AddAddressToAccessList(recipient)
			return nil
		}
		if k.erc20Keeper == nil {
			return nil
		}
		precompile, found, err := k.erc20Keeper.GetERC20PrecompileInstance(ctx, recipient)
		if err != nil || !found {
			return err
		}
		addressMap := make(map[common.Address]vm.PrecompiledContract)
		addressMap[recipient] = precompile
		evm.WithPrecompiles(addressMap)
		evm.StateDB.AddAddressToAccessList(recipient)
		return nil
	}
}
