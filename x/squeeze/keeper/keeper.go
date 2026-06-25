package keeper

import (
	"github.com/cosmos/evm/x/squeeze/types"
)

// Keeper for the squeeze fee module. Stateless: the split parameters are
// compile-time constants (see types/keys.go), so there is no store key and no
// genesis state. It only moves coins via the bank keeper at BeginBlock.
type Keeper struct {
	bankKeeper       types.BankKeeper
	feeCollectorName string
}

// NewKeeper returns a squeeze keeper. feeCollectorName is authtypes.FeeCollectorName.
func NewKeeper(bk types.BankKeeper, feeCollectorName string) Keeper {
	return Keeper{bankKeeper: bk, feeCollectorName: feeCollectorName}
}
