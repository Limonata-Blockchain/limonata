package types

import squeezetypes "github.com/cosmos/evm/x/squeeze/types"

const (
	// ModuleName is the gassponsor module name and its (minter) module account.
	ModuleName = "gassponsor"
	// StoreKey is the gassponsor store key.
	StoreKey = ModuleName
	// ConsensusVersion of the module.
	ConsensusVersion = 1
)

// Reuse the existing protocol gas pool + fee denom from x/squeeze. Do NOT define a
// second pool account: gassponsor mints into the SAME paymaster_gas_pool that squeeze
// recycles into and that pays users' EVM fees.
const (
	GasPoolName = squeezetypes.GasPoolName // "paymaster_gas_pool"
	FeeDenom    = squeezetypes.FeeDenom    // "aLIMO"
)

// Store layout (single-byte key prefixes).
var (
	ParamsKey         = []byte{0x01} // -> JSON Params
	AllowancePrefix   = []byte{0x02} // 0x02 | day(8) | sender -> used aLIMO (math.Int as decimal string)
	MintedTodayPrefix = []byte{0x03} // 0x03 | day(8) -> cumulative refill-minted aLIMO today (math.Int as decimal string)
)
