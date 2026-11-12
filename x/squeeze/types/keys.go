package types

// The "Squeeze" fee module: on-chain split of the materialized fee_collector
// balance each block, run immediately BEFORE x/distribution.
const (
	// ModuleName is the squeeze module name and its (burner) module account.
	ModuleName = "squeeze"

	// StoreKey is the squeeze store key. Squeeze became stateful in v0.3.0 when the
	// fee-split ratios were promoted from compile-time consts to governable params
	// (a single JSON Params blob at ParamsKey), mirroring x/gassponsor.
	StoreKey = ModuleName

	// GasPoolName is the protocol gas pool module account (no minter/burner
	// permission, no withdraw path). It receives the recycled fee slice and is the
	// sponsor account the paymaster draws from to pay users' fees (gasless UX).
	// The only outflow is the protocol paying gas; there is no claim/withdraw path.
	GasPoolName = "paymaster_gas_pool"

	// FeeDenom is the native gas/fee base denom that Squeeze splits.
	FeeDenom = "aLIMO"

	// Split, in basis points of the materialized fee_collector balance, applied
	// each block. The validator slice (the remainder) plus rounding dust is
	// LEFT in fee_collector so x/distribution allocates it through the normal
	// proposer/delegator/commission/community-tax path (PoS correctness).
	//
	// NOTE (v0.3.0): these are now DEFAULT FALLBACKS only. The live split is read
	// from governable Params (see params.go); DefaultParams seeds burn=2000/grant=2000
	// (20% burn / 20% gas-pool recycle / 60% validators). BeginBlock reads params, not
	// these consts. They remain so pre-params code paths / tests still have a constant.
	BurnBps  = 2000 // default 20% burned (the only burn on the chain)
	GrantBps = 2000 // default 20% recycled into the gas pool (the gasless loop)
	BpsDenom = 10000

	// ConsensusVersion of the squeeze module.
	ConsensusVersion = 1
)

// Store layout (single-byte key prefixes).
var (
	ParamsKey = []byte{0x01} // -> JSON Params (governable fee split)
)
