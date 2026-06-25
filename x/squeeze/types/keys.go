package types

// The "Squeeze" fee module: on-chain split of the materialized fee_collector
// balance each block, run immediately BEFORE x/distribution.
const (
	// ModuleName is the squeeze module name and its (burner) module account.
	ModuleName = "squeeze"

	// GasPoolName is the protocol gas pool module account (no minter/burner
	// permission, no withdraw path). It receives the recycled fee slice and is the
	// sponsor account the paymaster draws from to pay users' fees (gasless UX).
	// The only outflow is the protocol paying gas; there is no claim/withdraw path.
	GasPoolName = "paymaster_gas_pool"

	// FeeDenom is the native gas/fee base denom that Squeeze splits.
	FeeDenom = "aLIMO"

	// Split, in basis points of the materialized fee_collector balance, applied
	// each block. The validator slice (the remainder, ~50%) plus rounding dust is
	// LEFT in fee_collector so x/distribution allocates it through the normal
	// proposer/delegator/commission/community-tax path (PoS correctness).
	BurnBps  = 4000 // 40% burned (the only burn on the chain)
	GrantBps = 1000 // 10% recycled into the gas pool (the gasless loop)
	BpsDenom = 10000

	// ConsensusVersion of the squeeze module.
	ConsensusVersion = 1
)
