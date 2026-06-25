package types

const (
	// ModuleName is the x/netcap module name (net-seller cap).
	ModuleName = "netcap"
	// StoreKey is the x/netcap store key.
	StoreKey = ModuleName
	// ConsensusVersion is the module consensus version for migrations.
	ConsensusVersion = 1
)

// Store layout (single-byte key prefixes), plain JSON-in-store (no proto),
// mirroring x/valgrant.
var (
	ParamsKey   = []byte{0x01} // -> JSON Params
	SpendPrefix = []byte{0x02} // 0x02 | restricted-addr(bech32) -> JSON WindowSpend
)
