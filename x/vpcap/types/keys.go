package types

const (
	// ModuleName is the x/vpcap (validator voting-power cap) module name.
	ModuleName = "vpcap"
	// StoreKey is the x/vpcap store key.
	StoreKey = ModuleName
	// ConsensusVersion is the module consensus version for migrations.
	ConsensusVersion = 1
)

// Store layout (single-byte key prefixes), JSON-in-store (mirrors x/valgrant).
var (
	ParamsKey      = []byte{0x01} // -> JSON Params
	LastSentPrefix = []byte{0x02} // 0x02 | consAddr(bytes) -> JSON LastSent
)
