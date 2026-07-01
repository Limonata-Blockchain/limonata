package types

const (
	// ModuleName is the x/valgrant module name. It is ALSO the name of the
	// valgrant module account (the grant reserve pool; maccPerm nil).
	ModuleName = "valgrant"
	// StoreKey is the x/valgrant store key.
	StoreKey = ModuleName
	// ConsensusVersion is the module consensus version for migrations.
	ConsensusVersion = 1
)

// Store layout (single-byte key prefixes), mirroring x/contest's JSON-in-store.
var (
	ParamsKey           = []byte{0x01} // -> JSON Params
	GrantsPrefix        = []byte{0x02} // 0x02 | grantee(bech32) -> JSON Grant
	PendingClawbackPref = []byte{0x03} // 0x03 | grantee(bech32) -> JSON PendingClawback
	KPISnapshotKey      = []byte{0x04} // -> JSON KPISnapshot (latest decentralization snapshot)
)
