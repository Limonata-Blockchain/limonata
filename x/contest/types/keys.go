package types

const (
	// ModuleName is the x/contest module name.
	ModuleName = "contest"
	// StoreKey is the x/contest store key.
	StoreKey = ModuleName
	// ConsensusVersion is the module consensus version for migrations.
	ConsensusVersion = 1
)

// Store layout (single-byte key prefixes).
var (
	ParamsKey          = []byte{0x01} // -> JSON Params
	ShowcasePrefix     = []byte{0x02} // 0x02 | contractAddr(lower-hex) -> JSON ShowcaseApp
	DevStatsPrefix     = []byte{0x03} // 0x03 | dev                      -> JSON DevStats
	TesterPointsPrefix = []byte{0x04} // 0x04 | tester                  -> uint64 (big-endian)
	DailyUAWPrefix     = []byte{0x05} // 0x05 | day(8) | tester         -> 0x01 (seen today; rolled up in EndBlock)
	SnapshotDoneKey    = []byte{0x06} // -> 0x01 once the leaderboard is frozen
)
