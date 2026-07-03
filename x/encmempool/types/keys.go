package types

const (
	// ModuleName is the x/encmempool module name.
	ModuleName = "encmempool"
	// StoreKey is the x/encmempool store key.
	StoreKey = ModuleName
	// ConsensusVersion is the module consensus version for migrations.
	ConsensusVersion = 1
)

// Store layout (single-byte key prefixes). Heights and seqs are big-endian so
// that lexicographic store-key order equals (commitHeight, sender, seq) order,
// which is the determinism guarantee for BeginBlock execution.
var (
	ParamsKey     = []byte{0x01} // -> JSON Params
	SeqKey        = []byte{0x02} // -> uint64 (big-endian) monotonic commit counter
	CommitPrefix  = []byte{0x03} // 0x03 | be(height) | sender | be(seq) -> JSON Commit
	PendingPrefix = []byte{0x04} // 0x04 | be(commitHeight) | sender | be(seq) -> JSON PendingReveal
	// --- threshold encryption path ---
	EncSeqKey      = []byte{0x05} // -> uint64 (big-endian) monotonic enc-tx counter
	EncTxPrefix    = []byte{0x06} // 0x06 | be(decryptHeight) | be(seq) -> JSON EncTx
	EncSharePrefix = []byte{0x07} // 0x07 | be(decryptHeight) | be(seq) | keyper -> JSON EncShare

	// --- on-chain validator DKG (epoch = uint64 round id) ---
	DkgRoundPrefix     = []byte{0x10} // 0x10 | be(epoch) -> JSON DkgRound
	DkgDealPrefix      = []byte{0x11} // 0x11 | be(epoch) | be(dealerIndex) -> JSON Dealing
	DkgComplaintPrefix = []byte{0x12} // 0x12 | be(epoch) | be(against) | be(accuser) -> JSON DkgComplaint
	ActiveKeyPrefix    = []byte{0x13} // 0x13 | be(epoch) -> JSON ActiveThresholdKey
	CurrentEpochKey    = []byte{0x14} // -> uint64 (be): latest round opened
	ActiveEpochKey     = []byte{0x15} // -> uint64 (be): epoch of the currently-serving active key
)
