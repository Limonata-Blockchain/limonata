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
)
