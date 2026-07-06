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
	// EpochEncCountPrefix ref-counts the in-flight (un-matured) EncTx stamped to an
	// epoch, so a superseded active epoch's DkgRound + ActiveThresholdKey can be GC'd
	// the instant it has ZERO pending ciphertexts — bounding retained active-epoch
	// state to O(pending epochs) instead of O(total rekeys) (HIGH-2 variant fix).
	EpochEncCountPrefix = []byte{0x16} // 0x16 | be(epoch) -> uint64 (be): # of un-matured EncTx for the epoch
	// LastRekeyHeightKey records the height of the last member-change re-genesis, so a
	// rapid membership FLAP cannot mint fresh rounds / reset the retry backoff faster
	// than DkgMinRekeyGap blocks (a genuine settled change is preceded by stability and
	// is therefore never delayed).
	LastRekeyHeightKey = []byte{0x17} // -> uint64 (be): height of the last member-change rekey

	// --- encrypted-tx admission-control ref-counts (bound in-flight EncTx state) ---
	// GlobalEncCountKey ref-counts the TOTAL in-flight (un-matured) EncTx, so SubmitEncrypted
	// can REJECT a submission at ingress once the global ceiling is reached and the BeginBlock
	// decrypt path can shed excess with a loud, deterministic drop if state ever exceeds the
	// absolute ceiling. Maintained (inc on submit, dec on every EncTx delete) so the check is
	// O(1) — never an O(backlog) scan.
	GlobalEncCountKey = []byte{0x18} // -> uint64 (be): # of un-matured EncTx across all submitters
	// SubmitterEncCountPrefix ref-counts the in-flight EncTx per submitter, so one flooder can
	// be capped at ingress (per-submitter admission) without an O(backlog) scan. The record is
	// deleted when it returns to zero, so live counters stay O(submitters with pending ct) —
	// itself bounded by the global ceiling.
	SubmitterEncCountPrefix = []byte{0x19} // 0x19 | submitter -> uint64 (be): # of un-matured EncTx for that submitter

	// --- TRANSPARENT in-node DKG (ABCI++ vote extensions) ---
	// EncPubKeyPrefix records a bonded validator's AUTO-ANNOUNCED DKG enc pubkey, keyed by
	// its operator address. The PreBlocker writes it when it consumes a vote extension that
	// announced a (new) key; ActiveMembers reads it to derive the transparent member set
	// (bonded validators that have registered an enc key). Idempotent: only rewritten when
	// the announced key differs from the stored one.
	EncPubKeyPrefix = []byte{0x1A} // 0x1A | operatorAddr -> 33-byte compressed secp256k1 pubkey
	// EncKeyOwnerPrefix is the REVERSE index of EncPubKeyPrefix: it maps an announced enc
	// pubkey back to the single operator that owns it, so RecordEncPubKey can enforce
	// CROSS-OPERATOR UNIQUENESS (reject a key already bound to a different operator) in O(1)
	// without an O(committee) scan. Maintained in lock-step with the forward index: written
	// on first announce / rotation, deleted when an operator rotates its key. (HIGH-2/HIGH-4.)
	EncKeyOwnerPrefix = []byte{0x1B} // 0x1B | 33-byte compressed pubkey -> operatorAddr
	// DkgComplaintRejectedPrefix is the deterministic NEGATIVE-CACHE for the transparent
	// complaint path: once a complaint from (accuser) against (dealer) has been DLEQ-verified
	// and REJECTED (framing / frivolous), a marker is written here so a re-sent garbage
	// complaint is dropped by an O(1) lookup BEFORE re-charging the O(t) DLEQ verify — a
	// byzantine accuser gets at most ONE verify per targeted dealer per epoch, never a
	// per-block re-charge that would starve honest complaints out of the per-block budget.
	DkgComplaintRejectedPrefix = []byte{0x1C} // 0x1C | be(epoch) | be(against) | be(accuser) -> {1}
	// EncSubmitRatePrefix is the PER-SUBMITTER per-block admission RATE counter (Fix 1 C3'): the
	// missing rate dimension on top of the standing MaxInFlightPerSubmitter inventory cap. One record
	// per submitter (reused across blocks, lazily height-reset), storing be(height)||be(count), so the
	// increment is O(1) in canonical DeliverTx order and never leaks. It is PER-SUBMITTER (never a
	// single global slot) so no one address can monopolize ingress or let a proposer censor the
	// encrypted mempool by ordering its own ciphertexts first.
	EncSubmitRatePrefix = []byte{0x1D} // 0x1D | submitter -> be(height)||be(count) (16 bytes)
	// ActiveShareKeyPrefix caches the epoch's PUBLIC share keys Y_index = SharePubKey(PublicCommitments,
	// index), precomputed once at finalize (Fix 1 C4'), so each decryption-share DLEQ verify is an O(1)
	// cache read instead of an O(t) Horner recompute — the block-time flattener that closes HIGH-U's
	// per-verify cost. Pinned to the epoch: deleted together with the ActiveThresholdKey when the epoch
	// is superseded + drained (so it always outlives every in-flight ciphertext of the epoch).
	ActiveShareKeyPrefix = []byte{0x1E} // 0x1E | be(epoch) | be(index) -> 33-byte compressed Y_index
)
