package types

import "encoding/json"

// ============================================================================
// ABCI++ vote-extension payload for the TRANSPARENT in-node DKG.
//
// A validator's node attaches this to its consensus pre-commit vote (ExtendVote).
// It is signed BY COMETBFT with the node's ed25519 consensus key and auto-tagged
// with the node's consensus address, so the operator does NOTHING: no tx, no
// account, no fees, no separate daemon. The proposer collects the H-1 extensions
// (RequestPrepareProposal.LocalLastCommit), injects the whole ExtendedCommitInfo as
// an injected block-data pseudo-tx, ProcessProposal re-runs ValidateVoteExtensions,
// and a PreBlocker deterministically consumes the payloads into module state.
//
// It is PLAIN JSON with a leading version byte (the module stores everything as
// JSON-in-store, and CometBFT carries the extension bytes verbatim + signed, so
// there is no need for canonical proto here — we NEVER re-derive these bytes in a
// consensus-critical path; we consume the verbatim, signed bytes from the committed
// block).
// ============================================================================

// VoteExtVersion is the leading discriminator byte of a marshalled VoteExtension.
// A future format change bumps it; an unknown version is treated as "no payload"
// (safe: the node simply does not participate until it is upgraded).
const VoteExtVersion byte = 1

// VoteExtMaxBytes is the hard upper bound on a single vote extension. VerifyVoteExtension
// REJECTS anything larger so a peer cannot bloat the block via an oversized extension.
// Sized well above a legitimate extension (a committee-capped dealing + a bounded batch
// of decryption shares is a few KB..tens of KB).
const VoteExtMaxBytes = 1 << 20 // 1 MiB

// VoteExtension is the per-node DKG contribution carried on a consensus vote.
type VoteExtension struct {
	// EncPubKey is this node's announced compressed secp256k1 ECIES key (33 bytes).
	// It is auto-generated on first boot and announced idempotently in EVERY extension;
	// the PreBlocker records it keyed to the node's operator (resolved from the consensus
	// address CometBFT tags the extension with). It ALSO doubles as the node's
	// self-identifier: a node finds its own DKG member index by matching this key against
	// the recorded round member set, so the consensus key never needs threading into the
	// app.
	EncPubKey []byte `json:"enc_pubkey,omitempty"`

	// EncPubKeyPoP is a PROOF-OF-POSSESSION for EncPubKey: an ECDSA signature by the enc
	// PRIVATE key over the announcing operator's identity (see dkg.SignEncKeyPoP). The
	// consume path verifies it before recording the key, so a node cannot announce a key it
	// does not control (e.g. a victim's observed public key) — HIGH-2 / HIGH-4. It is bound
	// to the operator, so it is not replayable by a different validator.
	EncPubKeyPoP []byte `json:"enc_pubkey_pop,omitempty"`

	// Dealing, when present, is this node's Feldman dealing for the currently-open DKG
	// epoch (it replaces the MsgDkgDeal tx path).
	Dealing *VoteExtDealing `json:"dealing,omitempty"`

	// Shares, when present, are this node's DLEQ-proved threshold decryption shares for
	// in-flight ciphertexts that have not yet matured (it replaces the
	// MsgSubmitDecryptionShare tx path).
	Shares []VoteExtShare `json:"shares,omitempty"`
}

// VoteExtDealing is a dealer's contribution for one epoch, carried on a vote.
type VoteExtDealing struct {
	Epoch       uint64              `json:"epoch"`
	Commitments [][]byte            `json:"commitments"`
	EncShares   []DkgStoredEncShare `json:"enc_shares"`
}

// VoteExtShare is one DLEQ-proved decryption share for an in-flight ciphertext.
type VoteExtShare struct {
	Epoch         uint64 `json:"epoch"`
	DecryptHeight uint64 `json:"decrypt_height"`
	Seq           uint64 `json:"seq"`
	Index         uint64 `json:"index"`
	D             []byte `json:"d"`
	Proof         []byte `json:"proof"`
}

// MarshalVoteExtension serializes a VoteExtension with the leading version byte.
func MarshalVoteExtension(ve VoteExtension) []byte {
	b, err := json.Marshal(ve)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, len(b)+1)
	out = append(out, VoteExtVersion)
	return append(out, b...)
}

// UnmarshalVoteExtension parses bytes produced by MarshalVoteExtension. It returns
// ok=false for an empty payload, an unknown version, or malformed JSON — the caller
// then treats the extension as carrying no DKG data (a benign no-op), which is what
// keeps a stray/old-binary extension from ever halting the consume path.
func UnmarshalVoteExtension(b []byte) (VoteExtension, bool) {
	if len(b) < 1 || b[0] != VoteExtVersion {
		return VoteExtension{}, false
	}
	var ve VoteExtension
	if err := json.Unmarshal(b[1:], &ve); err != nil {
		return VoteExtension{}, false
	}
	return ve, true
}
