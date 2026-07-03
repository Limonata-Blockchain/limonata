package types

import "fmt"

// Params govern the commit-reveal timing. RevealDelay is the minimum number of
// blocks between a commit and its reveal; MaxRevealWindow bounds how long an
// unrevealed commit lingers in state before it is garbage-collected.
type Params struct {
	RevealDelay     uint64 `json:"reveal_delay"`
	MaxRevealWindow uint64 `json:"max_reveal_window"`

	// --- threshold encryption (OPT-IN; OFF by default so the binary is inert
	// until governance activates it — the same safety pattern as x/vpcap) ---
	EncEnabled   bool     `json:"enc_enabled"`   // master switch for the encrypted path
	ThresholdPub []byte   `json:"threshold_pub"` // compressed threshold public key Y = x*G (LEGACY trusted-setup path)
	Threshold    uint32   `json:"threshold"`     // t: decryption shares required (LEGACY path)
	Keypers      []string `json:"keypers"`       // authorized keyper addrs (bech32); share index = position+1 (LEGACY path)
	DecryptDelay uint64   `json:"decrypt_delay"` // blocks between submit and decrypt-execute

	// --- on-chain validator DKG (OPT-IN; supersedes the LEGACY trusted setup
	// above when enabled). The active threshold key is then produced by the
	// validators' DKG (stored per-epoch), not by params.ThresholdPub. ---
	DkgEnabled         bool        `json:"dkg_enabled"`          // run the validator DKG + use its key
	DkgStartHeight     uint64      `json:"dkg_start_height"`     // open epoch 1 at/after this height
	DkgDealWindow      uint64      `json:"dkg_deal_window"`      // blocks a dealer has to post its dealing
	DkgComplaintWindow uint64      `json:"dkg_complaint_window"` // blocks for complaints after the deal window
	DkgThreshold       uint32      `json:"dkg_threshold"`        // t for the DKG; 0 => majority floor(n/2)+1
	DkgMembers         []DkgMember `json:"dkg_members"`          // genesis-declared member set (operator+account+enc key)
}

// DkgMember is a genesis-declared DKG participant. For this PoC the member set is
// declared (rather than derived from validator keys) so the chain need not wait for
// x/auth to have seen a pubkey; the ACTIVE member set each round is this list
// INTERSECTED with the currently-bonded validators (matched by OperatorAddr), which
// is what drives the Shutter/Penumbra-style re-run when the validator set changes.
// Production would derive EncPubKey from the validator's registered/consensus key.
type DkgMember struct {
	OperatorAddr string `json:"operator_addr"` // validator operator address (valoper bech32)
	AccountAddr  string `json:"account_addr"`  // the member's fee/signer account (bech32) = MsgDkgDeal.dealer
	EncPubKey    []byte `json:"enc_pubkey"`    // compressed secp256k1 encryption key (shares are sealed to this)
}

// RoundMember is a DkgMember with its assigned 1-based index for a specific round
// (rank by OperatorAddr among the active members at round-open).
type RoundMember struct {
	Index        uint64 `json:"index"`
	OperatorAddr string `json:"operator_addr"`
	AccountAddr  string `json:"account_addr"`
	EncPubKey    []byte `json:"enc_pubkey"`
}

// DKG round status values.
const (
	DkgStatusOpen   = "open"   // dealing/complaint windows are in progress
	DkgStatusActive = "active" // finalized successfully; an ActiveThresholdKey was installed
	DkgStatusFailed = "failed" // |QUAL| < t; the previous active key (if any) is kept
)

// DkgRound is one DKG epoch's on-chain record.
type DkgRound struct {
	Epoch             uint64        `json:"epoch"`
	OpenHeight        uint64        `json:"open_height"`
	DealDeadline      uint64        `json:"deal_deadline"`      // deals accepted while height <= this
	ComplaintDeadline uint64        `json:"complaint_deadline"` // finalize runs at height == this
	Members           []RoundMember `json:"members"`
	Threshold         uint32        `json:"threshold"`
	MembersHash       []byte        `json:"members_hash"` // hash of the active operator set (re-run trigger)
	Status            string        `json:"status"`
}

// DkgStoredEncShare is one encrypted point-to-point share as stored on chain.
type DkgStoredEncShare struct {
	MemberIndex uint64 `json:"member_index"`
	A           []byte `json:"a"`
	Nonce       []byte `json:"nonce"`
	Body        []byte `json:"body"`
}

// Dealing is a dealer's stored on-chain contribution for an epoch.
type Dealing struct {
	Epoch       uint64              `json:"epoch"`
	DealerIndex uint64              `json:"dealer_index"`
	Dealer      string              `json:"dealer"` // account addr
	Commitments [][]byte            `json:"commitments"`
	EncShares   []DkgStoredEncShare `json:"enc_shares"`
}

// DkgComplaintRec is a stored, already-verified justified complaint. Its presence
// disqualifies the accused dealer at finalize.
type DkgComplaintRec struct {
	Epoch        uint64 `json:"epoch"`
	Against      uint64 `json:"against"`
	AccuserIndex uint64 `json:"accuser_index"`
}

// ActiveThresholdKey is the DKG output installed as the active encryption key for
// an epoch. It REPLACES the trusted params.ThresholdPub while DKG is enabled.
type ActiveThresholdKey struct {
	Epoch             uint64   `json:"epoch"`
	Pub               []byte   `json:"pub"`                // compressed msk*G
	PublicCommitments [][]byte `json:"public_commitments"` // aggregate V_j (for RecoverVerified)
	Threshold         uint32   `json:"threshold"`
	Qual              []uint64 `json:"qual"`
}

// Commit is a recorded hash-commitment to a future transaction.
type Commit struct {
	Sender     string `json:"sender"`
	CommitHash []byte `json:"commit_hash"` // sha256(reveal_tx || salt)
	Height     uint64 `json:"height"`      // block height the commit was recorded at
	Seq        uint64 `json:"seq"`
}

// PendingReveal is a validated reveal queued for deterministic execution in BeginBlock.
type PendingReveal struct {
	Sender       string `json:"sender"`
	CommitHeight uint64 `json:"commit_height"`
	Seq          uint64 `json:"seq"`
	RevealTx     []byte `json:"reveal_tx"`
	Salt         []byte `json:"salt"`
}

// EncTx is an encrypted transaction (threshold ciphertext) submitted for a future
// decrypt height. Stored ORDERED by (decryptHeight, seq) — the order is fixed
// before anyone can read the body, which is the anti-MEV property.
type EncTx struct {
	Submitter     string `json:"submitter"`
	SubmitHeight  uint64 `json:"submit_height"`
	DecryptHeight uint64 `json:"decrypt_height"` // submit_height + DecryptDelay
	Seq           uint64 `json:"seq"`
	A             []byte `json:"a"`     // ciphertext component r*G (compressed)
	Nonce         []byte `json:"nonce"` // AES-GCM nonce
	Body          []byte `json:"body"`  // AES-256-GCM ciphertext
	Epoch         uint64 `json:"epoch"` // DKG epoch whose key this was encrypted to (0 = legacy)
}

// EncShare is a keyper's threshold decryption share (x_i * A) for one EncTx.
type EncShare struct {
	Keyper        string `json:"keyper"`
	DecryptHeight uint64 `json:"decrypt_height"`
	Seq           uint64 `json:"seq"`   // the EncTx this share is for
	Index         uint64 `json:"index"` // keyper share index (1..n)
	D             []byte `json:"d"`     // compressed x_i * A
	Proof         []byte `json:"proof"` // DLEQ proof (C||Z, 64 bytes) binding D to Y_index; empty on legacy path
}

// GenesisState is the x/encmempool genesis (plain JSON, no proto).
type GenesisState struct {
	Params  Params          `json:"params"`
	Commits []Commit        `json:"commits"`
	Pending []PendingReveal `json:"pending"`
}

func DefaultParams() Params {
	return Params{
		RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: false, DecryptDelay: 1,
		// DKG is OFF by default; when enabled these give sane windows.
		DkgEnabled: false, DkgDealWindow: 5, DkgComplaintWindow: 3,
	}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams(), Commits: []Commit{}, Pending: []PendingReveal{}}
}

func (gs GenesisState) Validate() error {
	if gs.Params.RevealDelay == 0 {
		return fmt.Errorf("reveal_delay must be >= 1")
	}
	if gs.Params.MaxRevealWindow < gs.Params.RevealDelay {
		return fmt.Errorf("max_reveal_window (%d) must be >= reveal_delay (%d)", gs.Params.MaxRevealWindow, gs.Params.RevealDelay)
	}
	if gs.Params.DkgEnabled {
		if len(gs.Params.DkgMembers) == 0 {
			return fmt.Errorf("dkg_enabled requires a non-empty dkg_members set")
		}
		seenOp, seenAcc := map[string]bool{}, map[string]bool{}
		for i, m := range gs.Params.DkgMembers {
			if m.OperatorAddr == "" || m.AccountAddr == "" {
				return fmt.Errorf("dkg_members[%d]: operator_addr and account_addr are required", i)
			}
			if len(m.EncPubKey) != 33 {
				return fmt.Errorf("dkg_members[%d]: enc_pubkey must be a 33-byte compressed key, got %d", i, len(m.EncPubKey))
			}
			if seenOp[m.OperatorAddr] || seenAcc[m.AccountAddr] {
				return fmt.Errorf("dkg_members[%d]: duplicate operator/account address", i)
			}
			seenOp[m.OperatorAddr], seenAcc[m.AccountAddr] = true, true
		}
		if n := len(gs.Params.DkgMembers); gs.Params.DkgThreshold != 0 && int(gs.Params.DkgThreshold) > n {
			return fmt.Errorf("dkg_threshold (%d) must be <= number of members (%d)", gs.Params.DkgThreshold, n)
		}
	}
	return nil
}
