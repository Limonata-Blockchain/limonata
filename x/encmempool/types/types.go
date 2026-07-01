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
	ThresholdPub []byte   `json:"threshold_pub"` // compressed threshold public key Y = x*G
	Threshold    uint32   `json:"threshold"`     // t: decryption shares required to decrypt
	Keypers      []string `json:"keypers"`       // authorized keyper addrs (bech32); share index = position+1
	DecryptDelay uint64   `json:"decrypt_delay"` // blocks between submit and decrypt-execute
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
}

// EncShare is a keyper's threshold decryption share (x_i * A) for one EncTx.
type EncShare struct {
	Keyper        string `json:"keyper"`
	DecryptHeight uint64 `json:"decrypt_height"`
	Seq           uint64 `json:"seq"`   // the EncTx this share is for
	Index         uint64 `json:"index"` // keyper share index (1..n)
	D             []byte `json:"d"`     // compressed x_i * A
}

// GenesisState is the x/encmempool genesis (plain JSON, no proto).
type GenesisState struct {
	Params  Params          `json:"params"`
	Commits []Commit        `json:"commits"`
	Pending []PendingReveal `json:"pending"`
}

func DefaultParams() Params {
	return Params{RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: false, DecryptDelay: 1}
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
	return nil
}
