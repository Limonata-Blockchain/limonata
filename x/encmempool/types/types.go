package types

import "fmt"

// Params govern the commit-reveal timing. RevealDelay is the minimum number of
// blocks between a commit and its reveal; MaxRevealWindow bounds how long an
// unrevealed commit lingers in state before it is garbage-collected.
type Params struct {
	RevealDelay     uint64 `json:"reveal_delay"`
	MaxRevealWindow uint64 `json:"max_reveal_window"`
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

// GenesisState is the x/encmempool genesis (plain JSON, no proto).
type GenesisState struct {
	Params  Params          `json:"params"`
	Commits []Commit        `json:"commits"`
	Pending []PendingReveal `json:"pending"`
}

func DefaultParams() Params { return Params{RevealDelay: 1, MaxRevealWindow: 100} }

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
