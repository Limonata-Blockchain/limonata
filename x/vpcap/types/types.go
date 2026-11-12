package types

import (
	"encoding/hex"
	"fmt"
)

// Params are the governance-set voting-power-cap parameters. State is plain
// JSON-in-store (no proto), mirroring x/valgrant.
type Params struct {
	// Enabled turns the cap on. Default false (no-op) so the module is inert
	// until genesis/governance enables it — keeps a shared build tree safe.
	Enabled bool `json:"enabled"`
	// PerValidatorCapBps caps each validator's CONSENSUS voting power at this
	// fraction of total bonded power, in basis points (1000 = 10%). Must be in
	// (0, 10000) when enabled; 0 or >=10000 means no cap.
	PerValidatorCapBps uint32 `json:"per_validator_cap_bps"`
	// FoundationCapBps + FoundationValidators reserve the v2 AGGREGATE foundation
	// cap. NOT enforced in v1: the per-validator cap covers "foundation <15%"
	// transitively while the foundation runs a single validator. Kept for
	// forward-compatible genesis/params.
	FoundationCapBps     uint32   `json:"foundation_cap_bps"`
	FoundationValidators []string `json:"foundation_validators"`
}

// LastSentEntry is one persisted "what vpcap last told CometBFT" record
// (store prefix 0x02), carried across an export -> import migration.
//
// WHY IT MUST BE EXPORTED: when the cap is enabled, x/vpcap OWNS the whole
// ValidatorUpdates set. It diffs against this map to know which validators to
// re-emit and, crucially, which departed validators to emit with Power 0. An
// export that dropped the map would restart the chain with an EMPTY diff base:
// every validator would look new, and any validator that had been zeroed out
// would silently stay in the CometBFT set at its pre-cap power. The map is
// cheap (one entry per validator) and reconstructing it is not possible from
// params alone.
type LastSentEntry struct {
	// ConsAddr is the consensus address, lower-hex (the raw store key suffix).
	ConsAddr string `json:"cons_addr"`
	// PubKey is the marshaled cmtprotocrypto.PublicKey, base64 (encoding/json
	// encodes a []byte as base64).
	PubKey []byte `json:"pubkey"`
	// Power is the voting power vpcap last emitted for this validator.
	Power int64 `json:"power"`
}

// GenesisState is the x/vpcap genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params `json:"params"`
	// LastSent is the exported 0x02 map. Optional: absent/empty in a fresh
	// genesis (nothing has been emitted yet), populated by ExportGenesis.
	LastSent []LastSentEntry `json:"last_sent,omitempty"`
}

func DefaultParams() Params {
	return Params{
		Enabled:              false,
		PerValidatorCapBps:   1000, // 10%
		FoundationCapBps:     1500, // 15% (v2, not enforced)
		FoundationValidators: []string{},
	}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams()}
}

func (gs GenesisState) Validate() error {
	p := gs.Params
	if p.Enabled && (p.PerValidatorCapBps == 0 || p.PerValidatorCapBps >= 10000) {
		return fmt.Errorf("per_validator_cap_bps must be in (0,10000) when enabled, got %d", p.PerValidatorCapBps)
	}
	seen := make(map[string]struct{}, len(gs.LastSent))
	for i, e := range gs.LastSent {
		if e.ConsAddr == "" {
			return fmt.Errorf("last_sent[%d]: cons_addr is required", i)
		}
		if _, err := hex.DecodeString(e.ConsAddr); err != nil {
			return fmt.Errorf("last_sent[%d]: cons_addr %q is not hex: %w", i, e.ConsAddr, err)
		}
		if _, dup := seen[e.ConsAddr]; dup {
			return fmt.Errorf("last_sent[%d]: duplicate cons_addr %q", i, e.ConsAddr)
		}
		seen[e.ConsAddr] = struct{}{}
		if e.Power < 0 {
			return fmt.Errorf("last_sent[%d]: power must not be negative, got %d", i, e.Power)
		}
	}
	return nil
}
