package types

import "fmt"

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

// GenesisState is the x/vpcap genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params `json:"params"`
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
	return nil
}
