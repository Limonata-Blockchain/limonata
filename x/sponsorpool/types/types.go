package types

import (
	"fmt"

	"cosmossdk.io/math"
)

// Params govern the per-contract sponsorship escrow.
type Params struct {
	// Enabled is the master kill-switch for escrow-funded sponsorship.
	Enabled bool `json:"enabled"`
	// PerTxCap is the most a contract's escrow will cover for a SINGLE transaction
	// (aLIMO, math.Int as string). It bounds griefing where one huge tx drains a deposit.
	// Empty or "0" means no per-tx cap.
	PerTxCap string `json:"per_tx_cap"`
}

// GenesisState is the x/sponsorpool genesis (plain JSON, no proto). Live escrow balances are
// runtime state created by deposits, so genesis carries only params.
type GenesisState struct {
	Params Params `json:"params"`
}

func DefaultParams() Params {
	return Params{
		Enabled:  true,
		PerTxCap: "1000000000000000000000", // 1000 LIMO per-tx cap
	}
}

func DefaultGenesisState() *GenesisState { return &GenesisState{Params: DefaultParams()} }

func (gs GenesisState) Validate() error {
	if gs.Params.PerTxCap != "" {
		if _, ok := math.NewIntFromString(gs.Params.PerTxCap); !ok {
			return fmt.Errorf("invalid per_tx_cap %q", gs.Params.PerTxCap)
		}
	}
	return nil
}
