package types

import (
	"fmt"

	"cosmossdk.io/math"
)

// Params govern consensus-level EVM gas sponsorship.
type Params struct {
	// Enabled is the master kill-switch for sponsorship.
	Enabled bool `json:"enabled"`
	// BaselineDaily is the per-account daily free-gas allowance (aLIMO, math.Int as
	// string) for transactions NOT hitting an approved dApp. Approved dApps are
	// unlimited; this bounds the only other mint-backed sponsorship path.
	BaselineDaily string `json:"baseline_daily"`
	// RefillEnabled turns the mint-refill BeginBlock on/off.
	RefillEnabled bool `json:"refill_enabled"`
	// MinPoolBalance is the top-up target: each block the pool is minted back up to
	// at least this balance (aLIMO, math.Int as string).
	MinPoolBalance string `json:"min_pool_balance"`
}

// GenesisState is the x/gassponsor genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params `json:"params"`
}

func DefaultParams() Params {
	return Params{
		Enabled:        true,
		BaselineDaily:  "1000000000000000000",         // 1 LIMO/day baseline free gas per account
		RefillEnabled:  true,
		MinPoolBalance: "200000000000000000000000000", // 200,000,000 LIMO
	}
}

func DefaultGenesisState() *GenesisState { return &GenesisState{Params: DefaultParams()} }

func (gs GenesisState) Validate() error {
	if _, ok := math.NewIntFromString(gs.Params.BaselineDaily); !ok {
		return fmt.Errorf("invalid baseline_daily %q", gs.Params.BaselineDaily)
	}
	if _, ok := math.NewIntFromString(gs.Params.MinPoolBalance); !ok {
		return fmt.Errorf("invalid min_pool_balance %q", gs.Params.MinPoolBalance)
	}
	return nil
}
