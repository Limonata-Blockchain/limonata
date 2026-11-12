package types

import (
	"fmt"

	"cosmossdk.io/math"
)

// Params configure the net-seller cap: a rolling-window rate limit on how much a
// RESTRICTED address (team / foundation) may transfer OUT, to bound dumping while the
// network is not yet decentralized. Pairs with vesting (vesting controls WHEN coins
// unlock; this controls how fast UNLOCKED coins can leave). Genesis-set and
// counsel-tunable. Plain JSON (no proto), mirroring x/valgrant.
type Params struct {
	Enabled             bool     `json:"enabled"`
	RestrictedAddresses []string `json:"restricted_addresses"` // bech32 addrs subject to the cap
	Whitelist           []string `json:"whitelist"`            // bech32 destinations exempt (e.g. own cold/multisig)
	WindowSeconds       int64    `json:"window_seconds"`       // rolling window length in seconds
	CapPerWindow        string   `json:"cap_per_window"`       // max aLIMO OUT per window per restricted addr
}

// WindowSpend is the per-restricted-address rolling-window outflow accumulator.
type WindowSpend struct {
	WindowStartUnix int64  `json:"window_start_unix"`
	Spent           string `json:"spent"` // aLIMO sent out within the current window
}

// GenesisState is the x/netcap genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params `json:"params"`
}

func DefaultParams() Params {
	return Params{
		Enabled:             false,
		RestrictedAddresses: []string{},
		Whitelist:           []string{},
		WindowSeconds:       0,
		CapPerWindow:        "0",
	}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams()}
}

func (gs GenesisState) Validate() error {
	p := gs.Params
	if !p.Enabled {
		return nil
	}
	if p.WindowSeconds <= 0 {
		return fmt.Errorf("netcap: window_seconds must be > 0 when enabled")
	}
	if v, ok := math.NewIntFromString(p.CapPerWindow); !ok || v.IsNegative() {
		return fmt.Errorf("netcap: invalid cap_per_window %q", p.CapPerWindow)
	}
	return nil
}
