package types

import (
	"fmt"

	"cosmossdk.io/math"
	"github.com/ethereum/go-ethereum/common"
)

// ShowcaseApp is a contract promoted (from the off-chain submission portal) onto
// the on-chain contest registry. Only interactions with Approved apps earn points.
type ShowcaseApp struct {
	Address  string `json:"address"`  // EVM contract address, stored lower-case hex
	Dev      string `json:"dev"`      // identifier credited for Developer-track points
	VM       string `json:"vm"`       // "evm" (wasm reserved for when CosmWasm ships)
	Approved bool   `json:"approved"`
}

// DevStats are the raw, non-financial Developer-track inputs.
type DevStats struct {
	TxVolume     uint64 `json:"tx_volume"`     // count of txs to this dev's showcase contracts
	GasSponsored string `json:"gas_sponsored"` // total aLIMO sponsored via x/paymaster (math.Int as string)
}

// Params are the governance-set contest weights and the hard snapshot time.
type Params struct {
	SnapshotUnix          int64  `json:"snapshot_unix"`             // e.g. 1794355200 = 2026-11-11T00:00:00Z
	DevTrackBudget        string `json:"dev_track_budget"`         // aLIMO allocated to the Developer track
	TesterTrackBudget     string `json:"tester_track_budget"`      // aLIMO allocated to the Tester track
	WeightTxVolume        uint64 `json:"weight_tx_volume"`         // points per showcase tx
	WeightGasSponsoredPer uint64 `json:"weight_gas_sponsored_per"` // points per GasSponsoredDivisor aLIMO sponsored
	GasSponsoredDivisor   string `json:"gas_sponsored_divisor"`    // aLIMO per gas-point
	WeightUAW             uint64 `json:"weight_uaw"`               // points per unique-active day on a showcase app
	Admin                 string `json:"admin"`                    // bech32 addr authorized to register/remove showcase apps via Msgs ("" = disabled)
	PasskeyEnabled        bool   `json:"passkey_enabled"`          // EXPERIMENTAL: enable the WebAuthn/P-256 passkey ante path (default false)
}

// GenesisState is the x/contest genesis (plain JSON, no proto).
type GenesisState struct {
	Params   Params        `json:"params"`
	Showcase []ShowcaseApp `json:"showcase"`
}

func DefaultParams() Params {
	return Params{
		SnapshotUnix:          0,
		DevTrackBudget:        "0",
		TesterTrackBudget:     "0",
		WeightTxVolume:        1,
		WeightGasSponsoredPer: 1,
		GasSponsoredDivisor:   "1000000000000000000",
		WeightUAW:             10,
		Admin:                 "",
		PasskeyEnabled:        false,
	}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams(), Showcase: []ShowcaseApp{}}
}

func (gs GenesisState) Validate() error {
	p := gs.Params
	if _, ok := math.NewIntFromString(p.DevTrackBudget); !ok {
		return fmt.Errorf("invalid dev_track_budget %q", p.DevTrackBudget)
	}
	if _, ok := math.NewIntFromString(p.TesterTrackBudget); !ok {
		return fmt.Errorf("invalid tester_track_budget %q", p.TesterTrackBudget)
	}
	if _, ok := math.NewIntFromString(p.GasSponsoredDivisor); !ok {
		return fmt.Errorf("invalid gas_sponsored_divisor %q", p.GasSponsoredDivisor)
	}
	for i, a := range gs.Showcase {
		if a.VM == "evm" && !common.IsHexAddress(a.Address) {
			return fmt.Errorf("showcase %d: invalid EVM address %q", i, a.Address)
		}
	}
	return nil
}
