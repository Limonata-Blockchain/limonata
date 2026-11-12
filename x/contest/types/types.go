package types

import (
	"fmt"
	"strings"

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

	// PasskeyRPID is the WebAuthn relying-party id (e.g. "limonata.xyz") the ante
	// path pins: assertions whose signed rpIdHash != SHA256(PasskeyRPID) are
	// rejected. PasskeyAllowedOrigins is the exact-match allowlist for
	// clientData.origin (e.g. "https://limonata.xyz"). Both MUST be set before
	// PasskeyEnabled can be turned on (fail-closed at activation); on-chain
	// params so governance can rotate the RP without a binary upgrade.
	PasskeyRPID           string   `json:"passkey_rp_id"`
	PasskeyAllowedOrigins []string `json:"passkey_allowed_origins"`
}

// GenesisState is the x/contest genesis (plain JSON, no proto).
type GenesisState struct {
	Params   Params        `json:"params"`
	Showcase []ShowcaseApp `json:"showcase"`
	// DevStats is the exported 0x03 map: per-developer accumulated leaderboard
	// counters. Optional/empty on a fresh genesis.
	DevStats []DevStatsEntry `json:"dev_stats,omitempty"`
	// TesterPoints is the exported 0x04 map: per-tester accumulated points.
	// Optional/empty on a fresh genesis.
	TesterPoints []TesterPointsEntry `json:"tester_points,omitempty"`
	// DailyUAW is the exported 0x05 set: per-(day, tester) unique-active markers
	// not yet rolled up into TesterPoints. Optional/empty on a fresh genesis.
	DailyUAW []DailyUAWEntry `json:"daily_uaw,omitempty"`
	// SnapshotDone is the exported 0x06 flag: true once the leaderboard has been
	// frozen. It is a ONE-WAY latch that gates the whole scoring path, so an
	// export that dropped it would silently UNFREEZE a finished contest and let
	// points keep accruing after the deadline.
	SnapshotDone bool `json:"snapshot_done,omitempty"`
}

// DevStatsEntry is one developer's accumulated leaderboard counters (0x03).
type DevStatsEntry struct {
	Dev   string   `json:"dev"`
	Stats DevStats `json:"stats"`
}

// TesterPointsEntry is one tester's accumulated points (0x04).
type TesterPointsEntry struct {
	Tester string `json:"tester"`
	Points uint64 `json:"points"`
}

// DailyUAWEntry is one not-yet-rolled-up (day, tester) unique-active marker (0x05).
// EndBlock credits every marker for a day strictly before today as WeightUAW points
// and deletes it, so at most one day's worth of markers is ever in flight.
type DailyUAWEntry struct {
	Day    uint64 `json:"day"`
	Tester string `json:"tester"`
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
		PasskeyRPID:           "",
		PasskeyAllowedOrigins: nil,
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
	// Fail-closed: the passkey ante path must never run without RP binding.
	if p.PasskeyEnabled && (p.PasskeyRPID == "" || len(p.PasskeyAllowedOrigins) == 0) {
		return fmt.Errorf("passkey_enabled requires passkey_rp_id and at least one passkey_allowed_origins entry")
	}
	for i, o := range p.PasskeyAllowedOrigins {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("passkey_allowed_origins[%d] must be non-empty", i)
		}
	}
	for i, a := range gs.Showcase {
		if a.VM == "evm" && !common.IsHexAddress(a.Address) {
			return fmt.Errorf("showcase %d: invalid EVM address %q", i, a.Address)
		}
	}
	seenDev := make(map[string]struct{}, len(gs.DevStats))
	for i, d := range gs.DevStats {
		if d.Dev == "" {
			return fmt.Errorf("dev_stats[%d]: dev is required", i)
		}
		if _, dup := seenDev[d.Dev]; dup {
			return fmt.Errorf("dev_stats[%d]: duplicate dev %q", i, d.Dev)
		}
		seenDev[d.Dev] = struct{}{}
		if d.Stats.GasSponsored != "" {
			if v, ok := math.NewIntFromString(d.Stats.GasSponsored); !ok || v.IsNegative() {
				return fmt.Errorf("dev_stats[%d] (%s): invalid gas_sponsored %q", i, d.Dev, d.Stats.GasSponsored)
			}
		}
	}
	seenTester := make(map[string]struct{}, len(gs.TesterPoints))
	for i, tp := range gs.TesterPoints {
		if tp.Tester == "" {
			return fmt.Errorf("tester_points[%d]: tester is required", i)
		}
		if _, dup := seenTester[tp.Tester]; dup {
			return fmt.Errorf("tester_points[%d]: duplicate tester %q", i, tp.Tester)
		}
		seenTester[tp.Tester] = struct{}{}
	}
	seenUAW := make(map[string]struct{}, len(gs.DailyUAW))
	for i, u := range gs.DailyUAW {
		if u.Tester == "" {
			return fmt.Errorf("daily_uaw[%d]: tester is required", i)
		}
		key := fmt.Sprintf("%d|%s", u.Day, u.Tester)
		if _, dup := seenUAW[key]; dup {
			return fmt.Errorf("daily_uaw[%d]: duplicate (day %d, tester %s)", i, u.Day, u.Tester)
		}
		seenUAW[key] = struct{}{}
	}
	return nil
}
