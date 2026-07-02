package types

import "fmt"

// Params govern the per-block fee split that x/squeeze applies to the materialized
// fee_collector balance BEFORE x/distribution runs. Promoting these from compile-time
// consts (keys.go) to governable params lets the recycle/burn rates be tuned by gov
// without a re-genesis. Stored as a single JSON blob at ParamsKey, mirroring x/gassponsor.
//
// Split semantics (basis points of BpsDenom = 10000):
//   - BurnBps  is burned (the only burn on the chain),
//   - GrantBps is recycled into the gas pool (the gasless loop),
//   - the remainder (10000 - BurnBps - GrantBps) plus integer rounding dust is LEFT in
//     fee_collector so x/distribution allocates the validator slice normally.
//
// Safety bounds enforced by Validate (basis points of BpsDenom = 10000). These exist so
// no governance vote can push the split to economy-breaking values:
//   - BurnBps must be in [MinBurnBps, MaxBurnBps]   (10%-50%: always a real deflationary
//     sink, never so high it starves validators/gas-pool).
//   - GrantBps must be in [MinGrantBps, MaxGrantBps] (10%-40%: meaningful gas-pool
//     recycle without dwarfing the validator/burn slices).
//   - BurnBps+GrantBps (equivalently, the validator remainder 10000-BurnBps-GrantBps)
//     must be in [MinTakeBps, MaxTakeBps] so validators always keep [30%,70%]: never a
//     majority-take that reads as yield, and never so small it spikes effective
//     inflation pressure on validators.
const (
	MinBurnBps  = 1000 // 10%
	MaxBurnBps  = 5000 // 50%
	MinGrantBps = 1000 // 10%
	MaxGrantBps = 4000 // 40%
	MinTakeBps  = 3000 // burn+grant floor -> validator share ceiling of 70%
	MaxTakeBps  = 7000 // burn+grant ceiling -> validator share floor of 30%
)

type Params struct {
	// BurnBps is the burned share of each block's fee_collector balance, in basis points.
	BurnBps uint32 `json:"burn_bps"`
	// GrantBps is the gas-pool-recycled share of each block's fee_collector balance, in
	// basis points.
	GrantBps uint32 `json:"grant_bps"`
}

// GenesisState is the x/squeeze genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params `json:"params"`
}

// DefaultParams is the settled mainnet split: 20% burn / 20% gas-pool recycle / 60%
// validators (the 60% is the remainder left in fee_collector for x/distribution).
func DefaultParams() Params {
	return Params{
		BurnBps:  BurnBps,  // 2000 = 20% burn
		GrantBps: GrantBps, // 2000 = 20% gas-pool recycle
	}
}

func DefaultGenesisState() *GenesisState { return &GenesisState{Params: DefaultParams()} }

// Validate enforces the governance safety bounds documented above, so no gov vote can
// push the fee split to economy-breaking values (e.g. zero burn, or a validator
// majority-take that looks like yield).
func (p Params) Validate() error {
	if p.BurnBps < MinBurnBps || p.BurnBps > MaxBurnBps {
		return fmt.Errorf("burn_bps %d out of allowed range [%d,%d]", p.BurnBps, MinBurnBps, MaxBurnBps)
	}
	if p.GrantBps < MinGrantBps || p.GrantBps > MaxGrantBps {
		return fmt.Errorf("grant_bps %d out of allowed range [%d,%d]", p.GrantBps, MinGrantBps, MaxGrantBps)
	}
	take := uint64(p.BurnBps) + uint64(p.GrantBps)
	if take < MinTakeBps || take > MaxTakeBps {
		return fmt.Errorf("burn_bps+grant_bps %d out of allowed range [%d,%d] (validator share must stay in [%d,%d] bps)",
			take, MinTakeBps, MaxTakeBps, BpsDenom-MaxTakeBps, BpsDenom-MinTakeBps)
	}
	return nil
}

func (gs GenesisState) Validate() error { return gs.Params.Validate() }
