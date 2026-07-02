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
// Invariant enforced by Validate: BurnBps + GrantBps <= BpsDenom (so the validator
// remainder is non-negative).
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

// Validate rejects a split whose burn+grant exceeds 100%, which would make the
// validator remainder negative (and break per-block conservation).
func (p Params) Validate() error {
	if uint64(p.BurnBps)+uint64(p.GrantBps) > BpsDenom {
		return fmt.Errorf("invalid squeeze split: burn_bps(%d) + grant_bps(%d) exceeds %d bps", p.BurnBps, p.GrantBps, BpsDenom)
	}
	return nil
}

func (gs GenesisState) Validate() error { return gs.Params.Validate() }
