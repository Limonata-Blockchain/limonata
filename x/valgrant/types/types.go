package types

import (
	"fmt"

	"cosmossdk.io/math"
)

// Grant represents a locked grant for a validator candidate. State is plain
// JSON-in-store (no proto), mirroring x/contest.
type Grant struct {
	Grantee      string `json:"grantee"`       // bech32 cosmos addr
	LockedAmount string `json:"locked_amount"` // aLIMO principal (PermanentLockedAccount)
	GasAllowance string `json:"gas_allowance"` // aLIMO liquid gas allowance
	ValidatorOp  string `json:"validator_op"`  // validator operator addr (optional)
	IssuedHeight uint64 `json:"issued_height"` // block height when issued
	IssuedTime   int64  `json:"issued_time"`   // UnixTime when issued
	Status       string `json:"status"`        // "active" | "revoked"
}

// PendingClawbackEntry is one (validator, amount, completion) record awaiting
// the unbonding period before the deferred EndBlock sweep can finish.
type PendingClawbackEntry struct {
	Validator      string `json:"validator"`       // valoper bech32
	Amount         string `json:"amount"`          // aLIMO undelegated for this validator
	CompletionUnix int64  `json:"completion_unix"` // when the unbonding entry matures
}

// PendingClawback tracks a clawback whose bonded principal is still unbonding.
// EndBlock (ordered AFTER x/staking) sweeps it back to the pool once mature.
type PendingClawback struct {
	Grantee     string                 `json:"grantee"`      // bech32 cosmos addr
	Entries     []PendingClawbackEntry `json:"entries"`      // per-validator unbonding entries
	SweepAmount string                 `json:"sweep_amount"` // total principal still to sweep (aLIMO)
	InitiatedAt int64                  `json:"initiated_at"` // UnixTime clawback was initiated
}

// Params are the governance-set valgrant parameters.
type Params struct {
	Admin string `json:"admin"` // bech32 addr authorized to issue/clawback ("" = disabled)
	// FoundationValidators are the valoper addresses counted as foundation/team
	// for the foundation-VP KPI (there is no on-chain foundation tag). Genesis-
	// or gov-set. Empty => foundation VP is reported as 0.
	FoundationValidators []string `json:"foundation_validators,omitempty"`
}

// KPISnapshot is the latest on-chain decentralization snapshot, recorded each
// block in EndBlock (after staking) and exposed via the valgrant_kpi event +
// the store. v1: computed + recorded for TRANSPARENCY; gating is done off-chain.
type KPISnapshot struct {
	Height              int64 `json:"height"`
	Unix                int64 `json:"unix"`
	ActiveValidators    int   `json:"active_validators"`
	NakamotoCoefficient int   `json:"nakamoto_coefficient"` // min validators to exceed 1/3 of power (halting threshold)
	FoundationVPBps     int64 `json:"foundation_vp_bps"`    // foundation share of total power, basis points
	TopValidatorVPBps   int64 `json:"top_validator_vp_bps"` // largest single validator share, basis points
	TotalPower          int64 `json:"total_power"`
}

// GenesisState is the x/valgrant genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params  `json:"params"`
	Grants []Grant `json:"grants"`
}

func DefaultParams() Params {
	return Params{Admin: "", FoundationValidators: nil}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams(), Grants: []Grant{}}
}

func (gs GenesisState) Validate() error {
	for i, g := range gs.Grants {
		if _, ok := math.NewIntFromString(g.LockedAmount); !ok {
			return fmt.Errorf("grant %d: invalid locked_amount %q", i, g.LockedAmount)
		}
		if _, ok := math.NewIntFromString(g.GasAllowance); !ok {
			return fmt.Errorf("grant %d: invalid gas_allowance %q", i, g.GasAllowance)
		}
		if g.Status != "active" && g.Status != "revoked" {
			return fmt.Errorf("grant %d: invalid status %q", i, g.Status)
		}
	}
	return nil
}
