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

// EscrowEntry is one contract's total gas escrow (store prefix 0x01).
type EscrowEntry struct {
	// Contract is the lower-hex contract address (the raw store key suffix).
	Contract string `json:"contract"`
	// Amount is the escrow still funding that contract's gas (aLIMO, math.Int as string).
	Amount string `json:"amount"`
}

// ContributionEntry is one sponsor's withdrawable contribution toward a contract
// (store prefix 0x02).
type ContributionEntry struct {
	// Sponsor is the bech32 depositor address.
	Sponsor string `json:"sponsor"`
	// Contract is the lower-hex contract address the deposit is earmarked for.
	Contract string `json:"contract"`
	// Amount is that sponsor's unspent, withdrawable contribution (aLIMO, math.Int as string).
	Amount string `json:"amount"`
}

// GenesisState is the x/sponsorpool genesis (plain JSON, no proto).
//
// ESCROW IS REAL MONEY, NOT DERIVED STATE. Until these two lists existed,
// ExportGenesis returned params only. That is harmless for a fresh chain (there
// are no deposits yet) and CATASTROPHIC for the first export-based migration of a
// live chain: developers' deposits sit inside the shared gas-pool module account,
// which x/bank exports intact, but the accounting that says WHOSE money it is and
// WHICH contract it funds lives only here. Dropping it would leave the coins in
// the pool with every escrow at zero - no contract sponsored, no sponsor able to
// withdraw, the funds silently absorbed by the protocol.
type GenesisState struct {
	Params Params `json:"params"`
	// Escrows is the exported 0x01 map (per-contract escrow). Optional/empty on a
	// fresh genesis.
	Escrows []EscrowEntry `json:"escrows,omitempty"`
	// Contributions is the exported 0x02 map (per-sponsor, per-contract
	// withdrawable contribution). Optional/empty on a fresh genesis.
	Contributions []ContributionEntry `json:"contributions,omitempty"`
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
	escrow := make(map[string]struct{}, len(gs.Escrows))
	for i, e := range gs.Escrows {
		if e.Contract == "" {
			return fmt.Errorf("escrows[%d]: contract is required", i)
		}
		if _, dup := escrow[e.Contract]; dup {
			return fmt.Errorf("escrows[%d]: duplicate contract %q", i, e.Contract)
		}
		escrow[e.Contract] = struct{}{}
		if amt, ok := math.NewIntFromString(e.Amount); !ok || amt.IsNegative() {
			return fmt.Errorf("escrows[%d] (%s): invalid amount %q (must be a non-negative integer)", i, e.Contract, e.Amount)
		}
	}
	// NOTE - do NOT add a "contributions must not exceed escrow" rule here. It reads
	// like a solvency invariant and it is NOT one: Keeper.Reserve debits the
	// contract's escrow when a sponsored tx is paid but deliberately leaves the
	// per-sponsor contributions untouched, so a contract whose escrow has been
	// spent down (or drained to zero and deleted) legitimately still carries
	// contributions larger than its escrow. Withdraw already bounds a payout to
	// min(contribution, remaining escrow), which is where the real invariant lives.
	// Rejecting that state at import would refuse a perfectly normal export.
	seen := make(map[string]struct{}, len(gs.Contributions))
	for i, c := range gs.Contributions {
		if c.Sponsor == "" {
			return fmt.Errorf("contributions[%d]: sponsor is required", i)
		}
		if c.Contract == "" {
			return fmt.Errorf("contributions[%d]: contract is required", i)
		}
		pair := c.Sponsor + "|" + c.Contract
		if _, dup := seen[pair]; dup {
			return fmt.Errorf("contributions[%d]: duplicate (sponsor %s, contract %s)", i, c.Sponsor, c.Contract)
		}
		seen[pair] = struct{}{}
		if amt, ok := math.NewIntFromString(c.Amount); !ok || amt.IsNegative() {
			return fmt.Errorf("contributions[%d] (%s/%s): invalid amount %q (must be a non-negative integer)", i, c.Sponsor, c.Contract, c.Amount)
		}
	}
	return nil
}
