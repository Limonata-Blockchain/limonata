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

	// --- PER-VALIDATOR granted-share ledger (HIGH-A-CROSS fix) ---
	// GrantedShares is the locked-grant delegation SHARES currently sitting at
	// grant.ValidatorOp (a math.LegacyDec string). It is recorded when the module
	// performs the locked delegation at issuance (MsgIssueLocked) and thereafter
	// only ever DECREASES, CLAMPED by the x/valgrant staking hooks to the live
	// shares at grant.ValidatorOp (the SDK does NOT track per-validator locked
	// shares). An outflow is charged to the grantee's FREE shares FIRST, matching
	// x/auth's own free-first TrackUndelegation bucketing, so a grantee cannot
	// erode the grant by cycling their own liquid through grant.ValidatorOp
	// (HIGH-ERODE). The clawback reclaims EXACTLY
	// min(GrantedShares, delegation.Shares at grant.ValidatorOp) and NEVER reads
	// the account-global DelegatedVesting aggregate; it is bounded by the grant's
	// share count at issuance, so a grantee can never lose more than the grant.
	// Shares REDELEGATED off grant.ValidatorOp still escape the reclaim - see
	// keeper.reconcileGrantShares for the full boundary.
	// "" / "0" => nothing granted-and-bonded remains at grant.ValidatorOp.
	GrantedShares string `json:"granted_shares,omitempty"`
	// TrackedShares is the TOTAL delegation shares last observed at
	// grant.ValidatorOp by the staking hook (a math.LegacyDec string). Purely
	// OBSERVATIONAL since the HIGH-ERODE fix: the attribution is the stateless
	// clamp GrantedShares = min(GrantedShares, live shares), which needs no
	// history. Invariant GrantedShares <= TrackedShares.
	TrackedShares string `json:"tracked_shares,omitempty"`

	// --- OPTIONAL probation/deposit escrow (backward-compatible) ---
	// These default to "" / false for pre-existing grants (JSON omits them), so
	// existing grants and behaviour are unchanged. They exist so the governance
	// clawback can, when present, cancel unvested rewards and forfeit an on-chain
	// exogenous deposit. When absent (the MVP), the clawback treats them as a
	// documented no-op (rewards are liquid to the grantee by design; the deposit
	// is held off-chain).

	// UnvestedRewards is aLIMO of probationary rewards owed to the grant but not
	// yet vested to the grantee, HELD in the valgrant reserve pool. On a
	// governance clawback this claim is CANCELLED (the coins simply remain in the
	// foundation reserve; they never reach the grantee). "" / "0" => none.
	UnvestedRewards string `json:"unvested_rewards,omitempty"`
	// Deposit is aLIMO of an exogenous good-faith deposit associated with the
	// grant. It is FORFEITED on a governance clawback iff DepositEscrowed is true
	// (i.e. the deposit is actually held on-chain in the valgrant reserve pool).
	Deposit string `json:"deposit,omitempty"`
	// DepositEscrowed reports whether Deposit is escrowed ON-CHAIN in the valgrant
	// reserve pool. false => the deposit is off-chain (MVP): forfeiture is a
	// documented no-op event rather than an on-chain coin move.
	DepositEscrowed bool `json:"deposit_escrowed,omitempty"`
}

// PendingClawbackEntry is one (validator, amount, completion) record awaiting
// the unbonding period before the deferred EndBlock sweep can finish.
type PendingClawbackEntry struct {
	Validator      string `json:"validator"`       // valoper bech32
	Amount         string `json:"amount"`          // aLIMO undelegated for this validator (the fair value at clawback, PRE any re-slash)
	CompletionUnix int64  `json:"completion_unix"` // when the unbonding entry matures (whole seconds; event/display)
	// CompletionNanos is the FULL-nanosecond unbonding maturity. x/staking matures
	// UnbondingDelegations at nanosecond precision; the deferred sweep gates on THIS
	// (never the whole-second-truncated CompletionUnix) so it can never fire in the
	// sub-second gap BEFORE x/staking's CompleteUnbonding returns the coins (HIGH-B).
	CompletionNanos int64 `json:"completion_nanos,omitempty"`
	// CreationHeight is the block height at which the clawback's force-undelegation
	// created the specific x/staking UnbondingDelegationEntry. Together with the
	// validator and CompletionNanos it uniquely identifies THAT entry among the
	// grantee's unbonding delegations, so the deferred sweep can read its live,
	// re-slash-aware Balance (HIGH-C).
	CreationHeight int64 `json:"creation_height,omitempty"`
	// ResolvedBalance is the last-observed live Balance of the identified
	// UnbondingDelegationEntry (an aLIMO integer string), refreshed every block the
	// entry is still unbonding. x/staking DECREMENTS the entry's Balance in place on a
	// re-slash during the unbonding window, and never slashes a matured entry, so the
	// value captured on the last pre-maturity block EQUALS the amount x/staking returns
	// to the grantee at CompleteUnbonding. It is the RAW live Balance (the whole,
	// possibly-merged entry — NOT capped at Amount): the deferred sweep credits the
	// pool the grant's PROPORTIONAL share  floor(Amount * ResolvedBalance / EntryInit)
	// (HIGH-C / HIGH-C-MERGE) — never the pre-recorded Amount, never (balance - gas),
	// never the grantee's rewards/own liquid/own same-block return. Empty until the
	// first capture; the sweep then falls back to Amount (correct whenever no re-slash
	// occurred, e.g. an entry that matured with no intervening block to capture).
	ResolvedBalance string `json:"resolved_balance,omitempty"`
	// EntryInit is the identified UnbondingDelegationEntry's InitialBalance captured at
	// the FIRST EndBlock after the clawback (an aLIMO integer string). x/staking's
	// UnbondingDelegation.AddEntry MERGES a same-block undelegation with an identical
	// (CreationHeight, CompletionTime) into this entry by SUMMING InitialBalance/Balance,
	// so when the grantee partially undelegates their OWN self-bond at grant.ValidatorOp
	// in the EXACT block the clawback executes, EntryInit = Amount (the grant's reclaim)
	// + the grantee's same-block own undelegation. InitialBalance is slash-INVARIANT (a
	// re-slash decrements only Balance, and x/staking computes the slash proportional to
	// InitialBalance), so EntryInit is captured ONCE and frozen. At maturity the pool is
	// credited the grant's PROPORTIONAL share  floor(Amount * ResolvedBalance / EntryInit)
	// — the grant's fair fraction (Amount/EntryInit) of the re-slashed matured Balance,
	// rounded DOWN so it never over-credits and the grantee always keeps
	// ResolvedBalance - credit of their own same-block return. Empty until the first
	// capture; with NO merge EntryInit == Amount and the credit reduces EXACTLY to the
	// proven cycle-6 behavior (credit == ResolvedBalance).
	EntryInit string `json:"entry_init,omitempty"`
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
//
// PendingClawbacks and KPISnapshot were added for export completeness. Neither is
// needed by a fresh genesis, and dropping PendingClawbacks from an export of a LIVE
// chain would be a silent loss of foundation money: a governance clawback whose
// bonded principal is still unbonding lives ONLY under prefix 0x03 until the EndBlock
// sweep completes it (up to the 21-day unbonding period later). An export taken in
// that window and re-imported would forget the sweep entirely - the unbonding coins
// land back in the grantee's account and stay there.
type GenesisState struct {
	Params Params  `json:"params"`
	Grants []Grant `json:"grants"`
	// PendingClawbacks is the exported 0x03 map: clawbacks whose principal is still
	// unbonding and awaits the EndBlock sweep. Optional/empty on a fresh genesis.
	PendingClawbacks []PendingClawback `json:"pending_clawbacks,omitempty"`
	// KPISnapshot is the exported 0x04 record (the latest decentralisation snapshot).
	// Purely observational - it is recomputed and rewritten by the very next EndBlock -
	// but carrying it keeps a query made between the import and that first EndBlock from
	// reporting an all-zero snapshot as if the chain were empty.
	KPISnapshot *KPISnapshot `json:"kpi_snapshot,omitempty"`
}

func DefaultParams() Params {
	return Params{Admin: "", FoundationValidators: nil}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams(), Grants: []Grant{}}
}

func (gs GenesisState) Validate() error {
	seenPending := make(map[string]struct{}, len(gs.PendingClawbacks))
	for i, pc := range gs.PendingClawbacks {
		if pc.Grantee == "" {
			return fmt.Errorf("pending_clawbacks[%d]: grantee is required", i)
		}
		if _, dup := seenPending[pc.Grantee]; dup {
			return fmt.Errorf("pending_clawbacks[%d]: duplicate grantee %q", i, pc.Grantee)
		}
		seenPending[pc.Grantee] = struct{}{}
		for j, e := range pc.Entries {
			if _, ok := math.NewIntFromString(e.Amount); !ok {
				return fmt.Errorf("pending_clawbacks[%d].entries[%d]: invalid amount %q", i, j, e.Amount)
			}
		}
	}
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
		// Optional escrow fields: validate only when present (backward-compatible;
		// pre-existing grants omit them).
		if g.UnvestedRewards != "" {
			if v, ok := math.NewIntFromString(g.UnvestedRewards); !ok || v.IsNegative() {
				return fmt.Errorf("grant %d: invalid unvested_rewards %q", i, g.UnvestedRewards)
			}
		}
		if g.Deposit != "" {
			if v, ok := math.NewIntFromString(g.Deposit); !ok || v.IsNegative() {
				return fmt.Errorf("grant %d: invalid deposit %q", i, g.Deposit)
			}
		}
	}
	return nil
}
