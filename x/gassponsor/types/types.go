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
	// ColdStartDaily is the flat per-account daily free-gas allowance granted to EVERY
	// account regardless of balance, so a brand-new (dust) account can still transact
	// (aLIMO, math.Int as string). The history-scaled bonus is added on top. Empty -> 0.
	ColdStartDaily string `json:"cold_start_daily"`
	// BalanceDivisor sets the history-scaled bonus: bonus = held aLIMO / BalanceDivisor.
	// With "1" the bonus is 1:1 with held LIMO. Total allowance is
	// min(BaselineDaily, ColdStartDaily + bonus), so HOLDING LIMO (skin-in-the-game) is
	// what unlocks more sponsored gas and bounds sybil minting. Empty/"0" -> 1.
	BalanceDivisor string `json:"balance_divisor"`
	// DappPerTxFeeCap bounds the per-tx fee the UNLIMITED approved-dApp path will sponsor
	// (aLIMO, math.Int as string). If a tx's fee exceeds this cap, the dApp path is skipped
	// and the tx falls through to sponsorpool/baseline (as if the dApp were not approved).
	// This closes the pool-drain hole: without it an attacker holding B LIMO could set
	// gasFeeCap so gas*feeCap ≈ B and make the pool pay ~B per tx with no limit.
	// Empty/"0"/non-positive -> unlimited (no cap; legacy behaviour, for genesis back-compat).
	DappPerTxFeeCap string `json:"dapp_per_tx_fee_cap"`
	// RefillDailyMintCap bounds the TOTAL aLIMO the BeginBlock refill may mint per UTC day
	// (aLIMO, math.Int as string). This is the global inflation circuit breaker: even a novel
	// exploit that drains the pool cannot mint more than this per day. Once the day's minting
	// reaches the cap the refill stops (emitting gassponsor_refill_capped) until the next UTC
	// day. Empty/"0" -> unlimited (no cap; legacy behaviour, for genesis back-compat).
	RefillDailyMintCap string `json:"refill_daily_mint_cap"`
	// DappDailyCap bounds the TOTAL aLIMO the approved-dApp path may sponsor PER (UTC-day,
	// contract) (aLIMO, math.Int as string). Where DappPerTxFeeCap bounds a single tx, this
	// bounds a contract's whole-day sponsorship so one approved dApp cannot drain the pool with
	// many under-per-tx-cap txs. Tracked under DappSpentPrefix (0x07). Before sponsoring via the
	// dApp path, if this cap is set and dappSpentToday(day,to)+fee would exceed it, the dApp path
	// is SKIPPED and the tx falls through to sponsorpool/baseline/onboarding (as if the dApp were
	// not approved). Empty/"0"/non-positive -> unlimited (no cap; legacy behaviour, back-compat).
	DappDailyCap string `json:"dapp_daily_cap"`

	// --- v0.3.0 UNIFORM daily budget (settled gasless design) ---

	// DailyBudget is the FLAT per-account daily free-gas allowance (aLIMO, math.Int as
	// string) granted to every account that holds at least HoldMinimum LIMO — users and
	// app/contract accounts alike, identical for everyone. It REPLACES the old
	// history-scaled formula min(BaselineDaily, ColdStartDaily + held/BalanceDivisor).
	// Empty/"0"/unparseable -> the module FALLS BACK to that legacy formula (using the
	// BaselineDaily/ColdStartDaily/BalanceDivisor fields above), so genesis files written
	// before this field existed (e.g. the live chain) keep their exact prior behaviour.
	DailyBudget string `json:"daily_budget"`
	// HoldMinimum is the minimum aLIMO an account must hold to be eligible for DailyBudget
	// (aLIMO, math.Int as string). held >= HoldMinimum -> allowance = DailyBudget; else 0
	// (except the one-shot onboarding grant below). This is anti-farm #1: a farmer wanting
	// N maxed accounts must immobilize HoldMinimum across all N. Empty/"0" -> 0 (any holder,
	// including dust, is eligible). Only consulted when DailyBudget is set (uniform mode).
	HoldMinimum string `json:"hold_minimum"`
	// OnboardingGrant is the one-shot LIFETIME free-gas budget (aLIMO, math.Int as string)
	// a 0-balance never-seen account may draw down (tracked under OnboardingPrefix 0x05) so
	// its very first tx works with no faucet. After it is exhausted the account must hold
	// LIMO to earn DailyBudget. Bounded, and (being sponsored) its mint is naturally
	// counted against RefillDailyMintCap via the pool-drain -> refill loop.
	// Empty/"0" -> onboarding disabled (no grant).
	OnboardingGrant string `json:"onboarding_grant"`
	// OnboardingDailyCap bounds the TOTAL aLIMO handed out via the onboarding path across ALL
	// accounts per UTC day (aLIMO, math.Int as string) — a global sybil-flood gate on top of
	// the per-account OnboardingGrant. Tracked under GrantedTodayPrefix (0x06). When the day's
	// onboarding budget is exhausted, further cold wallets are DENIED the grant (they fall
	// through to user-paid and simply cannot transact until they hold LIMO); the cap only bites
	// under a sybil flood. Empty/"0" -> unlimited (no cap; legacy behaviour, back-compat).
	OnboardingDailyCap string `json:"onboarding_daily_cap"`
}

// GenesisState is the x/gassponsor genesis (plain JSON, no proto).
type GenesisState struct {
	Params Params `json:"params"`
}

func DefaultParams() Params {
	return Params{
		Enabled:            true,
		BaselineDaily:      "1000000000000000000", // legacy: 1 LIMO/day max allowance per account (cap)
		RefillEnabled:      true,
		MinPoolBalance:     "200000000000000000000000000", // 200,000,000 LIMO
		ColdStartDaily:     "100000000000000000",          // legacy: 0.1 LIMO/day flat cold-start
		BalanceDivisor:     "1",                           // legacy: bonus = held LIMO / 1 (1:1), capped at BaselineDaily
		DappPerTxFeeCap:    "1000000000000000000",         // 1 LIMO/tx cap on the approved-dApp path
		RefillDailyMintCap: "0",                           // 0 = unlimited daily mint (hardened value set by genesis)
		DappDailyCap:       "0",                           // 0 = unlimited per-(day,contract) dApp sponsorship (hardened value set by genesis)
		// v0.3.0 uniform budget (settled design). Present in DefaultParams so a FRESH
		// genesis runs the uniform model; an OLD genesis blob (no daily_budget) unmarshals
		// these as "" and the keeper falls back to the legacy formula above.
		DailyBudget:        "1000000000000000000", // 1 LIMO/day flat, holders only
		HoldMinimum:        "1000000000000000000", // must hold >= 1 LIMO to earn the daily budget
		OnboardingGrant:    "50000000000000000",   // 0.05 LIMO one-shot for a cold 0-balance wallet
		OnboardingDailyCap: "0",                   // 0 = unlimited daily onboarding budget (hardened value set by genesis)
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
	if gs.Params.ColdStartDaily != "" {
		if _, ok := math.NewIntFromString(gs.Params.ColdStartDaily); !ok {
			return fmt.Errorf("invalid cold_start_daily %q", gs.Params.ColdStartDaily)
		}
	}
	if gs.Params.BalanceDivisor != "" {
		if d, ok := math.NewIntFromString(gs.Params.BalanceDivisor); !ok || !d.IsPositive() {
			return fmt.Errorf("invalid balance_divisor %q (must be a positive integer)", gs.Params.BalanceDivisor)
		}
	}
	// New fields are OPTIONAL for back-compat: empty ("") means "unlimited" so pre-existing
	// genesis files (written before these fields existed) stay valid. When present they must
	// parse as a non-negative Int.
	if gs.Params.DappPerTxFeeCap != "" {
		if c, ok := math.NewIntFromString(gs.Params.DappPerTxFeeCap); !ok || c.IsNegative() {
			return fmt.Errorf("invalid dapp_per_tx_fee_cap %q (must be a non-negative integer)", gs.Params.DappPerTxFeeCap)
		}
	}
	if gs.Params.RefillDailyMintCap != "" {
		if c, ok := math.NewIntFromString(gs.Params.RefillDailyMintCap); !ok || c.IsNegative() {
			return fmt.Errorf("invalid refill_daily_mint_cap %q (must be a non-negative integer)", gs.Params.RefillDailyMintCap)
		}
	}
	if gs.Params.DappDailyCap != "" {
		if c, ok := math.NewIntFromString(gs.Params.DappDailyCap); !ok || c.IsNegative() {
			return fmt.Errorf("invalid dapp_daily_cap %q (must be a non-negative integer)", gs.Params.DappDailyCap)
		}
	}
	// v0.3.0 uniform-budget fields are OPTIONAL for back-compat (empty = fall back to the
	// legacy formula / disabled). When present they must parse as a non-negative Int.
	if gs.Params.DailyBudget != "" {
		if c, ok := math.NewIntFromString(gs.Params.DailyBudget); !ok || c.IsNegative() {
			return fmt.Errorf("invalid daily_budget %q (must be a non-negative integer)", gs.Params.DailyBudget)
		}
	}
	if gs.Params.HoldMinimum != "" {
		if c, ok := math.NewIntFromString(gs.Params.HoldMinimum); !ok || c.IsNegative() {
			return fmt.Errorf("invalid hold_minimum %q (must be a non-negative integer)", gs.Params.HoldMinimum)
		}
	}
	if gs.Params.OnboardingGrant != "" {
		if c, ok := math.NewIntFromString(gs.Params.OnboardingGrant); !ok || c.IsNegative() {
			return fmt.Errorf("invalid onboarding_grant %q (must be a non-negative integer)", gs.Params.OnboardingGrant)
		}
	}
	if gs.Params.OnboardingDailyCap != "" {
		if c, ok := math.NewIntFromString(gs.Params.OnboardingDailyCap); !ok || c.IsNegative() {
			return fmt.Errorf("invalid onboarding_daily_cap %q (must be a non-negative integer)", gs.Params.OnboardingDailyCap)
		}
	}
	return nil
}
