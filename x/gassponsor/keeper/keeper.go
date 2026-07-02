package keeper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/x/gassponsor/types"
)

// Keeper for x/gassponsor. JSON-in-store, like x/contest. It reads the x/contest
// showcase registry (approved dApps) and the bank keeper (pool moves + mint).
type Keeper struct {
	storeService corestore.KVStoreService
	contest      types.ContestReader
	bank         types.BankKeeper
	pool         types.SponsorPoolReader
	feeCollector string
}

func NewKeeper(ss corestore.KVStoreService, contest types.ContestReader, bank types.BankKeeper, pool types.SponsorPoolReader, feeCollector string) Keeper {
	return Keeper{storeService: ss, contest: contest, bank: bank, pool: pool, feeCollector: feeCollector}
}

func (k Keeper) store(ctx context.Context) corestore.KVStore { return k.storeService.OpenKVStore(ctx) }

// --- params ---

func (k Keeper) SetParams(ctx context.Context, p types.Params) error {
	bz, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(types.ParamsKey, bz)
}

func (k Keeper) GetParams(ctx context.Context) types.Params {
	bz, err := k.store(ctx).Get(types.ParamsKey)
	if err != nil || bz == nil {
		return types.DefaultParams()
	}
	var p types.Params
	if json.Unmarshal(bz, &p) != nil {
		return types.DefaultParams()
	}
	return p
}

// IsSponsored decides ONCE (in the EVM ante) whether this tx's fee is paid by the gas
// pool instead of the sender. The decision reads only consensus state, so CheckTx and
// DeliverTx and every node agree. The result is carried to the refund via the EVM
// object store; it is never recomputed.
//
// Fall-through order (each sponsored path emits a gassponsor_sponsored event with the
// path taken; observability is non-consensus and does not affect the app hash):
//
//  1. approved-dApp  (viaApp=true, capped per-tx by DappPerTxFeeCap)
//  2. sponsorpool escrow (viaApp=true, dev-funded, non-inflationary)
//  3. baseline uniform daily budget (viaApp=false, holders only, DEBITS the day counter)
//  4. one-shot onboarding grant (viaApp=false, cold 0-balance wallet, DEBITS the 0x05 counter)
//  5. user-paid (not sponsored)
//
// Because paths 3 and 4 debit persistent counters, IsSponsored MUST be called exactly
// once per tx (it is, from the ante). Returns (sponsored, viaApprovedApp).
func (k Keeper) IsSponsored(ctx sdk.Context, sender sdk.AccAddress, to *common.Address, fees sdk.Coins) (bool, bool) {
	p := k.GetParams(ctx)
	if !p.Enabled {
		return false, false
	}
	amt := fees.AmountOf(types.FeeDenom)
	if !amt.IsPositive() {
		return false, false
	}

	// 1. Approved dApp -> sponsorship, bounded per-tx by DappPerTxFeeCap. If the fee exceeds
	//    the cap, DO NOT sponsor via the dApp path — fall through to sponsorpool/baseline as
	//    if the dApp were not approved. This closes the pool-drain hole (an attacker holding
	//    B LIMO setting gasFeeCap so gas*feeCap ≈ B and draining ~B per tx).
	if to != nil {
		if app, ok := k.contest.GetShowcase(ctx, strings.ToLower(to.Hex())); ok && app.Approved && (app.VM == "" || app.VM == "evm") {
			if k.withinDappCap(p, amt) {
				k.emitSponsored(ctx, "dapp", sender, to, amt, k.dappRemaining(p, amt))
				return true, true
			}
			// fee > cap: fall through to the bounded paths below.
		}
	}

	// 2. Per-contract developer escrow (x/sponsorpool): dev-funded, non-inflationary.
	// Reserve debits the escrow accounting; the gas pool pays the fee via the normal
	// sponsored path (the deposit keeps the pool above its mint target, so no extra mint).
	// (true, true) skips the per-account baseline counter and routes refunds to the pool.
	if to != nil && k.pool != nil && k.pool.Reserve(ctx, strings.ToLower(to.Hex()), amt) {
		k.emitSponsored(ctx, "escrow", sender, to, amt, math.NewInt(-1))
		return true, true
	}

	// 3. Per-account UNIFORM daily budget (holders only), debited here. See effectiveAllowance.
	allow := k.effectiveAllowance(ctx, p, sender)
	if allow.IsPositive() {
		day := uint64(ctx.BlockTime().UTC().Unix() / 86400)
		used := k.allowanceUsed(ctx, day, sender)
		if used.Add(amt).LTE(allow) {
			newUsed := used.Add(amt)
			k.setAllowanceUsed(ctx, day, sender, newUsed)
			k.emitSponsored(ctx, "baseline", sender, to, amt, allow.Sub(newUsed))
			return true, false
		}
	}

	// 4. One-shot ONBOARDING grant: a cold 0-balance never-seen account gets a bounded
	//    lifetime budget (OnboardingGrant) so its first tx works with no faucet. After it is
	//    exhausted the account must hold LIMO to earn the daily budget.
	if k.tryOnboarding(ctx, p, sender, to, amt) {
		return true, false
	}

	// 5. User-paid.
	return false, false
}

// effectiveAllowance is an account's daily free-gas budget.
//
// UNIFORM mode (v0.3.0, when DailyBudget is set): every account that holds at least
// HoldMinimum LIMO gets the SAME flat DailyBudget — users and apps alike; everyone else
// gets 0 (cold 0-balance wallets are handled by the separate onboarding path). Holding is
// the anti-farm gate: maxing N accounts costs N * HoldMinimum of immobilized capital.
//
// LEGACY fallback (when DailyBudget is empty/0, e.g. a genesis written before the field
// existed): the old history-scaled formula
//
//	allowance = min(BaselineDaily, ColdStartDaily + heldLIMO / BalanceDivisor)
//
// so pre-v0.3.0 chains keep their exact prior behaviour until genesis/gov sets DailyBudget.
func (k Keeper) effectiveAllowance(ctx sdk.Context, p types.Params, sender sdk.AccAddress) math.Int {
	held := k.bank.GetAllBalances(ctx, sender).AmountOf(types.FeeDenom)

	// Uniform mode.
	if budget, ok := math.NewIntFromString(p.DailyBudget); ok && budget.IsPositive() {
		minHold := math.ZeroInt()
		if m, ok := math.NewIntFromString(p.HoldMinimum); ok && m.IsPositive() {
			minHold = m
		}
		// Require a POSITIVE hold >= minHold: a truly 0-balance account earns no daily
		// budget (it onboards instead), even if HoldMinimum is misconfigured to 0.
		if held.IsPositive() && held.GTE(minHold) {
			return budget
		}
		return math.ZeroInt()
	}

	// Legacy history-scaled fallback.
	baseline, ok := math.NewIntFromString(p.BaselineDaily)
	if !ok || !baseline.IsPositive() {
		return math.ZeroInt()
	}
	cold, ok := math.NewIntFromString(p.ColdStartDaily)
	if !ok {
		cold = math.ZeroInt()
	}
	div, ok := math.NewIntFromString(p.BalanceDivisor)
	if !ok || !div.IsPositive() {
		div = math.OneInt()
	}
	allow := cold.Add(held.Quo(div))
	if allow.GT(baseline) {
		allow = baseline
	}
	return allow
}

// tryOnboarding grants a bounded one-shot LIFETIME free-gas budget (OnboardingGrant) to a
// cold 0-balance never-seen account, tracked under OnboardingPrefix (0x05). It returns true
// (and debits the counter + emits the event) only when: onboarding is enabled
// (OnboardingGrant > 0), the account currently holds 0 aLIMO, and this tx's fee keeps the
// account's cumulative onboarding draw within the grant. Being a sponsored path, the mint it
// causes is naturally bounded by RefillDailyMintCap through the pool-drain -> refill loop.
func (k Keeper) tryOnboarding(ctx sdk.Context, p types.Params, sender sdk.AccAddress, to *common.Address, amt math.Int) bool {
	grant, ok := math.NewIntFromString(p.OnboardingGrant)
	if !ok || !grant.IsPositive() {
		return false // onboarding disabled
	}
	// Only a truly cold (0-balance) wallet onboards; holders earn the daily budget instead.
	held := k.bank.GetAllBalances(ctx, sender).AmountOf(types.FeeDenom)
	if !held.IsZero() {
		return false
	}
	used := k.onboardingUsed(ctx, sender)
	newUsed := used.Add(amt)
	if newUsed.GT(grant) {
		return false // would exceed the lifetime onboarding budget
	}
	k.setOnboardingUsed(ctx, sender, newUsed)
	k.emitSponsored(ctx, "onboarding", sender, to, amt, grant.Sub(newUsed))
	return true
}

// dappRemaining reports the per-tx headroom left under the approved-dApp cap for the
// gassponsor_sponsored event. Returns -1 when the cap is unlimited (empty/0/non-positive).
func (k Keeper) dappRemaining(p types.Params, amt math.Int) math.Int {
	c, ok := math.NewIntFromString(p.DappPerTxFeeCap)
	if !ok || !c.IsPositive() {
		return math.NewInt(-1)
	}
	return c.Sub(amt)
}

// emitSponsored emits the per-tx gassponsor_sponsored observability event. Events do not
// affect the app hash, so this is safe to ship independently of the consensus paths.
// remaining_allowance is -1 for paths without a running per-account budget (escrow, or an
// unlimited dApp cap).
func (k Keeper) emitSponsored(ctx sdk.Context, path string, sender sdk.AccAddress, to *common.Address, amount, remaining math.Int) {
	dapp := ""
	if to != nil {
		dapp = strings.ToLower(to.Hex())
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"gassponsor_sponsored",
		sdk.NewAttribute("path", path),
		sdk.NewAttribute("amount", amount.String()),
		sdk.NewAttribute("account", sender.String()),
		sdk.NewAttribute("dapp", dapp),
		sdk.NewAttribute("remaining_allowance", remaining.String()),
	))
}

// withinDappCap reports whether a fee amount is within the approved-dApp per-tx cap.
// An empty / "0" / non-positive / unparseable cap means "unlimited" (legacy behaviour,
// so genesis files written before the field existed keep working); any positive cap is
// enforced as fee <= cap.
func (k Keeper) withinDappCap(p types.Params, amt math.Int) bool {
	cap, ok := math.NewIntFromString(p.DappPerTxFeeCap)
	if !ok || !cap.IsPositive() {
		return true // unlimited
	}
	return amt.LTE(cap)
}

// --- per-account daily allowance ---

func allowanceKey(day uint64, sender sdk.AccAddress) []byte {
	out := append([]byte{}, types.AllowancePrefix...)
	var d [8]byte
	binary.BigEndian.PutUint64(d[:], day)
	out = append(out, d[:]...)
	return append(out, sender.Bytes()...)
}

func (k Keeper) allowanceUsed(ctx context.Context, day uint64, sender sdk.AccAddress) math.Int {
	bz, _ := k.store(ctx).Get(allowanceKey(day, sender))
	if bz == nil {
		return math.ZeroInt()
	}
	v, ok := math.NewIntFromString(string(bz))
	if !ok {
		return math.ZeroInt()
	}
	return v
}

func (k Keeper) setAllowanceUsed(ctx context.Context, day uint64, sender sdk.AccAddress, v math.Int) {
	_ = k.store(ctx).Set(allowanceKey(day, sender), []byte(v.String()))
}

// --- daily refill mint counter (global inflation circuit breaker) ---

func mintedTodayKey(day uint64) []byte {
	out := append([]byte{}, types.MintedTodayPrefix...)
	var d [8]byte
	binary.BigEndian.PutUint64(d[:], day)
	return append(out, d[:]...)
}

// mintedToday returns the cumulative aLIMO the refill has minted during the given UTC day.
// A new day has no key, so it reads back zero — the counter resets automatically at rollover.
func (k Keeper) mintedToday(ctx context.Context, day uint64) math.Int {
	bz, _ := k.store(ctx).Get(mintedTodayKey(day))
	if bz == nil {
		return math.ZeroInt()
	}
	v, ok := math.NewIntFromString(string(bz))
	if !ok {
		return math.ZeroInt()
	}
	return v
}

func (k Keeper) setMintedToday(ctx context.Context, day uint64, v math.Int) {
	_ = k.store(ctx).Set(mintedTodayKey(day), []byte(v.String()))
}

// MintedToday exposes the current UTC day's cumulative refill mint (query/telemetry/tests).
func (k Keeper) MintedToday(ctx sdk.Context) math.Int {
	day := uint64(ctx.BlockTime().UTC().Unix() / 86400)
	return k.mintedToday(ctx, day)
}

// AllowanceUsed exposes today's used baseline for an address (query/telemetry).
func (k Keeper) AllowanceUsed(ctx sdk.Context, sender sdk.AccAddress) math.Int {
	day := uint64(ctx.BlockTime().UTC().Unix() / 86400)
	return k.allowanceUsed(ctx, day, sender)
}

// EffectiveAllowance exposes an account's current daily free-gas budget (uniform budget
// in v0.3.0, or the legacy history-scaled cap when DailyBudget is unset) (query/telemetry/tests).
func (k Keeper) EffectiveAllowance(ctx sdk.Context, sender sdk.AccAddress) math.Int {
	return k.effectiveAllowance(ctx, k.GetParams(ctx), sender)
}

// --- one-shot onboarding grant counter (lifetime, per account) ---

func onboardingKey(sender sdk.AccAddress) []byte {
	out := append([]byte{}, types.OnboardingPrefix...)
	return append(out, sender.Bytes()...)
}

func (k Keeper) onboardingUsed(ctx context.Context, sender sdk.AccAddress) math.Int {
	bz, _ := k.store(ctx).Get(onboardingKey(sender))
	if bz == nil {
		return math.ZeroInt()
	}
	v, ok := math.NewIntFromString(string(bz))
	if !ok {
		return math.ZeroInt()
	}
	return v
}

func (k Keeper) setOnboardingUsed(ctx context.Context, sender sdk.AccAddress, v math.Int) {
	_ = k.store(ctx).Set(onboardingKey(sender), []byte(v.String()))
}

// OnboardingUsed exposes an account's cumulative lifetime onboarding-grant draw (query/telemetry).
func (k Keeper) OnboardingUsed(ctx sdk.Context, sender sdk.AccAddress) math.Int {
	return k.onboardingUsed(ctx, sender)
}

// PoolBalance exposes the current aLIMO balance of the shared paymaster gas pool that pays
// sponsored fees (query/telemetry).
func (k Keeper) PoolBalance(ctx sdk.Context) math.Int {
	poolAddr := authtypes.NewModuleAddress(types.GasPoolName)
	return k.bank.GetAllBalances(ctx, poolAddr).AmountOf(types.FeeDenom)
}
