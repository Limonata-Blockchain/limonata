package keeper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

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
//   - approved-dApp path (unlimited): the target is an admin-approved x/contest app.
//   - baseline path (capped): the sender is within its per-account daily allowance.
//     This path DEBITS the allowance counter, so IsSponsored must be called exactly
//     once per tx (it is, from the ante).
//
// Returns (sponsored, viaApprovedApp).
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
				return true, true
			}
			// fee > cap: fall through to the bounded paths below.
		}
	}

	// 1.5 Per-contract developer escrow (x/sponsorpool): dev-funded, non-inflationary.
	// Reserve debits the escrow accounting; the gas pool pays the fee via the normal
	// sponsored path (the deposit keeps the pool above its mint target, so no extra mint).
	// (true, true) skips the per-account baseline counter and routes refunds to the pool.
	if to != nil && k.pool != nil && k.pool.Reserve(ctx, strings.ToLower(to.Hex()), amt) {
		return true, true
	}

	// 2. Per-account daily allowance (history-scaled: cold-start + balance bonus, capped
	//    at BaselineDaily). Bounded, and debited here.
	allow := k.effectiveAllowance(ctx, p, sender)
	if !allow.IsPositive() {
		return false, false
	}
	day := uint64(ctx.BlockTime().UTC().Unix() / 86400)
	used := k.allowanceUsed(ctx, day, sender)
	if used.Add(amt).LTE(allow) {
		k.setAllowanceUsed(ctx, day, sender, used.Add(amt))
		return true, false
	}
	return false, false
}

// effectiveAllowance is an account's history-scaled daily free-gas cap:
//
//	allowance = min(BaselineDaily, ColdStartDaily + heldLIMO / BalanceDivisor)
//
// Every account gets the flat ColdStartDaily so a brand-new (dust) account can start;
// holding LIMO (skin-in-the-game) adds a bonus up to the BaselineDaily cap. This bounds
// sybil minting: more sponsored gas requires holding more real LIMO per account.
func (k Keeper) effectiveAllowance(ctx sdk.Context, p types.Params, sender sdk.AccAddress) math.Int {
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
	held := k.bank.GetAllBalances(ctx, sender).AmountOf(types.FeeDenom)
	allow := cold.Add(held.Quo(div))
	if allow.GT(baseline) {
		allow = baseline
	}
	return allow
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

// EffectiveAllowance exposes an account's current history-scaled daily allowance cap
// (query/telemetry/tests).
func (k Keeper) EffectiveAllowance(ctx sdk.Context, sender sdk.AccAddress) math.Int {
	return k.effectiveAllowance(ctx, k.GetParams(ctx), sender)
}
