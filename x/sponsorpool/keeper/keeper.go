package keeper

import (
	"context"
	"encoding/json"
	"strings"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/sponsorpool/types"
)

// Keeper for x/sponsorpool. JSON-in-store, like x/gassponsor.
//
// Architecture (chosen to avoid any change to the forked x/vm fee path):
//   - Deposits go INTO the protocol gas pool module account. Because the pool is minted
//     back up to its target each block, a deposit pushes it above target and SUPPRESSES
//     that block's refill mint. So escrow-funded gas is paid by the developer's deposit,
//     not by newly minted LIMO -> non-inflationary.
//   - When a tx targets a funded contract, gassponsor's IsSponsored calls Reserve(), which
//     ONLY decrements the escrow accounting (the gas pool itself pays the fee via the normal
//     sponsored path in x/vm). Reserve never moves coins.
//   - Withdrawals return a sponsor's unspent contribution from the pool.
//
// Safety invariant: a sponsor can withdraw at most min(its contribution, the contract's
// remaining escrow), and escrow only ever grows by deposits (which were added to the pool),
// so withdrawals can never exceed what was deposited and unspent.
type Keeper struct {
	storeService corestore.KVStoreService
	bank         types.BankKeeper
	poolModule   string // the gas pool module account (deposits land here; withdrawals come from here)
}

func NewKeeper(ss corestore.KVStoreService, bank types.BankKeeper, poolModule string) Keeper {
	return Keeper{storeService: ss, bank: bank, poolModule: poolModule}
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

// --- keys + int helpers ---

func escrowKey(contract string) []byte {
	return append(append([]byte{}, types.EscrowPrefix...), []byte(strings.ToLower(contract))...)
}

func contribKey(sponsor sdk.AccAddress, contract string) []byte {
	out := append(append([]byte{}, types.ContribPrefix...), sponsor.Bytes()...)
	return append(out, []byte(strings.ToLower(contract))...)
}

func (k Keeper) getInt(ctx context.Context, key []byte) math.Int {
	bz, _ := k.store(ctx).Get(key)
	if bz == nil {
		return math.ZeroInt()
	}
	v, ok := math.NewIntFromString(string(bz))
	if !ok {
		return math.ZeroInt()
	}
	return v
}

func (k Keeper) setInt(ctx context.Context, key []byte, v math.Int) {
	if !v.IsPositive() {
		_ = k.store(ctx).Delete(key)
		return
	}
	_ = k.store(ctx).Set(key, []byte(v.String()))
}

// EscrowOf returns the escrow currently funding a contract's gas.
func (k Keeper) EscrowOf(ctx context.Context, contract string) math.Int {
	return k.getInt(ctx, escrowKey(contract))
}

// ContributionOf returns a sponsor's withdrawable contribution toward a contract.
func (k Keeper) ContributionOf(ctx context.Context, sponsor sdk.AccAddress, contract string) math.Int {
	return k.getInt(ctx, contribKey(sponsor, contract))
}

// --- core operations ---

// Deposit: a sponsor funds a contract's gas escrow (permissionless). LIMO moves into the gas
// pool; the contract's escrow and the sponsor's contribution are credited.
func (k Keeper) Deposit(ctx context.Context, sponsor sdk.AccAddress, contract string, amt math.Int) error {
	if !amt.IsPositive() {
		return types.ErrBadAmount
	}
	coins := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, amt))
	if err := k.bank.SendCoinsFromAccountToModule(ctx, sponsor, k.poolModule, coins); err != nil {
		return err
	}
	k.setInt(ctx, escrowKey(contract), k.EscrowOf(ctx, contract).Add(amt))
	k.setInt(ctx, contribKey(sponsor, contract), k.ContributionOf(ctx, sponsor, contract).Add(amt))
	return nil
}

// DepositFrom credits a contract's escrow when the funds are ALREADY held at `payer` (used by
// the payable EVM precompile, where the EVM has already moved msg.value to the precompile's
// address). It moves the funds payer -> gas pool and credits `sponsor`'s contribution. This
// avoids double-charging the caller that Deposit() would cause in the payable path.
func (k Keeper) DepositFrom(ctx context.Context, payer, sponsor sdk.AccAddress, contract string, amt math.Int) error {
	if !amt.IsPositive() {
		return types.ErrBadAmount
	}
	coins := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, amt))
	if err := k.bank.SendCoinsFromAccountToModule(ctx, payer, k.poolModule, coins); err != nil {
		return err
	}
	k.setInt(ctx, escrowKey(contract), k.EscrowOf(ctx, contract).Add(amt))
	k.setInt(ctx, contribKey(sponsor, contract), k.ContributionOf(ctx, sponsor, contract).Add(amt))
	return nil
}

// Withdraw: a sponsor reclaims up to its own contribution, limited to what remains in escrow
// (a contract's escrow is shared; spends reduce it, so a late withdrawer may get less).
func (k Keeper) Withdraw(ctx context.Context, sponsor sdk.AccAddress, contract string, amt math.Int) error {
	if !amt.IsPositive() {
		return types.ErrBadAmount
	}
	contrib := k.ContributionOf(ctx, sponsor, contract)
	escrow := k.EscrowOf(ctx, contract)
	if amt.GT(contrib) {
		return types.ErrInsufficientContribution
	}
	if amt.GT(escrow) {
		return types.ErrInsufficientEscrow
	}
	coins := sdk.NewCoins(sdk.NewCoin(types.FeeDenom, amt))
	if err := k.bank.SendCoinsFromModuleToAccount(ctx, k.poolModule, sponsor, coins); err != nil {
		return err
	}
	k.setInt(ctx, escrowKey(contract), escrow.Sub(amt))
	k.setInt(ctx, contribKey(sponsor, contract), contrib.Sub(amt))
	return nil
}

// Reserve is called from gassponsor's IsSponsored when a tx targets `contract`. If the
// contract's escrow can cover `fee` (and it is enabled and under the per-tx cap), it debits
// the escrow accounting and returns true; the gas pool then pays the fee via the normal
// sponsored path in x/vm. It NEVER moves coins itself (no double-pay). Returns false to
// decline, letting the caller fall through to the per-account baseline (or the user paying).
func (k Keeper) Reserve(ctx context.Context, contract string, fee math.Int) bool {
	p := k.GetParams(ctx)
	if !p.Enabled || !fee.IsPositive() {
		return false
	}
	if c, ok := math.NewIntFromString(p.PerTxCap); ok && c.IsPositive() && fee.GT(c) {
		return false
	}
	escrow := k.EscrowOf(ctx, contract)
	if escrow.LT(fee) {
		return false
	}
	k.setInt(ctx, escrowKey(contract), escrow.Sub(fee))
	return true
}
