package keeper

import (
	"context"
	"encoding/json"

	corestore "cosmossdk.io/core/store"
	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/evm/x/netcap/types"
)

// BaseDenom is the native coin the net-seller cap applies to.
const BaseDenom = "aLIMO"

// Keeper for x/netcap. State is plain JSON-in-store (no proto), mirroring x/valgrant.
type Keeper struct {
	storeService  corestore.KVStoreService
	accountKeeper types.AccountKeeper
}

func NewKeeper(ss corestore.KVStoreService, ak types.AccountKeeper) Keeper {
	return Keeper{storeService: ss, accountKeeper: ak}
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

// --- rolling-window spend state ---

func (k Keeper) getSpend(ctx context.Context, addr string) types.WindowSpend {
	bz, err := k.store(ctx).Get(spendKey(addr))
	if err != nil || bz == nil {
		return types.WindowSpend{WindowStartUnix: 0, Spent: "0"}
	}
	var ws types.WindowSpend
	if json.Unmarshal(bz, &ws) != nil {
		return types.WindowSpend{WindowStartUnix: 0, Spent: "0"}
	}
	return ws
}

func (k Keeper) setSpend(ctx context.Context, addr string, ws types.WindowSpend) error {
	bz, err := json.Marshal(ws)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(spendKey(addr), bz)
}

// CheckAndRecord enforces the rolling-window net-seller cap for an outbound transfer of
// `amount` aLIMO from `from` to `to`. It is called from BOTH the bank SendRestriction
// (cosmos MsgSend/MultiSend + ERC20/WERC20 precompiles) and the EVM ante decorator
// (native eth value transfers, which bypass x/bank). It CHECKS in every phase, but only
// RECORDS spend on block delivery (not CheckTx) to avoid mempool double-counting.
//
// Fails OPEN on misconfiguration (never bricks transfers); fails CLOSED on cap breach.
func (k Keeper) CheckAndRecord(ctx sdk.Context, from, to sdk.AccAddress, amount math.Int) error {
	p := k.GetParams(ctx)
	if !p.Enabled || amount.IsNil() || !amount.IsPositive() {
		return nil
	}
	fromStr := from.String()
	if !contains(p.RestrictedAddresses, fromStr) {
		return nil
	}
	// Exempt explicit whitelist destinations and any module account: sending to
	// staking/gov/distribution/etc. is not a market sale.
	if contains(p.Whitelist, to.String()) || k.isModuleAccount(ctx, to) {
		return nil
	}

	capAmt, ok := math.NewIntFromString(p.CapPerWindow)
	if !ok {
		return nil // misconfigured cap -> fail open
	}

	now := ctx.BlockTime().Unix()
	ws := k.getSpend(ctx, fromStr)
	if ws.WindowStartUnix == 0 || now-ws.WindowStartUnix >= p.WindowSeconds {
		ws.WindowStartUnix = now
		ws.Spent = "0"
	}
	spent, ok := math.NewIntFromString(ws.Spent)
	if !ok {
		spent = math.ZeroInt()
	}
	newSpent := spent.Add(amount)
	if newSpent.GT(capAmt) {
		return errorsmod.Wrapf(types.ErrNetCapExceeded,
			"address %s would exceed net-seller cap: %s + %s > %s aLIMO within %ds window",
			fromStr, spent.String(), amount.String(), capAmt.String(), p.WindowSeconds)
	}

	// Record spend only on block delivery (ante & restriction also run in CheckTx).
	if ctx.IsCheckTx() || ctx.IsReCheckTx() {
		return nil
	}
	ws.Spent = newSpent.String()
	return k.setSpend(ctx, fromStr, ws)
}

func (k Keeper) isModuleAccount(ctx context.Context, addr sdk.AccAddress) bool {
	if k.accountKeeper == nil {
		return false
	}
	acc := k.accountKeeper.GetAccount(ctx, addr)
	if acc == nil {
		return false
	}
	_, ok := acc.(authtypes.ModuleAccountI)
	return ok
}

// SendRestrictionFn is registered via bank.AppendSendRestriction. It enforces the cap on
// x/bank-routed sends (cosmos MsgSend/MultiSend + ERC20/WERC20 precompiles). It does NOT
// see native EVM value transfers (those commit via UncheckedSetBalance) — those are caught
// by the EVM ante decorator instead.
func (k Keeper) SendRestrictionFn(ctx context.Context, from, to sdk.AccAddress, amt sdk.Coins) (sdk.AccAddress, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if err := k.CheckAndRecord(sdkCtx, from, to, amt.AmountOf(BaseDenom)); err != nil {
		return to, err
	}
	return to, nil
}

// --- helpers ---

func spendKey(addr string) []byte {
	out := make([]byte, 0, len(types.SpendPrefix)+len(addr))
	out = append(out, types.SpendPrefix...)
	out = append(out, []byte(addr)...)
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
