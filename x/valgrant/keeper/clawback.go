package keeper

import (
	"context"
	"fmt"
	"time"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// Clawback force-undelegates the grantee's delegations and sweeps the LOCKED
// PRINCIPAL (grant.LockedAmount) back to the valgrant pool, leaving earned
// rewards + gas with the grantee, then marks the grant revoked.
//
// Two portions of principal:
//   - IN-ACCOUNT locked (never bonded, or already returned): swept IMMEDIATELY.
//   - BONDED (delegated): force-undelegated now -> starts unbonding -> swept
//     later by the deferred EndBlock sweep once the unbonding matures.
//
// CRITICAL: a PermanentLockedAccount's locked coins cannot be moved by
// SendCoinsFromAccountToModule (the bank spendable check blocks them). To sweep
// we FIRST unlock by converting the account to a plain BaseAccount (same
// addr/pubkey/number/sequence), THEN SendCoinsFromAccountToModule.
//
// Returns: total undelegated (bonded principal sent to unbonding), the amount
// swept immediately, and the amount left pending (deferred sweep).
func (k Keeper) Clawback(ctx context.Context, granteeStr string) (undelegated, sweptNow, pending math.Int, err error) {
	undelegated, sweptNow, pending = math.ZeroInt(), math.ZeroInt(), math.ZeroInt()

	grantee, derr := k.accountKeeper.AddressCodec().StringToBytes(granteeStr)
	if derr != nil {
		return undelegated, sweptNow, pending, fmt.Errorf("invalid grantee address %q: %w", granteeStr, derr)
	}

	grant, found := k.GetGrant(ctx, granteeStr)
	if !found {
		return undelegated, sweptNow, pending, fmt.Errorf("grant for %s not found", granteeStr)
	}
	// Idempotency guard: never re-sweep an already-revoked grant (that would
	// claw back the grantee's legitimate gas + earned rewards). Once revoked the
	// principal has been (or will be, via the pending sweep) returned to the pool.
	if grant.Status == "revoked" {
		return undelegated, sweptNow, pending, fmt.Errorf("grant for %s is already revoked", granteeStr)
	}

	bondDenom, derr := k.stakingKeeper.BondDenom(ctx)
	if derr != nil {
		return undelegated, sweptNow, pending, derr
	}

	lockedPrincipal, ok := math.NewIntFromString(grant.LockedAmount)
	if !ok {
		return undelegated, sweptNow, pending, fmt.Errorf("grant %s has invalid locked_amount %q", granteeStr, grant.LockedAmount)
	}

	// --- (a) force-undelegate all delegations (bonded principal) ---
	delegations, derr := k.stakingKeeper.GetDelegatorDelegations(ctx, grantee, 255)
	if derr != nil {
		return undelegated, sweptNow, pending, derr
	}

	var pendingEntries []types.PendingClawbackEntry
	for _, del := range delegations {
		valAddr, verr := k.stakingKeeper.ValidatorAddressCodec().StringToBytes(del.ValidatorAddress)
		if verr != nil {
			return undelegated, sweptNow, pending, verr
		}
		completionTime, amt, uerr := k.stakingKeeper.Undelegate(ctx, grantee, sdk.ValAddress(valAddr), del.Shares)
		if uerr != nil {
			return undelegated, sweptNow, pending, fmt.Errorf("undelegate from %s failed: %w", del.ValidatorAddress, uerr)
		}
		undelegated = undelegated.Add(amt)
		pendingEntries = append(pendingEntries, types.PendingClawbackEntry{
			Validator:      del.ValidatorAddress,
			Amount:         amt.String(),
			CompletionUnix: completionTime.Unix(),
		})
	}

	// The bonded principal we will sweep later is capped at grant.LockedAmount.
	pendingPrincipal := undelegated
	if pendingPrincipal.GT(lockedPrincipal) {
		pendingPrincipal = lockedPrincipal
	}

	// --- (b) sweep the IN-ACCOUNT locked principal immediately ---
	// The immediate portion of principal we may sweep is the part of the
	// locked principal that is NOT currently bonded (i.e. still in-account).
	immediatePrincipal := lockedPrincipal.Sub(pendingPrincipal)
	if immediatePrincipal.IsPositive() {
		// Unlock the account (convert PLVA -> BaseAccount) so the locked coins
		// become spendable, then send the principal back to the pool.
		k.unlockAccount(ctx, grantee)

		// Cap the immediate sweep at the actual in-account balance of bondDenom
		// (rewards/gas are spendable too, but we only sweep principal).
		bal := k.bankKeeper.GetBalance(ctx, grantee, bondDenom).Amount
		sweep := immediatePrincipal
		if sweep.GT(bal) {
			sweep = bal
		}
		if sweep.IsPositive() {
			coins := sdk.NewCoins(sdk.NewCoin(bondDenom, sweep))
			if serr := k.bankKeeper.SendCoinsFromAccountToModule(ctx, grantee, types.ModuleName, coins); serr != nil {
				return undelegated, sweptNow, pending, fmt.Errorf("immediate sweep failed: %w", serr)
			}
			sweptNow = sweep
		}
	}

	// --- record the deferred (bonded) portion for the EndBlock sweep ---
	if pendingPrincipal.IsPositive() {
		pc := types.PendingClawback{
			Grantee:     granteeStr,
			Entries:     pendingEntries,
			SweepAmount: pendingPrincipal.String(),
			InitiatedAt: sdk.UnwrapSDKContext(ctx).BlockTime().Unix(),
		}
		if serr := k.SetPendingClawback(ctx, pc); serr != nil {
			return undelegated, sweptNow, pending, serr
		}
		pending = pendingPrincipal
	}

	// --- mark grant revoked ---
	grant.Status = "revoked"
	if serr := k.SetGrant(ctx, grant); serr != nil {
		return undelegated, sweptNow, pending, serr
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent(
		"valgrant_clawed_back",
		sdk.NewAttribute("grantee", granteeStr),
		sdk.NewAttribute("locked_amount", grant.LockedAmount),
		sdk.NewAttribute("undelegated", undelegated.String()),
		sdk.NewAttribute("swept_now", sweptNow.String()),
		sdk.NewAttribute("pending", pending.String()),
	))

	return undelegated, sweptNow, pending, nil
}

// unlockAccount converts a grantee's PermanentLockedAccount into a plain
// BaseAccount (same addr/pubkey/number/sequence), removing the vesting lock so
// the bank spendable check no longer blocks the principal sweep. No-op if the
// account is not a vesting account.
func (k Keeper) unlockAccount(ctx context.Context, grantee sdk.AccAddress) {
	acc := k.accountKeeper.GetAccount(ctx, grantee)
	if acc == nil {
		return
	}
	if _, isVesting := acc.(*vestingtypes.PermanentLockedAccount); !isVesting {
		return
	}
	base := authtypes.NewBaseAccount(acc.GetAddress(), acc.GetPubKey(), acc.GetAccountNumber(), acc.GetSequence())
	k.accountKeeper.SetAccount(ctx, base)
}

// SweepMaturedClawbacks is called from EndBlock (ordered AFTER x/staking, so the
// staking module has already run CompleteUnbonding for matured entries and
// returned the coins to the grantee's account — RE-LOCKED on the PLVA). It
// unlocks each grantee whose entries have all matured and sweeps the recorded
// principal back to the pool.
func (k Keeper) SweepMaturedClawbacks(ctx context.Context) error {
	now := sdk.UnwrapSDKContext(ctx).BlockTime()

	bondDenom, err := k.stakingKeeper.BondDenom(ctx)
	if err != nil {
		return err
	}

	type ready struct {
		pc    types.PendingClawback
		addr  sdk.AccAddress
		sweep math.Int
	}
	var readyList []ready

	k.IteratePendingClawbacks(ctx, func(pc types.PendingClawback) {
		// all entries must be mature
		for _, e := range pc.Entries {
			if time.Unix(e.CompletionUnix, 0).After(now) {
				return
			}
		}
		addr, derr := k.accountKeeper.AddressCodec().StringToBytes(pc.Grantee)
		if derr != nil {
			return
		}
		sweep, ok := math.NewIntFromString(pc.SweepAmount)
		if !ok {
			return
		}
		readyList = append(readyList, ready{pc: pc, addr: addr, sweep: sweep})
	})

	for _, r := range readyList {
		// staking's CompleteUnbonding (already run this block) returned the coins
		// to the account, re-locked on the PLVA. Unlock then sweep the principal.
		k.unlockAccount(ctx, r.addr)

		bal := k.bankKeeper.GetBalance(ctx, r.addr, bondDenom).Amount
		sweep := r.sweep
		if sweep.GT(bal) {
			sweep = bal
		}
		if sweep.IsPositive() {
			coins := sdk.NewCoins(sdk.NewCoin(bondDenom, sweep))
			if serr := k.bankKeeper.SendCoinsFromAccountToModule(ctx, r.addr, types.ModuleName, coins); serr != nil {
				sdk.UnwrapSDKContext(ctx).Logger().Error("valgrant deferred sweep failed", "grantee", r.pc.Grantee, "err", serr)
				continue
			}
		}
		k.DeletePendingClawback(ctx, r.pc.Grantee)
		sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent(
			"valgrant_clawback_swept",
			sdk.NewAttribute("grantee", r.pc.Grantee),
			sdk.NewAttribute("swept", sweep.String()),
		))
	}
	return nil
}
