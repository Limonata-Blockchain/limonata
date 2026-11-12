package keeper

import (
	"context"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// On the fresh mainnet, hooks reject movements of protected grant shares and
// cancellation of an in-flight clawback. Historical chains keep the ledger-only
// behavior described below, preserving their existing replay.
//
// Hooks wires x/valgrant into the x/staking delegation lifecycle so the module
// can FOLLOW the locked grant's shares as they move off grant.ValidatorOp via
// redelegation / partial-unbond. It implements stakingtypes.StakingHooks; only
// the delegation-share hooks do work (all validator/unbonding hooks are no-ops).
//
// WHY a bespoke ledger (HIGH-A-CROSS): the SDK does NOT track locked (vesting)
// shares PER-VALIDATOR. Its PermanentLockedAccount.DelegatedVesting is an
// account-GLOBAL aggregate that (a) is filled by delegation ORDER regardless of
// WHICH validator receives the delegation and (b) is blind to redelegation
// (bonded->bonded moves shares between validators WITHOUT touching the vesting
// buckets). Reclaiming min(DelegatedVesting, delegation.Shares) at
// grant.ValidatorOp therefore mis-attributes the grantee's OWN/free shares in any
// split / redelegate topology. This ledger records the grant's shares at issuance
// (a module-performed delegation) and CLAMPS them to the live shares at
// grant.ValidatorOp as the delegation moves, so the clawback reclaims the locked
// remainder still present here. See reconcileGrantShares for the attribution
// rule (free-first, HIGH-ERODE) and for what it deliberately does NOT fix.
type Hooks struct{ k Keeper }

var _ stakingtypes.StakingHooks = Hooks{}

// Hooks returns the x/valgrant staking hooks. Registered into the staking
// MultiStakingHooks in app.go so redelegation / partial-unbond of a granted
// delegation keeps GrantedShares correct.
func (k Keeper) Hooks() Hooks { return Hooks{k: k} }

// --- delegation lifecycle: maintain the per-validator granted-share ledger ---

// AfterDelegationModified fires after a delegation's shares are set to a new,
// still-non-zero value (create, additional self-bond, redelegate destination, or
// the remainder after a partial unbond/redelegate). Reconcile the grant ledger
// against the LIVE shares now at (delAddr, valAddr).
func (h Hooks) AfterDelegationModified(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error {
	remaining := h.k.liveDelegationShares(ctx, delAddr, valAddr)
	if err := h.k.guardMainnetGrantShares(ctx, delAddr, valAddr, remaining); err != nil {
		return err
	}
	h.k.reconcileGrantShares(ctx, delAddr, valAddr, remaining)
	return nil
}

// BeforeDelegationRemoved fires when a delegation is about to be fully removed
// (every share has left this validator). The live share count is effectively 0.
func (h Hooks) BeforeDelegationRemoved(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error {
	if err := h.k.guardMainnetGrantShares(ctx, delAddr, valAddr, math.LegacyZeroDec()); err != nil {
		return err
	}
	h.k.reconcileGrantShares(ctx, delAddr, valAddr, math.LegacyZeroDec())
	return nil
}

// --- no-op hooks (present to satisfy stakingtypes.StakingHooks) ---

func (h Hooks) BeforeDelegationCreated(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error {
	return h.k.guardMainnetGrantDestination(ctx, delAddr, valAddr)
}
func (h Hooks) BeforeDelegationSharesModified(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error {
	return h.k.guardMainnetGrantDestination(ctx, delAddr, valAddr)
}
func (h Hooks) AfterValidatorCreated(context.Context, sdk.ValAddress) error { return nil }
func (h Hooks) BeforeValidatorModified(context.Context, sdk.ValAddress) error {
	return nil
}
func (h Hooks) AfterValidatorRemoved(context.Context, sdk.ConsAddress, sdk.ValAddress) error {
	return nil
}
func (h Hooks) AfterValidatorBonded(context.Context, sdk.ConsAddress, sdk.ValAddress) error {
	return nil
}
func (h Hooks) AfterValidatorBeginUnbonding(context.Context, sdk.ConsAddress, sdk.ValAddress) error {
	return nil
}
func (h Hooks) BeforeValidatorSlashed(context.Context, sdk.ValAddress, math.LegacyDec) error {
	return nil
}
func (h Hooks) AfterUnbondingInitiated(context.Context, uint64) error { return nil }

// --- ledger internals ---

// liveDelegationShares returns the grantee's current delegation shares at valAddr
// (zero if there is no such delegation). Never errors — a bookkeeping read must
// not block a staking operation.
func (k Keeper) liveDelegationShares(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) math.LegacyDec {
	del, err := k.stakingKeeper.GetDelegation(ctx, delAddr, valAddr)
	if err != nil {
		return math.LegacyZeroDec()
	}
	return del.Shares
}

// reconcileGrantShares follows the LOCKED grant's shares at grant.ValidatorOp.
// Called from the staking hooks with the delegation's LIVE shares after a change
// (0 when removed).
//
// RULE (HIGH-ERODE fix):  GrantedShares = min(GrantedShares, live shares here).
// The ledger is CLAMPED to the live shares and is otherwise left alone. It is
// never increased (a post-issuance increase at grant.ValidatorOp is the
// grantee's OWN free self-bond), and a decrease is charged to the grantee's FREE
// shares FIRST - the grant is only debited once the live count falls BELOW it,
// i.e. once the outflow provably ate into the foundation principal.
//
// WHY free-FIRST, not grant-first. Shares are fungible: when a merged delegation
// (grant + own self-bond) shrinks, no on-chain fact says WHICH shares left, so
// the attribution is a policy choice, and the SDK has already made it at the
// ACCOUNT level. x/auth's BaseVestingAccount.TrackUndelegation charges an
// undelegation to the FREE bucket first (x := min(DelegatedFree, D), y :=
// min(DelegatedVesting, D-X)), so an undelegating grantee gets their own money
// back spendable while the locked principal stays counted as delegated
// (DelegatedVesting) or is re-locked in-account. Charging free-first here keeps
// this per-validator ledger IN STEP with that account-level bucketing: the
// bonded remainder the clawback reclaims plus the in-account locked coins it
// sweeps always add back up to the foundation principal.
//
// The previous rule charged every decrease to the GRANT first, described as "the
// only SAFE choice" because over-decrementing merely under-reclaims. That was
// wrong, and it was the HIGH-ERODE defect: the sequence
//
//	grant 1000 -> grantee self-bonds 1000 of their OWN liquid -> grantee
//	withdraws that same own 1000
//
// drove GrantedShares to 0 (it is never re-increased) while the foundation's
// 1000 was still bonded at grant.ValidatorOp, so a later clawback reclaimed
// NOTHING. Any grantee could zero their own clawback exposure at will. See
// audit_erosion_probe_test.go.
//
// WHAT THIS DOES NOT FIX (the honest boundary - the clawback is NOT a guarantee
// of full recovery):
//   - Shares REDELEGATED off grant.ValidatorOp still escape the reclaim, which
//     only ever touches grant.ValidatorOp. Under the clamp, an outflow is
//     attributed to the grantee's free shares first, so a redelegation away is
//     read as the grantee moving THEIR OWN stake; the grant's aggregate value is
//     preserved when the grantee moves less than their own contribution, and the
//     foundation still under-reclaims when the grantee redelegates more than
//     that. Following the grant across a redelegation needs the destination side
//     of the move, which no staking hook reports (BeginRedelegation writes its
//     redelegation record AFTER both Unbond and Delegate have fired their hooks),
//     so it is a design item, not a patch.
//   - Consequently the seizure is location-based: a grantee who commingles at
//     grant.ValidatorOp and then moves stake elsewhere keeps their own
//     contribution in AGGREGATE VALUE (across validators), not necessarily at
//     grant.ValidatorOp itself. The reclaim is still bounded by the grant's own
//     share count at issuance (GrantedShares only ever decreases), so a grantee
//     can never lose more than the grant.
//
// Deterministic (reads only the live delegation), idempotent, never blocks a
// staking operation.
func (k Keeper) reconcileGrantShares(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress, nowShares math.LegacyDec) {
	granteeStr, err := k.accountKeeper.AddressCodec().BytesToString(delAddr.Bytes())
	if err != nil {
		return
	}
	grant, found := k.GetGrant(ctx, granteeStr)
	if !found || grant.Status == "revoked" {
		return
	}
	valStr, verr := k.stakingKeeper.ValidatorAddressCodec().BytesToString(valAddr.Bytes())
	if verr != nil || grant.ValidatorOp != valStr {
		return // only grant.ValidatorOp carries a locked-share ledger
	}

	if nowShares.IsNil() {
		nowShares = math.LegacyZeroDec()
	}
	granted := parseDecOrZero(grant.GrantedShares)
	tracked := parseDecOrZero(grant.TrackedShares)

	changed := false
	// CLAMP: the grant cannot hold more shares than are delegated here. Anything
	// above the live count provably left; anything at or below it is still the
	// foundation's, whatever the grantee's own shares did in the meantime.
	if granted.GT(nowShares) {
		grant.GrantedShares = nowShares.String()
		changed = true
	}
	// TrackedShares is now purely observational (the last live total seen here).
	// The clamp above needs no history, which is exactly why the erosion sequence
	// can no longer accumulate against the grant.
	if !tracked.Equal(nowShares) {
		grant.TrackedShares = nowShares.String()
		changed = true
	}
	if changed {
		_ = k.SetGrant(ctx, grant)
	}
}

// parseDecOrZero parses a math.LegacyDec string, returning zero for "" or a
// malformed value (defensive; the ledger only ever writes valid decimals).
func parseDecOrZero(s string) math.LegacyDec {
	if s == "" {
		return math.LegacyZeroDec()
	}
	d, err := math.LegacyNewDecFromStr(s)
	if err != nil {
		return math.LegacyZeroDec()
	}
	return d
}
