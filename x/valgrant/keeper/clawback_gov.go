package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// On the fresh mainnet, protected shares cannot leave grant.ValidatorOp except
// through this authorized reclaim. Historical-chain escape cases documented
// below remain unchanged for replay. Slashing can still reduce recovered value.
//
// ClawbackGrantGov is the surgical clawback of a validator-bootstrap grant.
// It is invoked ONLY from the gated msg server: the gov-gated ClawbackGrant
// (a passed governance proposal) and — since cycle 7 (HIGH-D) — the
// admin-gated Clawback (MsgClawback / the EVM precompile clawback(address)),
// which previously used a blunt undelegate-everything path that could sweep
// the grantee's own stake. ALL clawback surfaces now share this single
// locked-share reclaim. It is fully deterministic and has NO consensus-
// halt path: every failure returns a clean error (the msg handler rolls the tx
// back atomically) and it never panics.
//
// Effects (atomic within the msg handler):
//
//	(1) REVOKE the grant: reclaim ONLY the foundation-granted locked principal
//	    and return it to the foundation reserve pool (NOT to the grantee). The
//	    reclaim targets EXCLUSIVELY the delegation to grant.ValidatorOp and the
//	    still-locked principal physically sitting on the grantee's PLVA:
//	      - bonded portion: force-undelegate ONLY the LOCKED grant shares of the
//	        granted delegation — exactly min(grant.GrantedShares, delegation shares),
//	        where GrantedShares is the module-maintained PER-VALIDATOR ledger (NOT
//	        the account-global DelegatedVesting) — swept after unbonding via the
//	        EndBlock sweep. Because shares are slash-invariant, this reclaims the
//	        grant's proportionally-slashed fair value and leaves the grantee's own
//	        (free) self-bond shares fully intact even when the two are commingled in
//	        ONE delegation or the grant was partially redelegated elsewhere;
//	      - in-account portion: the never-bonded LOCKED coins on the PLVA
//	        (OriginalVesting - DelegatedVesting = LockedCoins), swept immediately.
//	    A slashed granted delegation reclaims the fair slashed value of the locked
//	    shares (correct, not an over-seizure); a granted delegation that was
//	    redelegated away / fully unbonded reclaims only the locked remainder present
//	    at grant.ValidatorOp (never substituted from other funds).
//	(2) CANCEL unvested rewards owed to the grant. There is NO on-chain reward
//	    escrow (rewards are liquid to the grantee by design), so there is nothing
//	    to cancel on-chain and this is reported as 0 (an honest no-op — never a
//	    phantom forfeiture).
//	(3) FORFEIT the exogenous deposit (grant.Deposit) IFF it is escrowed on
//	    chain (grant.DepositEscrowed asserts the pool actually holds it). When
//	    off-chain, this is 0 (a documented no-op recorded in the event).
//	(4) The validator SEAT is left to fall out naturally via unbonding — we do
//	    NOT jail or force-remove it (that could touch consensus). Removing the
//	    granted principal drops the validator's power; if that leaves it below
//	    the active set / min-self-delegation, x/staking unbonds it. Halt-free.
//
// SAFETY BOUNDARY — a validator's OWN self-bond / liquid funds are NEVER clawed
// back:
//   - #1: an account with NO grant record is rejected (its stake is entirely its
//     own; there is nothing foundation-granted to reclaim).
//   - #2: staking reclaim touches ONLY the delegation to grant.ValidatorOp and,
//     within that delegation, at most grant.GrantedShares (the per-validator
//     ledger), which never exceeds the shares minted for the grant at issuance. Any
//     delegation to ANY OTHER validator and the grantee's liquid balance / gas
//     allowance / earned rewards are off-limits - never force-unbonded, never swept.
//     A self-bond commingled at grant.ValidatorOp is preserved in AGGREGATE VALUE,
//     not necessarily at grant.ValidatorOp itself: an outflow from this validator is
//     charged to the grantee's free shares first (HIGH-ERODE), so a grantee who
//     moves stake away from here may see the reclaim executed against the shares
//     that remain. They can never lose more than the grant.
//   - #3: the immediate sweep moves ONLY the locked (non-spendable) principal on
//     the PLVA, read from the vesting account itself — never the spendable
//     balance. On a shortfall (slash) it under-reclaims rather than dipping into
//     liquid funds.
//
// Returns the principal returned immediately, the principal still pending
// (unbonding), the rewards cancelled, the deposit forfeited, and the grant's
// validator operator (for the event / response).
func (k Keeper) ClawbackGrantGov(ctx context.Context, granteeStr, reason string) (
	principalReturned, principalPending, rewardsCancelled, depositForfeited math.Int, valoper string, err error,
) {
	principalReturned = math.ZeroInt()
	principalPending = math.ZeroInt()
	rewardsCancelled = math.ZeroInt()
	depositForfeited = math.ZeroInt()

	grantee, derr := k.accountKeeper.AddressCodec().StringToBytes(granteeStr)
	if derr != nil {
		return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper,
			fmt.Errorf("invalid grantee address %q: %w", granteeStr, derr)
	}

	// SAFETY BOUNDARY #1: only a FOUNDATION-GRANTED account is clawback-able.
	grant, found := k.GetGrant(ctx, granteeStr)
	if !found {
		return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper,
			fmt.Errorf("no valgrant grant for %s: only foundation-granted locked principal is clawback-able (a validator's own self-bond is not)", granteeStr)
	}
	valoper = grant.ValidatorOp

	// Idempotency guard: never re-sweep an already-revoked grant (that would claw
	// back the grantee's legitimate gas + earned rewards).
	if grant.Status == "revoked" {
		return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper,
			fmt.Errorf("grant for %s is already revoked", granteeStr)
	}

	lockedPrincipal, ok := math.NewIntFromString(grant.LockedAmount)
	if !ok || lockedPrincipal.IsNegative() {
		return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper,
			fmt.Errorf("grant %s has invalid locked_amount %q", granteeStr, grant.LockedAmount)
	}

	bondDenom, derr := k.stakingKeeper.BondDenom(ctx)
	if derr != nil {
		return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper, derr
	}

	// --- (1) reclaim ONLY the LOCKED grant shares at grant.ValidatorOp ---
	// SAFETY BOUNDARY #2 (HIGH-A-CROSS — commingled self-bond, cross-validator). A
	// validator operator's OWN self-bond and the foundation grant can BOTH be
	// delegations from the grantee to grant.ValidatorOp (x/staking MERGES them into
	// ONE Delegation), and the grantee may also (partially) redelegate the locked
	// grant to a DIFFERENT validator while self-bonding their own funds here. We
	// reclaim ONLY the locked (grant) shares STILL present at grant.ValidatorOp,
	// never more than the grant's own share count at issuance, and never anything
	// at another validator.
	//
	// The locked-share count is the module-maintained PER-VALIDATOR ledger
	// grant.GrantedShares — NOT the account-global DelegatedVesting aggregate.
	// DelegatedVesting is filled by delegation ORDER regardless of validator and is
	// blind to redelegation, so it cannot identify the locked shares at a specific
	// validator (that is exactly the HIGH-A-CROSS defect). GrantedShares is recorded
	// when the module delegates the locked principal at issuance and is CLAMPED by
	// the staking hooks to the live shares at grant.ValidatorOp, an outflow being
	// charged to the grantee's FREE shares first (HIGH-ERODE; see
	// keeper.reconcileGrantShares for why, and for the boundary this does NOT fix).
	//
	// We undelegate exactly  min(GrantedShares, delegation.Shares)  shares:
	//   - SLASHED (below OR above nominal): shares are slash-invariant, so Undelegate
	//     returns the locked shares' PROPORTIONALLY-slashed token value (the grant's
	//     fair value) — never the free shares (CAP 40%: 2000 sh/1200 tok, take 1000
	//     -> 600 fair, leave 1000 sh/600 tok own; FALLBACK 70%: 2000 sh/600 tok, take
	//     1000 -> 300 fair, leave 300 own).
	//   - PARTIALLY MOVED AWAY: the clamp left GrantedShares at the live share count
	//     when it fell below the grant, so the reclaim never exceeds what is bonded
	//     here; whatever was redelegated elsewhere is left where it went (an
	//     under-reclaim the module does NOT chase - the clawback is not a guarantee
	//     of full recovery).
	//   - FULLY REDELEGATED / UNBONDED AWAY: GrantedShares is 0 -> reclaim 0, never
	//     substituted from a delegation elsewhere or from liquid.
	undelegated := math.ZeroInt()
	var pendingEntries []types.PendingClawbackEntry

	// The grantee account is read ONCE and reused for the in-account locked sweep.
	acc := k.accountKeeper.GetAccount(ctx, grantee)
	plva, isPLVA := acc.(*vestingtypes.PermanentLockedAccount)

	grantedShares := parseDecOrZero(grant.GrantedShares)
	if grantedShares.IsPositive() {
		delegations, derr := k.stakingKeeper.GetDelegatorDelegations(ctx, grantee, 255)
		if derr != nil {
			return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper, derr
		}
		for _, del := range delegations {
			// ONLY the granted validator is clawback-able. Skip self-bond / any
			// other delegation regardless of store/bech32 iteration order.
			if del.ValidatorAddress != grant.ValidatorOp {
				continue
			}
			valAddr, verr := k.stakingKeeper.ValidatorAddressCodec().StringToBytes(del.ValidatorAddress)
			if verr != nil {
				return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper, verr
			}
			// Reclaim EXACTLY the granted (locked) shares still delegated here,
			// capped at the live shares (which also carry the grantee's own/free
			// self-bond). NEVER derived from the global DelegatedVesting aggregate.
			lockedShares := math.LegacyMinDec(grantedShares, del.Shares)
			if lockedShares.IsNil() || !lockedShares.IsPositive() {
				break
			}
			// The msg handlers have already enforced admin/governance authority.
			// Scope the bypass to this grantee and this staking call only.
			clawbackCtx := sdk.UnwrapSDKContext(ctx).WithValue(mainnetClawbackKey{}, granteeStr)
			completion, amt, uerr := k.stakingKeeper.Undelegate(clawbackCtx, grantee, sdk.ValAddress(valAddr), lockedShares)
			if uerr != nil {
				return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper,
					fmt.Errorf("undelegate from %s failed: %w", del.ValidatorAddress, uerr)
			}
			undelegated = amt
			pendingEntries = append(pendingEntries, types.PendingClawbackEntry{
				Validator:       del.ValidatorAddress,
				Amount:          amt.String(),
				CompletionUnix:  completion.Unix(),
				CompletionNanos: completion.UnixNano(),
				CreationHeight:  sdk.UnwrapSDKContext(ctx).BlockHeight(),
			})
			break // the reclaim touches the granted validator ONLY
		}
	}

	// The bonded principal we sweep later (after unbonding) is exactly the fair
	// (slashed) token value we undelegated from the locked shares, capped at the
	// nominal grant (defensive; the deferred sweep delivers this recorded amount
	// bounded by (balance - gasAllowance) so it can never seize liquid or orphan the
	// principal — see SweepMaturedClawbacks).
	pendingPrincipal := undelegated
	if pendingPrincipal.GT(lockedPrincipal) {
		pendingPrincipal = lockedPrincipal
	}

	// --- immediate sweep of the IN-ACCOUNT LOCKED principal (HIGH-2, MED PLVA) ---
	// The only principal we may sweep from the account NOW is the still-locked,
	// never-bonded portion of the grant that physically sits on the grantee's
	// PermanentLockedAccount (OriginalVesting - DelegatedVesting = LockedCoins).
	// We read it from the vesting account itself — NOT from the spendable balance
	// — so the grantee's liquid gas allowance, own funds, and earned rewards are
	// NEVER swept. A plain BaseAccount (nothing locked in-account) => 0, so a
	// slash shortfall under-reclaims instead of dipping into liquid funds.
	inAccountLocked := math.ZeroInt()
	if isPLVA {
		inAccountLocked = plva.LockedCoins(sdk.UnwrapSDKContext(ctx).BlockTime()).AmountOf(bondDenom)
	}
	// Never sweep more locked principal than the nominal grant not already covered
	// by the bonded reclaim above.
	remainingNominal := lockedPrincipal.Sub(pendingPrincipal)
	if remainingNominal.IsNegative() {
		remainingNominal = math.ZeroInt()
	}
	immediatePrincipal := inAccountLocked
	if immediatePrincipal.GT(remainingNominal) {
		immediatePrincipal = remainingNominal
	}

	// Only unlock the PLVA when we are ACTUALLY sweeping in-account locked
	// principal now; otherwise leave the permanent lock intact on any unreclaimed
	// remainder (MED PLVA: do NOT blanket-unlock).
	if immediatePrincipal.IsPositive() {
		// Unlock the PLVA (convert -> BaseAccount) so the locked coins are movable,
		// then send ONLY the locked principal back to the pool. Rewards + gas
		// (spendable) are left with the grantee.
		//
		// immediatePrincipal is bounded by LockedCoins — the genuine in-account locked
		// grant principal, read from the vesting account BEFORE any of THIS clawback's
		// undelegation returns, so (unlike the deferred sweep) it is NOT subject to the
		// free-first re-bucketing and is accurate here. We additionally floor the sweep
		// at (balance - gasAllowance), symmetric with SweepMaturedClawbacks, so the
		// grantee's liquid gas allowance is never taken.
		k.unlockAccount(ctx, grantee)
		bal := k.bankKeeper.GetBalance(ctx, grantee, bondDenom).Amount
		maxSweep := bal.Sub(parseIntOrZero(grant.GasAllowance))
		if maxSweep.IsNegative() {
			maxSweep = math.ZeroInt()
		}
		sweep := immediatePrincipal
		if sweep.GT(maxSweep) {
			sweep = maxSweep
		}
		if sweep.IsPositive() {
			coins := sdk.NewCoins(sdk.NewCoin(bondDenom, sweep))
			if serr := k.bankKeeper.SendCoinsFromAccountToModule(ctx, grantee, types.ModuleName, coins); serr != nil {
				return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper,
					fmt.Errorf("immediate principal sweep failed: %w", serr)
			}
			principalReturned = sweep
		}
	}

	// --- record the deferred (bonded) sweep for the existing EndBlock handler ---
	if pendingPrincipal.IsPositive() {
		pc := types.PendingClawback{
			Grantee:     granteeStr,
			Entries:     pendingEntries,
			SweepAmount: pendingPrincipal.String(),
			InitiatedAt: sdk.UnwrapSDKContext(ctx).BlockTime().Unix(),
		}
		if serr := k.SetPendingClawback(ctx, pc); serr != nil {
			return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper, serr
		}
		principalPending = pendingPrincipal
	}

	// --- (2) cancel unvested rewards owed to the grant ---
	// There is NO on-chain reward escrow in this design (rewards are liquid to the
	// grantee by design), so there is nothing held on-chain to cancel: report 0
	// rather than a phantom forfeiture the event has no coin move to back. The
	// stored claim field is voided below purely as bookkeeping.
	rewardsCancelled = math.ZeroInt()

	// --- (3) forfeit the exogenous deposit IFF it is escrowed on-chain ---
	// depositForfeited is non-zero ONLY when DepositEscrowed asserts the deposit is
	// actually held on-chain in the reserve pool (backed); off-chain => 0 no-op.
	depositOnChain := grant.DepositEscrowed
	if grant.DepositEscrowed && grant.Deposit != "" {
		if v, ok := math.NewIntFromString(grant.Deposit); ok && v.IsPositive() {
			// The deposit is held in the foundation reserve pool; forfeiture leaves it
			// there (it is NOT refunded to the grantee).
			depositForfeited = v
		}
	}

	// --- mark the grant revoked + void the (now-cancelled) escrow claims ---
	grant.Status = "revoked"
	grant.UnvestedRewards = "0"
	grant.Deposit = "0"
	grant.DepositEscrowed = false
	if serr := k.SetGrant(ctx, grant); serr != nil {
		return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper, serr
	}

	// --- (4) validator seat: left to fall out via unbonding (halt-free) ---

	// Loud event.
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent(
		"valgrant_clawback",
		sdk.NewAttribute("grantee", granteeStr),
		sdk.NewAttribute("valoper", valoper),
		sdk.NewAttribute("reason", reason),
		sdk.NewAttribute("principal_returned", principalReturned.String()),
		sdk.NewAttribute("principal_pending", principalPending.String()),
		sdk.NewAttribute("principal_total", principalReturned.Add(principalPending).String()),
		sdk.NewAttribute("rewards_cancelled", rewardsCancelled.String()),
		sdk.NewAttribute("deposit_forfeited", depositForfeited.String()),
		sdk.NewAttribute("deposit_on_chain", fmt.Sprintf("%t", depositOnChain)),
	))

	return principalReturned, principalPending, rewardsCancelled, depositForfeited, valoper, nil
}
