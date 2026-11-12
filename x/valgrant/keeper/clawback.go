package keeper

import (
	"context"
	"time"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// NOTE (HIGH-D, cycle 7): the legacy blunt Clawback — which force-undelegated
// EVERY delegation the grantee held (self-bond at the granted validator + every
// other-validator delegation) and recorded each entry's FULL amount, relying on
// the SweepAmount cap alone to bound the pool credit — has been RETIRED. Both
// non-governance surfaces (the admin-gated MsgClawback and the EVM precompile
// clawback(address), which routes through the same msg server) now execute the
// SAME surgical locked-share reclaim as the governance path: ClawbackGrantGov
// undelegates only min(grant.GrantedShares, delegation shares) at
// grant.ValidatorOp - never more than the shares minted for the grant at
// issuance - so every pending entry is bounded by the foundation principal and
// other-validator delegations are never touched. See msg_server.go
// (msgServer.Clawback), clawback_gov.go, and keeper.reconcileGrantShares for how
// an outflow at grant.ValidatorOp is attributed (free-first, HIGH-ERODE).

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
// returned the reclaimed principal to the grantee's account). Each block, per
// pending clawback, it does one of two jobs:
//
//   - CAPTURE (entry still unbonding): for every recorded entry not yet matured, it
//     reads the grantee's LIVE x/staking UnbondingDelegation and records the identified
//     entry's current Balance into ResolvedBalance (RAW, uncapped) and — once, at the
//     first EndBlock after the clawback — its InitialBalance into EntryInit. x/staking
//     DECREMENTS an unbonding entry's Balance IN PLACE on a re-slash during the unbonding
//     window and NEVER slashes a matured entry, so the Balance captured on the last
//     pre-maturity block EQUALS the amount CompleteUnbonding hands back at maturity;
//     InitialBalance is slash-invariant, so EntryInit is captured once and frozen.
//
//   - SWEEP (every entry matured): x/staking (ordered before us) has already returned
//     the coins; the pool is credited the sum of the entries' PROPORTIONAL grant shares
//     floor(Amount * ResolvedBalance / EntryInit) (see entryPoolCredit), CAPPED at the
//     recorded locked principal pc.SweepAmount (HIGH-D safety belt: the pool can never
//     receive more than the reclaimed foundation principal, whatever the entries hold).
//
// HIGH-C / HIGH-C-MERGE (re-slash-aware, merge-safe amount — no over-credit, no orphan,
// no seizure of the grantee's own same-block return):
//
//	A re-slash during the unbonding window shrinks the ACTUAL returned principal below the
//	amount recorded at clawback. The OLD sweep sent min(recorded, balance - gas): on a
//	re-slash it took the (recorded - actual) shortfall out of the grantee's earned
//	rewards / own liquid (OVER-CREDIT) and, with a spent-down gas balance, ORPHANED
//	principal. Cycle-6 credited the tracked entry's matured Balance directly — correct for
//	a SOLE-grant entry, but when the grantee undelegates their OWN self-bond at
//	grant.ValidatorOp in the clawback block, x/staking's AddEntry MERGES it into the
//	tracked entry (summing InitialBalance/Balance); crediting the merged Balance then
//	seized the grantee's own return. The proportional credit floor(Amount * currentBalance
//	/ EntryInit) takes ONLY the grant's fair fraction (Amount/EntryInit) of the re-slashed
//	matured Balance, so the grantee always keeps currentBalance - credit; with NO merge
//	EntryInit == Amount and it reduces EXACTLY to the proven cycle-6 Balance credit. The
//	grantee's gas allowance, earned rewards, own self-bond, own same-block undelegation
//	return, and redelegation targets are all left fully intact.
//
// HIGH-B (never fire early; preserved):
//   - Maturity gates on the FULL-nanosecond completion (entryCompletion), NEVER a
//     whole-second-truncated value, so the sweep can never fire in the sub-second gap
//     BEFORE x/staking's CompleteUnbonding returns the coins.
//   - The PLVA is unlocked ONLY when principal is actually swept (never a blanket
//     unlock), so a pure-vesting return (correctly re-locked) is still movable.
func (k Keeper) SweepMaturedClawbacks(ctx context.Context) error {
	now := sdk.UnwrapSDKContext(ctx).BlockTime()

	bondDenom, err := k.stakingKeeper.BondDenom(ctx)
	if err != nil {
		return err
	}

	type readyClawback struct {
		pc   types.PendingClawback
		addr sdk.AccAddress
	}
	// Collect during iteration; mutate the store only AFTER the iterator closes
	// (writing to the iterated prefix mid-iteration is unsafe).
	var ready []readyClawback
	var toPersist []types.PendingClawback

	k.IteratePendingClawbacks(ctx, func(pc types.PendingClawback) {
		addr, derr := k.accountKeeper.AddressCodec().StringToBytes(pc.Grantee)
		if derr != nil {
			return
		}
		allMatured := true
		changed := false
		for i := range pc.Entries {
			// EVERY entry must be strictly matured at FULL nanosecond precision before
			// we sweep, so x/staking (which matures UnbondingDelegations at nanosecond
			// precision and runs earlier this block) has already returned the coins.
			stillUnbonding := entryCompletion(pc.Entries[i]).After(now)
			if mainnetGrantProtection(ctx) && !stillUnbonding {
				// A maturity timestamp alone does not prove staking has returned the
				// funds (an entry can be held). Never replace them with personal gas.
				_, _, live := k.liveClawbackEntry(ctx, addr, pc.Entries[i])
				stillUnbonding = live
			}
			if stillUnbonding {
				allMatured = false
				// Still unbonding: capture the identified entry's live state. x/staking
				// mutates Balance in place on a re-slash; the last pre-maturity capture is
				// final (a matured entry is never slashed).
				if bal, initBal, ok := k.liveClawbackEntry(ctx, addr, pc.Entries[i]); ok {
					// currentBalance: the entry's live, re-slash-aware Balance (the WHOLE,
					// possibly-merged entry). Captured RAW — NOT capped at the grant's
					// recorded Amount — because a same-block grantee undelegation merged
					// into this entry can legitimately push it above Amount; the
					// proportional credit at maturity scales it by Amount/EntryInit.
					if s := bal.String(); s != pc.Entries[i].ResolvedBalance {
						pc.Entries[i].ResolvedBalance = s
						changed = true
					}
					// entryInit: the entry's InitialBalance = Amount (the grant's reclaim)
					// + any same-block grantee self-undelegation merged in by x/staking
					// AddEntry. InitialBalance is slash-INVARIANT, so it is captured ONCE
					// (the first EndBlock after the clawback, by which point every same-block
					// undelegation has already merged) and then frozen.
					if pc.Entries[i].EntryInit == "" && initBal.IsPositive() {
						pc.Entries[i].EntryInit = initBal.String()
						changed = true
					}
				}
			}
		}
		if allMatured {
			ready = append(ready, readyClawback{pc: pc, addr: addr})
		} else if changed {
			toPersist = append(toPersist, pc)
		}
	})

	// Persist captured re-slash-aware balances for still-unbonding clawbacks.
	for _, pc := range toPersist {
		if serr := k.SetPendingClawback(ctx, pc); serr != nil {
			sdk.UnwrapSDKContext(ctx).Logger().Error("valgrant clawback capture failed", "grantee", pc.Grantee, "err", serr)
		}
	}

	for _, r := range ready {
		// The pool receives the sum, over the entries, of the grant's PROPORTIONAL share
		// of each entry's matured, re-slash-aware balance:
		//   floor(Amount * ResolvedBalance / EntryInit)
		// (see entryPoolCredit). With no same-block merge EntryInit == Amount and this is
		// exactly the entry's matured Balance (proven cycle-6); with a merge it is the
		// grant's fair fraction, leaving the grantee's own same-block return intact.
		sweep := math.ZeroInt()
		for _, e := range r.pc.Entries {
			sweep = sweep.Add(entryPoolCredit(e))
		}
		// HIGH-D safety belt: NEVER credit the pool more than the recorded LOCKED
		// principal for this clawback (SweepAmount), regardless of which path wrote
		// the pending record. Every writer (gov + admin/precompile, both surgical
		// since cycle 7) produces pure-locked entries with Σ Amount <= SweepAmount,
		// so this cap is a no-op there; it exists so no future (or legacy) pending
		// whose entries commingle the grantee's own funds can ever sweep beyond the
		// locked principal. SweepAmount is always set positive by both writers; a
		// non-positive parse (impossible for module-written records) skips the cap
		// rather than zeroing the sweep (capping to 0 would ORPHAN principal).
		if lockedCap := parseIntOrZero(r.pc.SweepAmount); lockedCap.IsPositive() && sweep.GT(lockedCap) {
			sweep = lockedCap
		}
		// Defensive floor at the live balance so the send can never fail. x/staking
		// returned the principal THIS block (ordered before us), so balance >= sweep
		// always holds and this never binds; it is NOT a (balance - gas) cap and can
		// never seize the grantee's rewards / own liquid (sweep is the entry's own
		// matured value, which the returned coins fully cover).
		if bal := k.bankKeeper.GetBalance(ctx, r.addr, bondDenom).Amount; sweep.GT(bal) {
			sweep = bal
		}

		if sweep.IsPositive() {
			// The returned principal may sit in EITHER bucket — spendable (after the
			// free-first TrackUndelegation of a commingled reclaim) or still locked (a
			// pure-vesting return). Unlock the PLVA so either is movable, then send.
			if _, isPLVA := k.accountKeeper.GetAccount(ctx, r.addr).(*vestingtypes.PermanentLockedAccount); isPLVA {
				k.unlockAccount(ctx, r.addr)
			}
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

// entryPoolCredit returns the re-slash-aware, MERGE-safe amount to credit the pool for
// one matured entry: the grant's PROPORTIONAL share of the entry's current (matured)
// balance,
//
//	credit = floor(grantRecorded * currentBalance / entryInit)
//
// where grantRecorded (Amount) is the tokens THIS clawback undelegated for the grant,
// entryInit (EntryInit) is the entry's InitialBalance captured at the first EndBlock
// (grantRecorded + any same-block grantee self-undelegation that x/staking's AddEntry
// merged in), and currentBalance (ResolvedBalance) is the entry's live Balance after
// any in-window re-slash. Because x/staking slashes proportional to InitialBalance, the
// merged entry's grant and grantee portions shrink by the SAME factor, so scaling
// grantRecorded by currentBalance/entryInit yields the grant's fair post-slash value.
//
// Integer math only (sdkmath.Int), MUL BEFORE DIV, rounding DOWN — so the pool is
// never over-credited and the grantee always keeps currentBalance - credit of their own
// same-block return. Bounds (grantRecorded <= entryInit and currentBalance <= entryInit)
// give 0 <= credit <= min(grantRecorded, currentBalance).
//
// Degenerate / backward-compatible fallbacks, both reducing to the proven cycle-6 path:
//   - No capture ever ran (ResolvedBalance == "": the entry matured with no intervening
//     pre-maturity EndBlock) => credit = grantRecorded (no re-slash could have shrunk it).
//   - A capture ran but EntryInit is unset (legacy pre-merge-fix record) => credit =
//     min(currentBalance, grantRecorded) (the cycle-6 amount; new records always set
//     EntryInit, and with NO merge EntryInit == grantRecorded => credit == currentBalance).
//
// A fully-slashed entry (currentBalance == 0 after a capture) credits 0.
func entryPoolCredit(e types.PendingClawbackEntry) math.Int {
	grantRecorded := parseIntOrZero(e.Amount)

	// No live capture ever ran: ResolvedBalance is the empty string (distinct from a
	// captured "0", which means the entry was fully slashed and must credit 0).
	if e.ResolvedBalance == "" {
		return grantRecorded
	}
	currentBalance := parseIntOrZero(e.ResolvedBalance)

	// Legacy record with a capture but no merged-init to prorate against: fall back to
	// the proven cycle-6 credit.
	if e.EntryInit == "" {
		return math.MinInt(currentBalance, grantRecorded)
	}
	entryInit := parseIntOrZero(e.EntryInit)
	if !entryInit.IsPositive() {
		// Defensive: never divide by zero. A non-positive init with a live capture is
		// impossible (init >= balance >= 0 and init was stored only when positive), but
		// crediting 0 here can only ever UNDER-credit, never seize the grantee.
		return math.ZeroInt()
	}
	// Grant's proportional share: mul before div, truncating (round DOWN).
	return grantRecorded.Mul(currentBalance).Quo(entryInit)
}

// liveClawbackEntry reads the grantee's live x/staking UnbondingDelegation at the
// entry's validator and returns the current Balance AND slash-invariant InitialBalance
// of the SPECIFIC UnbondingDelegationEntry the clawback created — matched by
// CreationHeight AND full-nanosecond CompletionTime (which together uniquely identify it
// among the grantee's unbonding entries). InitialBalance already reflects any same-block
// merge (x/staking's AddEntry sums it), so it is the denominator for the grant's
// proportional share. Returns (0,0,false) when the unbonding delegation or a matching
// entry is absent (already completed, fully removed, or a pre-HIGH-C record with no
// CreationHeight), so the caller keeps the last captured values. Never errors — a
// bookkeeping read must not halt EndBlock.
func (k Keeper) liveClawbackEntry(ctx context.Context, grantee sdk.AccAddress, e types.PendingClawbackEntry) (balance, initialBalance math.Int, ok bool) {
	valBz, err := k.stakingKeeper.ValidatorAddressCodec().StringToBytes(e.Validator)
	if err != nil {
		return math.ZeroInt(), math.ZeroInt(), false
	}
	ubd, err := k.stakingKeeper.GetUnbondingDelegation(ctx, grantee, sdk.ValAddress(valBz))
	if err != nil {
		return math.ZeroInt(), math.ZeroInt(), false
	}
	for _, ent := range ubd.Entries {
		if ent.CreationHeight == e.CreationHeight && ent.CompletionTime.UnixNano() == e.CompletionNanos {
			return ent.Balance, ent.InitialBalance, true
		}
	}
	return math.ZeroInt(), math.ZeroInt(), false
}

// entryCompletion returns a pending entry's unbonding maturity at the finest
// precision available: the FULL-nanosecond CompletionNanos when present, else the
// legacy whole-second CompletionUnix (backward-compatible with pre-fix records).
func entryCompletion(e types.PendingClawbackEntry) time.Time {
	if e.CompletionNanos != 0 {
		return time.Unix(0, e.CompletionNanos)
	}
	return time.Unix(e.CompletionUnix, 0)
}

// parseIntOrZero parses an aLIMO integer string, returning zero for "", "0", a
// malformed value, or any non-positive amount.
func parseIntOrZero(s string) math.Int {
	if v, ok := math.NewIntFromString(s); ok && v.IsPositive() {
		return v
	}
	return math.ZeroInt()
}
