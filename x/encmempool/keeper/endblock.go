package keeper

import (
	"bytes"
	"encoding/json"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/types"
)

// dkgBackoffCeilingBlocks is the hard ceiling (in blocks) on the auto-retry backoff.
// The backoff grows geometrically with the failed-attempt count so a SUSTAINED
// sub-quorum retries less and less often (bounded event/state churn), but it is capped
// here so the chain ALWAYS reopens within a bounded window and therefore converges the
// instant >= t members return — liveness is preserved, never traded away.
const dkgBackoffCeilingBlocks uint64 = 1000

// EndBlockDKG drives the on-chain validator DKG. It is fully deterministic (reads
// only committed state + the bonded validator set) so every node runs an identical
// state machine — the same consensus-safety property BeginBlock relies on.
//
// Each block it:
//  1. FINALIZES the in-flight round once its complaint window closes, installing the
//     aggregate key as the active encmempool key (Active) or marking the round Failed
//     when it could not (|QUAL| < t, i.e. a timed-out round with too few good deals);
//  2. AUTO-RETRIES a Failed round — after a small backoff it opens a FRESH round
//     (new epoch, reset deadlines, incremented attempt) so a single timing hiccup or
//     transient member outage can NEVER wedge the chain permanently keyless. As long
//     as >= t members are live the chain always converges to an active key with no
//     manual intervention;
//  3. opens a NEW epoch on first start or when the member set changes (the
//     Shutter/Penumbra "just re-run, no resharing" trigger).
//
// DETERMINISM: every branch below is a pure function of committed state (params,
// block height, the stored round, and the bonded validator set). There is no
// wall-clock, no map iteration that feeds an output, and no randomness — the dealing
// entropy lives entirely in the off-chain daemon; the chain only aggregates PUBLIC
// commitments. All nodes therefore compute an identical transition (or identical
// failed outcome), which is the #1 multi-node halt-safety requirement.
func (k Keeper) EndBlockDKG(ctx sdk.Context) {
	// PANIC-GUARD (defense-in-depth): EndBlock runs inside consensus; an unrecovered
	// panic here halts the whole chain. Every branch below is written not to panic (the
	// crypto aggregate handles malformed/empty inputs, and DkgDeal ingress validation
	// rejects malformed dealings before they reach finalize), but a last-resort recover
	// converts any unforeseen data-dependent panic into a contained, DETERMINISTIC event
	// (identical committed state => identical outcome on every node) instead of a halt.
	defer func() {
		if r := recover(); r != nil {
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_endblock_panic",
				sdk.NewAttribute("height", u64str(uint64(ctx.BlockHeight()))),
				sdk.NewAttribute("reason", fmt.Sprintf("%v", r)),
			))
		}
	}()

	p := k.GetParams(ctx)
	if !p.DkgEnabled {
		return
	}
	h := uint64(ctx.BlockHeight())
	if h < p.DkgStartHeight {
		return
	}

	cur := k.GetCurrentEpoch(ctx)
	var lastRound types.DkgRound
	haveLast := false
	if cur > 0 {
		lastRound, haveLast = k.GetDkgRound(ctx, cur)
	}

	// 1. Finalize the in-flight round once its complaint window closes. finalizeRound
	//    installs the aggregate key (=> Active) or records a Failed outcome that the
	//    auto-retry branch below will recover from.
	if haveLast && lastRound.Status == types.DkgStatusOpen && h >= lastRound.ComplaintDeadline {
		k.finalizeRound(ctx, lastRound)
		lastRound, haveLast = k.GetDkgRound(ctx, cur) // reload the post-finalize status
	}

	// Never disturb a round that is still genuinely in-flight (open, pre-deadline).
	if haveLast && lastRound.Status == types.DkgStatusOpen {
		return
	}

	// 2. Determine the current eligible member set. With no bonded/declared member we
	//    cannot run a round (nobody can deal), so hold — the daemon-less chain simply
	//    keeps its last active key, if any, and reopens when members return.
	active := k.ActiveMembers(ctx, p)
	if len(active) == 0 {
		return
	}
	hash := MembersHash(active)

	// 3. Decide whether / how to (re)open a round.
	switch {
	case cur == 0 || !haveLast:
		// First ever run (or a lost round record) — open epoch 1, attempt 1.
		k.openRound(ctx, cur+1, active, hash, h, p, 1, "start")

	case !bytes.Equal(lastRound.MembersHash, hash):
		// Membership changed -> fresh INDEPENDENT campaign (attempt resets to 1). This
		// takes priority over retry: a failed round whose set has since changed should
		// re-genesis against the new set, not retry the stale one.
		//
		// FLAP DAMPENING (HIGH-2 variant): a validator can induce a membership FLAP
		// (toggling its bond) to force endless re-genesis and RESET the retry backoff on
		// every churn. Rate-limit member-change re-genesis to at most once per
		// DkgMinRekeyGap blocks. A change arriving within the gap of the last rekey is
		// HELD (the current round keeps running); it is applied once the gap elapses if
		// the set is still different. A GENUINE settled change is NOT delayed: it follows
		// a stable period, so `h - last` already exceeds the gap and it rekeys immediately.
		last := k.GetLastRekeyHeight(ctx)
		if p.DkgMinRekeyGap > 0 && last != 0 && h < addSat(last, p.DkgMinRekeyGap) {
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_rekey_dampened",
				sdk.NewAttribute("height", u64str(h)),
				sdk.NewAttribute("last_rekey", u64str(last)),
				sdk.NewAttribute("min_gap", u64str(p.DkgMinRekeyGap)),
			))
			return
		}
		// GC the SUPERSEDED round. If it installed a key (Active) it is the STILL-SERVING
		// key until the new round finalizes, and in-flight ciphertexts stamped to it still
		// need its record to authorize shares — so keep it (only drop its now-dead dealing
		// bulk); it is reclaimed later by maybePruneEpoch once superseded AND drained. If it
		// never installed a key (Open/Failed) it is dead weight nothing references — delete
		// its record entirely, so a member-change FLAP that keeps interrupting rounds cannot
		// mint unbounded orphaned round records.
		if lastRound.Status == types.DkgStatusActive {
			k.purgeDealings(ctx, cur)
		} else {
			k.purgeFailedRound(ctx, cur)
		}
		k.SetLastRekeyHeight(ctx, h)
		k.openRound(ctx, cur+1, active, hash, h, p, 1, "member_change")

	case lastRound.Status == types.DkgStatusFailed:
		// AUTO-RETRY / SELF-HEAL. Wait out a backoff measured from the failed round's
		// complaint deadline, then open a fresh round carrying an incremented attempt
		// counter. The backoff grows with the attempt count and is CAPPED (HIGH-2), so
		// a long outage retries less often but never stops.
		if h < addSat(lastRound.ComplaintDeadline, retryBackoff(p, lastRound.Attempt)) {
			return
		}
		attempt := lastRound.Attempt + 1
		if p.DkgMaxAttempts > 0 && attempt > p.DkgMaxAttempts {
			// ALERT past the configured bound — but STILL reopen. Halting retries here
			// would brick the feature; instead operators get a signal while liveness
			// is preserved (the round converges the moment >= t members are back).
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_stalled",
				sdk.NewAttribute("epoch", u64str(cur+1)),
				sdk.NewAttribute("attempt", u64str(attempt)),
				sdk.NewAttribute("members", u64str(uint64(len(active)))),
			))
		}
		// HIGH-2: GC the failed round ENTIRELY (dealings, complaints, AND its DkgRound
		// record) before opening the retry, so sustained sub-quorum retries can never
		// grow retained round-record state without bound.
		k.purgeFailedRound(ctx, cur)
		k.openRound(ctx, cur+1, active, hash, h, p, attempt, "retry")

	// case Active with an unchanged member set: steady state — nothing to do.
	default:
	}
}

// openRound writes a fresh DkgRound and emits dkg_round_opened. The full round
// (members + their enc keys + threshold) is emitted as round_json so a member's node
// can auto-deal off block events without a custom query endpoint. attempt/reason are
// emitted so operators can watch convergence (start / member_change / retry).
func (k Keeper) openRound(ctx sdk.Context, epoch uint64, members []types.RoundMember, hash []byte, h uint64, p types.Params, attempt uint64, reason string) {
	t := roundThreshold(p, len(members))
	// MEDIUM FIXES: (1) the complaint window is FLOORED at >= 1 block so a dealing that
	// lands on the deal deadline still has at least one block in which it can be
	// complained about before finalize — a zero window would let a last-block bad dealer
	// finalize uncontestable. (2) All deadline arithmetic uses a SATURATING add so a
	// pathologically large governance-set window cannot overflow uint64 and wrap the
	// deadline below the current height (which would make deals/complaints instantly
	// "closed" and jam the round machine).
	dealDeadline := addSat(h, max64(p.DkgDealWindow, 1))
	round := types.DkgRound{
		Epoch:             epoch,
		OpenHeight:        h,
		DealDeadline:      dealDeadline,
		ComplaintDeadline: addSat(dealDeadline, max64(p.DkgComplaintWindow, 1)),
		Members:           members,
		Threshold:         t,
		MembersHash:       hash,
		Status:            types.DkgStatusOpen,
		Attempt:           attempt,
	}
	_ = k.SetDkgRound(ctx, round)
	k.SetCurrentEpoch(ctx, epoch)

	roundJSON, _ := json.Marshal(round)
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_dkg_round_opened",
		sdk.NewAttribute("epoch", u64str(epoch)),
		sdk.NewAttribute("attempt", u64str(attempt)),
		sdk.NewAttribute("reason", reason),
		sdk.NewAttribute("deal_deadline", u64str(round.DealDeadline)),
		sdk.NewAttribute("complaint_deadline", u64str(round.ComplaintDeadline)),
		sdk.NewAttribute("threshold", u64str(uint64(t))),
		sdk.NewAttribute("members", u64str(uint64(len(members)))),
		sdk.NewAttribute("round_json", string(roundJSON)),
	))
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// addSat is a saturating uint64 add: it returns a+b, or the uint64 max on overflow,
// so deadline arithmetic can never wrap past 2^64 and produce a deadline BELOW the
// current height (which would jam the deal/complaint windows).
func addSat(a, b uint64) uint64 {
	s := a + b
	if s < a {
		return ^uint64(0)
	}
	return s
}

// retryBackoff returns the blocks to wait after a FAILED round (of the given attempt)
// before auto-reopening. It grows geometrically with the failed attempt so a sustained
// sub-quorum outage backs off (bounded churn), but is CAPPED at dkgBackoffCeilingBlocks
// (never below the configured base) so the chain ALWAYS retries within a bounded window
// and converges the moment >= t members return. failedAttempt is the failed round's
// Attempt, so the FIRST retry (attempt 1) waits exactly the configured base backoff.
func retryBackoff(p types.Params, failedAttempt uint64) uint64 {
	base := max64(p.DkgRetryBackoff, 1)
	ceiling := max64(base, dkgBackoffCeilingBlocks)
	b := base
	for i := uint64(1); i < failedAttempt; i++ {
		next := b << 1
		if next < b || next >= ceiling { // overflow or reached the ceiling
			return ceiling
		}
		b = next
	}
	return b
}
