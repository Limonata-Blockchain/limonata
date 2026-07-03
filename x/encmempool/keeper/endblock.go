package keeper

import (
	"bytes"
	"encoding/json"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/types"
)

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
		k.openRound(ctx, cur+1, active, hash, h, p, 1, "member_change")

	case lastRound.Status == types.DkgStatusFailed:
		// AUTO-RETRY / SELF-HEAL. Wait out a backoff (>= 1 block, so we never spin
		// every block) measured from the failed round's complaint deadline, then open
		// a fresh round carrying an incremented attempt counter.
		if h < lastRound.ComplaintDeadline+max64(p.DkgRetryBackoff, 1) {
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
		// The failed epoch's dealings/complaints are dead weight — GC them so an
		// extended outage cannot grow state without bound across many retries.
		k.purgeRoundData(ctx, cur)
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
	round := types.DkgRound{
		Epoch:             epoch,
		OpenHeight:        h,
		DealDeadline:      h + max64(p.DkgDealWindow, 1),
		ComplaintDeadline: h + max64(p.DkgDealWindow, 1) + p.DkgComplaintWindow,
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
