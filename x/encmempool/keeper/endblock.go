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
// Each block it (1) FINALIZES the in-flight round once its complaint window closes,
// installing the aggregate key as the active encmempool ThresholdPub, and (2) opens
// a NEW epoch when the DKG first starts or when the member set changes (the
// Shutter/Penumbra "just re-run, no resharing" trigger).
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

	// 1. Finalize the in-flight round at its complaint deadline.
	if cur > 0 {
		if round, ok := k.GetDkgRound(ctx, cur); ok && round.Status == types.DkgStatusOpen && h >= round.ComplaintDeadline {
			k.finalizeRound(ctx, round)
		}
	}

	// 2. Decide whether to open a new epoch.
	active := k.ActiveMembers(ctx, p)
	if len(active) == 0 {
		return // no eligible members (no declared member is bonded) — nothing to run
	}
	hash := MembersHash(active)

	var lastRound types.DkgRound
	haveLast := false
	if cur > 0 {
		lastRound, haveLast = k.GetDkgRound(ctx, cur)
	}
	// Never open while a round is still in-flight.
	if haveLast && lastRound.Status == types.DkgStatusOpen {
		return
	}

	needNew := false
	switch {
	case cur == 0:
		needNew = true // first run
	case haveLast && !bytes.Equal(lastRound.MembersHash, hash):
		needNew = true // membership changed -> re-run (new independent msk')
	}
	if needNew {
		k.openRound(ctx, cur+1, active, hash, h, p)
	}
}

// openRound writes a fresh DkgRound and emits dkg_round_opened. The full round
// (members + their enc keys + threshold) is emitted as round_json so a member's
// node can auto-deal off block events without a custom query endpoint.
func (k Keeper) openRound(ctx sdk.Context, epoch uint64, members []types.RoundMember, hash []byte, h uint64, p types.Params) {
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
	}
	_ = k.SetDkgRound(ctx, round)
	k.SetCurrentEpoch(ctx, epoch)

	roundJSON, _ := json.Marshal(round)
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_dkg_round_opened",
		sdk.NewAttribute("epoch", u64str(epoch)),
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
