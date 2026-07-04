package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// NOTE: the two former PROBE-B tests here (TestProbe_DeferScanIsOBacklogNotCapped /
// TestProbe_DeferFirstBlockScansWholeBacklog) demonstrated the DROP->DEFER-induced
// O(backlog) per-block SCAN. That HIGH is now CLOSED (bounded scan + admission + fairness),
// and the fix is locked by TestCollectMaturedUpTo_BoundedWindow, TestDecryptFloodBoundedAndFair,
// and TestSubmitEncrypted_AdmissionCeilings (admission_regr_test.go), so the demonstration
// probes were removed rather than left asserting a now-false finding.

// ---------------------------------------------------------------------------
// PROBE A: flap-dampener liveness. A GENUINE settled member change that happens to arrive
// WITHIN gap blocks of the last (attacker-induced) rekey is DELAYED, but must (1) never be
// permanently blocked and (2) rekey the instant the gap elapses. Confirms bounded delay,
// no liveness halt.
// ---------------------------------------------------------------------------
func TestProbe_SettledChangeWithinGapIsDelayedNotBlocked(t *testing.T) {
	const gap = 20
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")

	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 1, DkgComplaintWindow: 1, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: 2, DkgMinRekeyGap: gap,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	markActive := func(epoch uint64) {
		r, _ := k.GetDkgRound(ctx, epoch)
		r.Status = types.DkgStatusActive
		_ = k.SetDkgRound(ctx, r)
	}
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	markActive(1)

	// A first member change at height 10 rekeys immediately (last==0 => not dampened).
	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager()))
	if k.GetCurrentEpoch(ctx) != 2 {
		t.Fatalf("first change should open epoch 2, got %d", k.GetCurrentEpoch(ctx))
	}
	markActive(2)
	last := k.GetLastRekeyHeight(ctx)
	if last != 10 {
		t.Fatalf("last rekey height should be 10, got %d", last)
	}

	// GENUINE settled change to {A,C,D} arrives at height 11 (within gap of last=10).
	p.DkgMembers = declaredFrom([]member{A, C, D})
	_ = k.SetParams(ctx, p)

	// Every block from 11 up to (but not including) 10+gap must HOLD (dampened): no rekey.
	firstRekeyAt := int64(0)
	for h := int64(11); h <= int64(10+gap)+5; h++ {
		before := k.GetCurrentEpoch(ctx)
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
		if k.GetCurrentEpoch(ctx) != before {
			firstRekeyAt = h
			markActive(k.GetCurrentEpoch(ctx))
			break
		}
	}
	if firstRekeyAt == 0 {
		t.Fatal("LIVENESS: settled change never rekeyed — dampener permanently blocked it")
	}
	if firstRekeyAt < int64(10+gap) {
		t.Fatalf("dampener released early at %d (want >= %d)", firstRekeyAt, 10+gap)
	}
	// Delay must be BOUNDED by ~gap (released the instant the gap elapsed), not longer.
	if firstRekeyAt > int64(10+gap) {
		t.Fatalf("settled change delayed BEYOND the gap: rekeyed at %d, gap boundary %d", firstRekeyAt, 10+gap)
	}
	t.Logf("settled change held then rekeyed at height %d (gap boundary %d) — bounded delay, no halt", firstRekeyAt, 10+gap)
}

// TestProbe_DampenerDoesNotFreezeFailedRetry locks in the LOW fix: while a member change is
// being DAMPENED, a FAILED round must STILL auto-retry (self-heal is never frozen). The
// dampener coalesces only the genuine member CHANGE; the failed round retries against its OLD
// member set (so MembersHash stays stable and the flap cannot reset the backoff). Pre-fix the
// member_change arm returned early during dampening, freezing the retry for the whole gap.
func TestProbe_DampenerDoesNotFreezeFailedRetry(t *testing.T) {
	const gap = 30
	A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")

	k, ctx := newKeeper(t, 1)
	p := types.Params{
		EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
		DkgDealWindow: 1, DkgComplaintWindow: 1, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
		DkgThreshold: 2, DkgMinRekeyGap: gap,
		DkgMembers: declaredFrom([]member{A, B, C}),
	}
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Open epoch 1 and drive a member change at height 50 to set LastRekeyHeight and open
	// a fresh round, which we then FAIL (no deals -> finalize marks it Failed).
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	r1, _ := k.GetDkgRound(ctx, 1)
	r1.Status = types.DkgStatusActive
	_ = k.SetDkgRound(ctx, r1) // force-activate epoch 1 so member change drives the next open

	p.DkgMembers = declaredFrom([]member{A, B, D})
	_ = k.SetParams(ctx, p)
	k.EndBlockDKG(ctx.WithBlockHeight(50).WithEventManager(sdk.NewEventManager())) // rekey -> epoch 2, last=50
	if k.GetCurrentEpoch(ctx) != 2 || k.GetLastRekeyHeight(ctx) != 50 {
		t.Fatalf("setup: epoch=%d last=%d", k.GetCurrentEpoch(ctx), k.GetLastRekeyHeight(ctx))
	}
	// Let epoch 2 FAIL: no dealings, finalize at its complaint deadline.
	r2, _ := k.GetDkgRound(ctx, 2)
	k.EndBlockDKG(ctx.WithBlockHeight(int64(r2.ComplaintDeadline)).WithEventManager(sdk.NewEventManager()))
	r2, _ = k.GetDkgRound(ctx, 2)
	if r2.Status != types.DkgStatusFailed {
		t.Fatalf("epoch 2 should be Failed, got %q", r2.Status)
	}

	// A NEW member change (to {A,C,D}) arrives within the gap of last=50. The member_change arm
	// is dampened — but the FAILED round must still be retried (against the OLD set), NOT frozen.
	p.DkgMembers = declaredFrom([]member{A, C, D})
	_ = k.SetParams(ctx, p)
	retriedDuringGapAt := int64(0)
	for h := int64(r2.ComplaintDeadline) + 1; h < int64(50+gap); h++ {
		before := k.GetCurrentEpoch(ctx)
		k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
		if k.GetCurrentEpoch(ctx) != before {
			retriedDuringGapAt = h
			break
		}
	}
	if retriedDuringGapAt == 0 {
		t.Fatal("REGRESSION: failed round FROZEN during dampening — self-heal must not be blocked by the flap dampener")
	}
	if retriedDuringGapAt >= int64(50+gap) {
		t.Fatalf("retry only happened at/after the gap boundary (%d); it must fire DURING the gap", retriedDuringGapAt)
	}
	// The retry must be against the OLD member set {op1,op2,op4} (change coalesced), so the flap
	// cannot reset the backoff via a member_change re-genesis. The pending change swaps op2->op3.
	rr, _ := k.GetDkgRound(ctx, k.GetCurrentEpoch(ctx))
	ops := map[string]bool{}
	for _, m := range rr.Members {
		ops[m.OperatorAddr] = true
	}
	if !ops["op2"] || ops["op3"] {
		t.Fatalf("dampened retry applied the pending member change (want OLD set incl op2, excl op3; got %v)", ops)
	}
	if rr.Attempt < 2 {
		t.Fatalf("dampened retry should carry an incremented attempt (>=2), got %d", rr.Attempt)
	}
	t.Logf("failed round retried DURING dampening at height %d (attempt %d, old set) — not frozen", retriedDuringGapAt, rr.Attempt)
}

// ---------------------------------------------------------------------------
// PROBE: determinism of the new GC + flap logic. Two independent keepers fed the identical
// committed inputs (member flap + GC-inducing rekeys) must reach byte-identical retained
// state (round count, key count, active/current epoch, last-rekey height).
// ---------------------------------------------------------------------------
func TestProbe_GCAndFlapDeterministicAcrossNodes(t *testing.T) {
	drive := func() (rounds, keys int, active, current, last uint64) {
		A, B, C, D := newMember("op1", "acc1"), newMember("op2", "acc2"), newMember("op3", "acc3"), newMember("op4", "acc4")
		all := []member{A, B, C, D}
		setA := []member{A, B, C}
		setB := []member{A, B, D}
		k, ctx := newKeeper(t, 1)
		ms := keeper.NewMsgServerImpl(k)
		p := types.Params{
			EncEnabled: true, DkgEnabled: true, DkgStartHeight: 1,
			DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 1, DkgMaxAttempts: 8,
			DkgThreshold: 2, DkgMinRekeyGap: 3,
			DkgMembers: declaredFrom(setA),
		}
		_ = k.SetParams(ctx, p)
		k.EndBlockDKG(ctx.WithBlockHeight(1))
		dealAllMembers(t, k, ms, ctx.WithBlockHeight(2), all, 1, 2)
		k.EndBlockDKG(ctx.WithBlockHeight(5).WithEventManager(sdk.NewEventManager()))
		h := int64(6)
		for epoch := uint64(2); epoch <= 5; epoch++ {
			if epoch%2 == 0 {
				p.DkgMembers = declaredFrom(setB)
			} else {
				p.DkgMembers = declaredFrom(setA)
			}
			_ = k.SetParams(ctx, p)
			k.EndBlockDKG(ctx.WithBlockHeight(h).WithEventManager(sdk.NewEventManager()))
			if k.GetCurrentEpoch(ctx) == epoch {
				dealAllMembers(t, k, ms, ctx.WithBlockHeight(h+1), all, epoch, 2)
				k.EndBlockDKG(ctx.WithBlockHeight(h + 4).WithEventManager(sdk.NewEventManager()))
			}
			h += 10 // beyond gap so each settled change rekeys
		}
		return k.CountDkgRounds(ctx), k.CountActiveKeys(ctx),
			k.GetActiveEpoch(ctx), k.GetCurrentEpoch(ctx), k.GetLastRekeyHeight(ctx)
	}
	r1, k1, a1, c1, l1 := drive()
	r2, k2, a2, c2, l2 := drive()
	if r1 != r2 || k1 != k2 || a1 != a2 || c1 != c2 || l1 != l2 {
		t.Fatalf("NON-DETERMINISTIC GC/flap: node1{rounds=%d keys=%d active=%d cur=%d last=%d} != node2{rounds=%d keys=%d active=%d cur=%d last=%d}",
			r1, k1, a1, c1, l1, r2, k2, a2, c2, l2)
	}
	t.Logf("deterministic: rounds=%d keys=%d active=%d cur=%d last=%d", r1, k1, a1, c1, l1)
}

// TestProbe_ValidateWindowsDoesNotRejectRealisticConfigs: the new param bounds must accept
// every realistic DKG config (the fix must not brick a valid deployment).
func TestProbe_ValidateWindowsDoesNotRejectRealisticConfigs(t *testing.T) {
	good := []types.Params{
		types.DefaultParams(),
		{DkgDealWindow: 1, DkgComplaintWindow: 1, DkgRetryBackoff: 1, DkgMinRekeyGap: 0, DkgMaxAttempts: 0},
		{DkgDealWindow: 20, DkgComplaintWindow: 10, DkgRetryBackoff: 5, DkgMinRekeyGap: 30, DkgMaxAttempts: 8},
		{DkgDealWindow: 100, DkgComplaintWindow: 50, DkgRetryBackoff: 25, DkgMinRekeyGap: 300, DkgMaxAttempts: 100},
	}
	for i, p := range good {
		if err := p.ValidateDkgWindows(); err != nil {
			t.Fatalf("realistic config #%d rejected: %v", i, err)
		}
	}
	// And a zero window IS rejected (intended tightening).
	bad := types.Params{DkgDealWindow: 0, DkgComplaintWindow: 10, DkgRetryBackoff: 5}
	if err := bad.ValidateDkgWindows(); err == nil {
		t.Fatal("expected zero deal window to be rejected")
	}
}
