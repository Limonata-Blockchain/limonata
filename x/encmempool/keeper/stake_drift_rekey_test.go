// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper_test

import (
	"testing"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-5 item 1: OPTIONAL cadence / stake-drift rekey.
//
// MembersHash covers OPERATORS only, so a pure re-delegation (same operator set,
// shifted weights) does NOT re-key: the frozen round-open stake snapshot drifts from
// live stake, weakening the snapshot-proven safety/liveness coupling. Two OPTIONAL,
// DEFAULT-OFF triggers bound that drift by re-genesis-ing the SAME committee against a
// fresh snapshot. These tests prove: (a) DEFAULT-OFF => byte-identical (a big re-
// delegation triggers NO rekey), (b) the epoch-cadence trigger, (c) the stake-drift-bps
// trigger (both directions of the threshold), and (d) the DkgMinRekeyGap flap-dampener
// still bounds the rekey rate.
// ============================================================================

// activeRoundFixture stands up an Active epoch-1 transparent round over the given validators,
// snapshotting their stake at round-open (height 1), so the stake-drift triggers have an Active
// round with a frozen snapshot to compare live stake against.
func activeRoundFixture(t *testing.T, sk *mockStaking, members []member, p types.Params) (keeper.Keeper, sdk.Context) {
	t.Helper()
	k, ctx := newKeeperSK(t, 1, sk)
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if !k.RecordEncPubKey(ctx, m.op, m.pub, encPoP(m)) {
			t.Fatalf("failed to register enc key for %s", m.op)
		}
	}
	snap := k.ActiveMembers(ctx, p) // snapshot weights at round-open
	if len(snap) != len(members) {
		t.Fatalf("committee = %d members, want %d", len(snap), len(members))
	}
	allocated := keeper.AllocateEvalPoints(snap, p.EffectiveShareBudget(), 1)
	round := types.DkgRound{
		Epoch: 1, OpenHeight: 1, DealDeadline: 3, ComplaintDeadline: 5,
		Members: allocated, MembersHash: keeper.MembersHash(snap), Status: types.DkgStatusActive,
		Attempt: 1,
	}
	if err := k.SetDkgRound(ctx, round); err != nil {
		t.Fatal(err)
	}
	k.SetCurrentEpoch(ctx, 1)
	k.SetActiveEpoch(ctx, 1)
	k.SetLastRekeyHeight(ctx, 1)
	return k, ctx
}

// threeEqual builds 3 members each bonded with equal stake (100), all committee members.
func threeEqual() (*mockStaking, []member) {
	ms := []member{newMember("opA", ""), newMember("opB", ""), newMember("opC", "")}
	sk := &mockStaking{vals: []stakingtypes.Validator{
		bondedVal("opA", 100), bondedVal("opB", 100), bondedVal("opC", 100),
	}}
	return sk, ms
}

// reDelegate rewrites a validator's live bonded stake (models a re-delegation) WITHOUT changing
// the operator set, so MembersHash is unchanged and only the stake-drift path can react.
func reDelegate(sk *mockStaking, op string, tokens int64) {
	for i := range sk.vals {
		if sk.vals[i].OperatorAddress == op {
			sk.vals[i] = bondedVal(op, tokens)
			return
		}
	}
}

func rekeyedTo(k keeper.Keeper, ctx sdk.Context, epoch uint64) bool {
	return k.GetCurrentEpoch(ctx) == epoch
}

// TestStakeDrift_DefaultOffIsInert: with BOTH triggers 0 (the default), even a large re-
// delegation triggers NO rekey — dormant behavior is byte-identical to pre-cycle-5.
func TestStakeDrift_DefaultOffIsInert(t *testing.T) {
	sk, ms := threeEqual()
	p := transparentParams(2, 0) // DkgMaxEpochBlocks / DkgRekeyOnStakeDriftBps both 0
	if p.DkgMaxEpochBlocks != 0 || p.DkgRekeyOnStakeDriftBps != 0 {
		t.Fatal("fixture precondition: both drift triggers must default off")
	}
	k, ctx := activeRoundFixture(t, sk, ms, p)

	// A massive re-delegation: opA quintuples its stake.
	reDelegate(sk, "opA", 500)
	k.EndBlockDKG(ctx.WithBlockHeight(100_000))

	if !rekeyedTo(k, ctx, 1) {
		t.Fatal("DEFAULT-OFF violated: a re-delegation must NOT rekey when both triggers are 0")
	}
}

// TestStakeDrift_EpochCadence: DkgMaxEpochBlocks re-genesis-es the committee every N blocks even
// with an unchanged member set, and never before N blocks have elapsed since round-open.
func TestStakeDrift_EpochCadence(t *testing.T) {
	sk, ms := threeEqual()
	p := transparentParams(2, 0)
	p.DkgMaxEpochBlocks = 50 // cadence
	p.DkgMinRekeyGap = 0     // isolate the cadence
	k, ctx := activeRoundFixture(t, sk, ms, p)

	// Before the cadence elapses (open@1, N=50 => due at height 51): no rekey.
	k.EndBlockDKG(ctx.WithBlockHeight(40))
	if !rekeyedTo(k, ctx, 1) {
		t.Fatal("must NOT rekey before the cadence elapses")
	}
	// At/after the cadence boundary: rekey (same operators, fresh snapshot).
	bctx := ctx.WithBlockHeight(51).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(bctx)
	if !rekeyedTo(k, bctx, 2) {
		t.Fatal("cadence must open a fresh epoch at the boundary")
	}
	if !hasEvent(bctx, "encmempool_dkg_stake_drift_rekey") {
		t.Fatal("cadence rekey must emit encmempool_dkg_stake_drift_rekey")
	}
	if !rekeyReason(bctx, "stake_drift") {
		t.Fatal("cadence rekey must open the round with reason=stake_drift")
	}
	// The fresh round is Open over the SAME operators.
	r2, ok := k.GetDkgRound(bctx, 2)
	if !ok || r2.Status != types.DkgStatusOpen || len(r2.Members) != 3 {
		t.Fatalf("fresh round malformed: %+v", r2)
	}
}

// TestStakeDrift_BpsThreshold: DkgRekeyOnStakeDriftBps rekeys IFF the measured max-coalition
// drift reaches the threshold — no drift => no rekey; a re-delegation past the threshold => rekey;
// a threshold above the drift => no rekey.
func TestStakeDrift_BpsThreshold(t *testing.T) {
	// No drift (stake unchanged) must never rekey, even with a tiny threshold.
	{
		sk, ms := threeEqual()
		p := transparentParams(2, 0)
		p.DkgRekeyOnStakeDriftBps = 1 // 0.01%
		p.DkgMinRekeyGap = 0
		k, ctx := activeRoundFixture(t, sk, ms, p)
		k.EndBlockDKG(ctx.WithBlockHeight(1000))
		if !rekeyedTo(k, ctx, 1) {
			t.Fatal("zero drift must NOT rekey")
		}
	}
	// opA 100->200 (others 100) moves the max coalition fraction by ~1666 bps.
	// Threshold 500 bps: rekey. Threshold 2000 bps: no rekey.
	for _, tc := range []struct {
		name      string
		threshold uint64
		wantRekey bool
	}{
		{"below-threshold-fires", 500, true},
		{"above-threshold-holds", 2000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sk, ms := threeEqual()
			p := transparentParams(2, 0)
			p.DkgRekeyOnStakeDriftBps = tc.threshold
			p.DkgMinRekeyGap = 0
			k, ctx := activeRoundFixture(t, sk, ms, p)

			reDelegate(sk, "opA", 200) // ~1666 bps max-coalition drift
			bctx := ctx.WithBlockHeight(1000).WithEventManager(sdk.NewEventManager())
			k.EndBlockDKG(bctx)

			if got := rekeyedTo(k, bctx, 2); got != tc.wantRekey {
				t.Fatalf("drift threshold %d bps: rekeyed=%v, want %v", tc.threshold, got, tc.wantRekey)
			}
			if tc.wantRekey && !hasEvent(bctx, "encmempool_dkg_stake_drift_rekey") {
				t.Fatal("drift rekey must emit the monitor event")
			}
		})
	}
}

// TestStakeDrift_RespectsFlapGap: even when a trigger is due, the shared DkgMinRekeyGap
// flap-dampener holds the rekey until the gap since the last rekey has elapsed (no storm).
func TestStakeDrift_RespectsFlapGap(t *testing.T) {
	sk, ms := threeEqual()
	p := transparentParams(2, 0)
	p.DkgMaxEpochBlocks = 10   // cadence due early
	p.DkgMinRekeyGap = 100_000 // but the gap since last rekey (height 1) is huge
	k, ctx := activeRoundFixture(t, sk, ms, p)

	// Cadence elapsed (open@1, N=10 => due at 11) but within the flap gap of the last rekey (1):
	// held.
	k.EndBlockDKG(ctx.WithBlockHeight(11))
	if !rekeyedTo(k, ctx, 1) {
		t.Fatal("flap gap must hold the cadence rekey within DkgMinRekeyGap of the last rekey")
	}
	// Past the flap gap: the cadence rekey is applied.
	bctx := ctx.WithBlockHeight(100_002).WithEventManager(sdk.NewEventManager())
	k.EndBlockDKG(bctx)
	if !rekeyedTo(k, bctx, 2) {
		t.Fatal("once the flap gap elapses the cadence rekey must fire")
	}
}

// rekeyReason reports whether a dkg_round_opened event carried the given reason.
func rekeyReason(ctx sdk.Context, reason string) bool {
	for _, ev := range ctx.EventManager().Events() {
		if ev.Type != "encmempool_dkg_round_opened" {
			continue
		}
		for _, a := range ev.Attributes {
			if a.Key == "reason" && a.Value == reason {
				return true
			}
		}
	}
	return false
}
