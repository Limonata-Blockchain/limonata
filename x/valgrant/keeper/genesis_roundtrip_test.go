package keeper

import (
	"testing"

	"github.com/cosmos/evm/x/valgrant/types"
)

// A governance clawback whose principal is still unbonding exists ONLY under
// prefix 0x03 until the EndBlock sweep completes it - up to a full unbonding
// period later. Dropping it from an export loses foundation money: the maturing
// coins land back in the grantee's account and stay there.
func TestValgrantGenesis_PendingClawbackRoundTrip(t *testing.T) {
	f := newFixture(t)

	if err := f.k.SetParams(f.ctx, types.Params{Admin: "admin-a", FoundationValidators: []string{f.valStr}}); err != nil {
		t.Fatal(err)
	}
	pc := types.PendingClawback{
		Grantee: f.granteeStr,
		Entries: []types.PendingClawbackEntry{{
			Validator:       f.valStr,
			Amount:          "1000",
			CompletionUnix:  1_700_000_100,
			CompletionNanos: 1_700_000_100_000_000_000,
			CreationHeight:  100,
			ResolvedBalance: "950",
			EntryInit:       "1200",
		}},
		SweepAmount: "1000",
		InitiatedAt: 1_700_000_000,
	}
	if err := f.k.SetPendingClawback(f.ctx, pc); err != nil {
		t.Fatal(err)
	}
	snap := types.KPISnapshot{
		Height: 100, Unix: 1_700_000_000, ActiveValidators: 16,
		NakamotoCoefficient: 6, FoundationVPBps: 625, TopValidatorVPBps: 625, TotalPower: 1600,
	}
	if err := f.k.SetKPISnapshot(f.ctx, snap); err != nil {
		t.Fatal(err)
	}

	exported := f.k.ExportGenesis(f.ctx)
	if len(exported.PendingClawbacks) != 1 {
		t.Fatalf("pending_clawbacks = %+v, want 1 entry", exported.PendingClawbacks)
	}
	if exported.KPISnapshot == nil {
		t.Fatal("kpi_snapshot must be exported when one is recorded")
	}
	if err := exported.Validate(); err != nil {
		t.Fatalf("an export must validate: %v", err)
	}

	// Re-import into a virgin keeper. Grants are empty here on purpose: this test
	// isolates the two prefixes that were silently dropped, without re-running the
	// seat-provisioning path (covered by genesis_seats_test.go).
	f2 := newFixture(t)
	if err := f2.k.InitGenesis(f2.ctx, *exported); err != nil {
		t.Fatalf("import failed: %v", err)
	}
	var got []types.PendingClawback
	f2.k.IteratePendingClawbacks(f2.ctx, func(p types.PendingClawback) { got = append(got, p) })
	if len(got) != 1 {
		t.Fatalf("pending clawback was LOST by the round trip: %+v", got)
	}
	e := got[0].Entries
	if got[0].Grantee != pc.Grantee || got[0].SweepAmount != "1000" || len(e) != 1 {
		t.Fatalf("pending clawback did not round-trip: %+v", got[0])
	}
	if e[0].Amount != "1000" || e[0].ResolvedBalance != "950" || e[0].EntryInit != "1200" ||
		e[0].CompletionNanos != 1_700_000_100_000_000_000 || e[0].CreationHeight != 100 {
		// These four fields are what the deferred sweep computes the payout from
		// (HIGH-B / HIGH-C / HIGH-C-MERGE); losing any of them changes the amount.
		t.Fatalf("sweep-critical fields did not round-trip: %+v", e[0])
	}
	restored, ok := f2.k.GetKPISnapshot(f2.ctx)
	if !ok || restored != snap {
		t.Fatalf("kpi snapshot did not round-trip: %+v (ok=%v)", restored, ok)
	}
	if p := f2.k.GetParams(f2.ctx); p.Admin != "admin-a" || len(p.FoundationValidators) != 1 {
		t.Fatalf("params did not round-trip: %+v", p)
	}
}

func TestValgrantGenesis_EmptyStaysEmpty(t *testing.T) {
	f := newFixture(t)
	if err := f.k.SetParams(f.ctx, types.DefaultParams()); err != nil {
		t.Fatal(err)
	}
	gs := f.k.ExportGenesis(f.ctx)
	if len(gs.PendingClawbacks) != 0 || gs.KPISnapshot != nil {
		t.Fatalf("a chain with no clawback and no snapshot must export neither, got %+v", gs)
	}
}

func TestValgrantGenesis_RejectsBadPendingClawback(t *testing.T) {
	for name, gs := range map[string]types.GenesisState{
		"no grantee": {Params: types.DefaultParams(), PendingClawbacks: []types.PendingClawback{{SweepAmount: "1"}}},
		"duplicate": {Params: types.DefaultParams(), PendingClawbacks: []types.PendingClawback{
			{Grantee: "g"}, {Grantee: "g"},
		}},
		"bad entry amount": {Params: types.DefaultParams(), PendingClawbacks: []types.PendingClawback{
			{Grantee: "g", Entries: []types.PendingClawbackEntry{{Validator: "v", Amount: "nope"}}},
		}},
	} {
		if err := gs.Validate(); err == nil {
			t.Fatalf("%s: must be rejected", name)
		}
	}
}
