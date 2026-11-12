package keeper

import (
	"testing"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/contest/types"
)

func realStoreKeeper(t *testing.T) (Keeper, sdk.Context) {
	t.Helper()
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_contest")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)
	return NewKeeper(runtime.NewKVStoreService(key)), testCtx.Ctx
}

// The leaderboard IS the payout map. Before this, ExportGenesis carried params +
// showcase only: a migration would have restarted the contest with every score at
// zero and the snapshot latch reopened.
func TestContestGenesis_RoundTrip(t *testing.T) {
	k, ctx := realStoreKeeper(t)

	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
		t.Fatal(err)
	}
	if err := k.SetShowcase(ctx, types.ShowcaseApp{Address: "0x00000000000000000000000000000000deadbeef", VM: "evm", Approved: true}); err != nil {
		t.Fatal(err)
	}
	k.AddDevTxVolume(ctx, "dev-b", 7)
	k.AddDevTxVolume(ctx, "dev-a", 3)
	k.AddTesterPoints(ctx, "tester-b", 40)
	k.AddTesterPoints(ctx, "tester-a", 10)
	k.MarkActiveToday(ctx, 19000, "tester-a")
	k.MarkActiveToday(ctx, 19001, "tester-b")

	exported := k.ExportGenesis(ctx)
	if len(exported.DevStats) != 2 || len(exported.TesterPoints) != 2 || len(exported.DailyUAW) != 2 {
		t.Fatalf("export is incomplete: %+v", exported)
	}
	if exported.SnapshotDone {
		t.Fatal("snapshot_done must be false before the freeze")
	}
	// Deterministic order (sorted), not map order.
	if exported.DevStats[0].Dev != "dev-a" || exported.TesterPoints[0].Tester != "tester-a" {
		t.Fatalf("export is not sorted: %+v", exported)
	}
	if err := exported.Validate(); err != nil {
		t.Fatalf("an export must validate: %v", err)
	}

	k2, ctx2 := realStoreKeeper(t)
	if err := k2.InitGenesis(ctx2, *exported); err != nil {
		t.Fatalf("import failed: %v", err)
	}
	got := k2.ExportGenesis(ctx2)
	if len(got.DevStats) != 2 || got.DevStats[0].Stats.TxVolume != 3 || got.DevStats[1].Stats.TxVolume != 7 {
		t.Fatalf("dev stats did not round-trip: %+v", got.DevStats)
	}
	if got.TesterPoints[0].Points != 10 || got.TesterPoints[1].Points != 40 {
		t.Fatalf("tester points did not round-trip: %+v", got.TesterPoints)
	}
	if got.DailyUAW[0].Day != 19000 || got.DailyUAW[0].Tester != "tester-a" ||
		got.DailyUAW[1].Day != 19001 || got.DailyUAW[1].Tester != "tester-b" {
		t.Fatalf("daily UAW markers did not round-trip: %+v", got.DailyUAW)
	}
	if len(got.Showcase) != 1 {
		t.Fatalf("showcase did not round-trip: %+v", got.Showcase)
	}
}

// The frozen latch must survive: an export that dropped it would silently
// UNFREEZE a finished contest and let points keep accruing past the deadline.
func TestContestGenesis_SnapshotLatchSurvives(t *testing.T) {
	k, ctx := realStoreKeeper(t)
	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
		t.Fatal(err)
	}
	k.setSnapshotDone(ctx)

	exported := k.ExportGenesis(ctx)
	if !exported.SnapshotDone {
		t.Fatal("snapshot_done must be exported once the leaderboard is frozen")
	}
	k2, ctx2 := realStoreKeeper(t)
	if err := k2.InitGenesis(ctx2, *exported); err != nil {
		t.Fatal(err)
	}
	if !k2.SnapshotDone(ctx2) {
		t.Fatal("the contest was silently UNFROZEN by the round trip")
	}
}

func TestContestGenesis_EmptyStaysEmpty(t *testing.T) {
	k, ctx := realStoreKeeper(t)
	if err := k.InitGenesis(ctx, *types.DefaultGenesisState()); err != nil {
		t.Fatal(err)
	}
	gs := k.ExportGenesis(ctx)
	if len(gs.DevStats) != 0 || len(gs.TesterPoints) != 0 || len(gs.DailyUAW) != 0 || gs.SnapshotDone {
		t.Fatalf("fresh genesis must export no leaderboard state, got %+v", gs)
	}
}

func TestContestGenesis_RejectsBadEntries(t *testing.T) {
	base := func() types.GenesisState { return types.GenesisState{Params: types.DefaultParams()} }
	cases := map[string]types.GenesisState{}
	g := base()
	g.DevStats = []types.DevStatsEntry{{Stats: types.DevStats{}}}
	cases["dev without name"] = g
	g = base()
	g.DevStats = []types.DevStatsEntry{{Dev: "a"}, {Dev: "a"}}
	cases["duplicate dev"] = g
	g = base()
	g.DevStats = []types.DevStatsEntry{{Dev: "a", Stats: types.DevStats{GasSponsored: "nope"}}}
	cases["bad gas_sponsored"] = g
	g = base()
	g.TesterPoints = []types.TesterPointsEntry{{Points: 1}}
	cases["tester without name"] = g
	g = base()
	g.TesterPoints = []types.TesterPointsEntry{{Tester: "t"}, {Tester: "t"}}
	cases["duplicate tester"] = g
	g = base()
	g.DailyUAW = []types.DailyUAWEntry{{Day: 1}}
	cases["uaw without tester"] = g
	g = base()
	g.DailyUAW = []types.DailyUAWEntry{{Day: 1, Tester: "t"}, {Day: 1, Tester: "t"}}
	cases["duplicate uaw"] = g

	for name, gs := range cases {
		if err := gs.Validate(); err == nil {
			t.Fatalf("%s: must be rejected", name)
		}
	}
}
