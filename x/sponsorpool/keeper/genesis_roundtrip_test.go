package keeper

import (
	"bytes"
	"testing"

	"cosmossdk.io/math"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/sponsorpool/types"
)

// realStoreKeeper builds a keeper over a REAL iavl-backed store: the export path
// walks prefixes 0x01/0x02 with a store iterator, which the package's in-memory
// test store does not implement.
func realStoreKeeper(t *testing.T) (Keeper, sdk.Context) {
	t.Helper()
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_sponsorpool")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)
	return NewKeeper(runtime.NewKVStoreService(key), nil, poolMod), testCtx.Ctx
}

// The escrow ledger IS the money map: without it a migration would leave every
// developer deposit stranded inside the shared gas pool.
func TestSponsorPoolGenesis_RoundTrip(t *testing.T) {
	k, ctx := realStoreKeeper(t)

	sponsorA := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20))
	sponsorB := sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20))
	contract1 := "0x00000000000000000000000000000000deadbeef"
	contract2 := "0x00000000000000000000000000000000cafebabe"

	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
		t.Fatal(err)
	}
	k.setInt(ctx, escrowKey(contract1), math.NewInt(900))
	k.setInt(ctx, escrowKey(contract2), math.NewInt(50))
	k.setInt(ctx, contribKey(sponsorA, contract1), math.NewInt(600))
	k.setInt(ctx, contribKey(sponsorB, contract1), math.NewInt(400))
	k.setInt(ctx, contribKey(sponsorA, contract2), math.NewInt(50))

	exported := k.ExportGenesis(ctx)
	if len(exported.Escrows) != 2 {
		t.Fatalf("escrows = %v, want 2 entries", exported.Escrows)
	}
	if len(exported.Contributions) != 3 {
		t.Fatalf("contributions = %v, want 3 entries", exported.Contributions)
	}
	if err := exported.Validate(); err != nil {
		// NOTE: contract1's contributions (600+400=1000) exceed its escrow (900)
		// because Reserve spends escrow WITHOUT touching contributions. That is a
		// normal live state and Validate must not reject it.
		t.Fatalf("an export of live state must validate: %v", err)
	}

	// Re-import into a virgin store and compare every value.
	k2, ctx2 := realStoreKeeper(t)
	if err := k2.InitGenesis(ctx2, *exported); err != nil {
		t.Fatalf("import failed: %v", err)
	}
	for _, c := range []struct {
		contract string
		want     int64
	}{{contract1, 900}, {contract2, 50}} {
		if got := k2.EscrowOf(ctx2, c.contract); !got.Equal(math.NewInt(c.want)) {
			t.Fatalf("escrow(%s) = %s, want %d", c.contract, got, c.want)
		}
	}
	for _, c := range []struct {
		sponsor  sdk.AccAddress
		contract string
		want     int64
	}{
		{sponsorA, contract1, 600},
		{sponsorB, contract1, 400},
		{sponsorA, contract2, 50},
	} {
		if got := k2.ContributionOf(ctx2, c.sponsor, c.contract); !got.Equal(math.NewInt(c.want)) {
			t.Fatalf("contribution(%s,%s) = %s, want %d", c.sponsor, c.contract, got, c.want)
		}
	}

	// A second export must be byte-identical to the first (determinism).
	again := k2.ExportGenesis(ctx2)
	if len(again.Escrows) != len(exported.Escrows) || len(again.Contributions) != len(exported.Contributions) {
		t.Fatalf("re-export shape differs: %+v vs %+v", again, exported)
	}
	for i := range again.Escrows {
		if again.Escrows[i] != exported.Escrows[i] {
			t.Fatalf("escrows[%d] differs: %+v vs %+v", i, again.Escrows[i], exported.Escrows[i])
		}
	}
	for i := range again.Contributions {
		if again.Contributions[i] != exported.Contributions[i] {
			t.Fatalf("contributions[%d] differs: %+v vs %+v", i, again.Contributions[i], exported.Contributions[i])
		}
	}
}

// A fresh genesis must stay exactly what it was: no empty lists forced into the file.
func TestSponsorPoolGenesis_EmptyStaysEmpty(t *testing.T) {
	k, ctx := realStoreKeeper(t)
	if err := k.InitGenesis(ctx, *types.DefaultGenesisState()); err != nil {
		t.Fatal(err)
	}
	gs := k.ExportGenesis(ctx)
	if len(gs.Escrows) != 0 || len(gs.Contributions) != 0 {
		t.Fatalf("fresh genesis must export no escrow state, got %+v", gs)
	}
}

func TestSponsorPoolGenesis_RejectsBadEntries(t *testing.T) {
	for name, gs := range map[string]types.GenesisState{
		"escrow without contract":  {Params: types.DefaultParams(), Escrows: []types.EscrowEntry{{Amount: "1"}}},
		"escrow bad amount":        {Params: types.DefaultParams(), Escrows: []types.EscrowEntry{{Contract: "0xabc", Amount: "x"}}},
		"escrow negative":          {Params: types.DefaultParams(), Escrows: []types.EscrowEntry{{Contract: "0xabc", Amount: "-1"}}},
		"duplicate escrow":         {Params: types.DefaultParams(), Escrows: []types.EscrowEntry{{Contract: "0xabc", Amount: "1"}, {Contract: "0xabc", Amount: "2"}}},
		"contribution no sponsor":  {Params: types.DefaultParams(), Contributions: []types.ContributionEntry{{Contract: "0xabc", Amount: "1"}}},
		"contribution no contract": {Params: types.DefaultParams(), Contributions: []types.ContributionEntry{{Sponsor: "cosmos1x", Amount: "1"}}},
		"duplicate contribution": {Params: types.DefaultParams(), Contributions: []types.ContributionEntry{
			{Sponsor: "cosmos1x", Contract: "0xabc", Amount: "1"},
			{Sponsor: "cosmos1x", Contract: "0xabc", Amount: "2"},
		}},
	} {
		if err := gs.Validate(); err == nil {
			t.Fatalf("%s: must be rejected", name)
		}
	}
}
