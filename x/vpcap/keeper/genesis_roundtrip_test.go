package keeper

import (
	"bytes"
	"encoding/hex"
	"testing"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/vpcap/types"
)

// realStoreKeeper builds a keeper over a REAL iavl-backed store: the export path
// walks prefix 0x02 with a store iterator.
func realStoreKeeper(t *testing.T) (Keeper, sdk.Context) {
	t.Helper()
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_vpcap")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)
	return NewKeeper(runtime.NewKVStoreService(key), nil), testCtx.Ctx
}

// Losing the last-sent map means losing the diff base vpcap needs to zero out
// departed validators - they would silently stay in the CometBFT set.
func TestVpcapGenesis_RoundTrip(t *testing.T) {
	k, ctx := realStoreKeeper(t)

	consA := bytes.Repeat([]byte{0xAA}, 20)
	consB := bytes.Repeat([]byte{0xBB}, 20)

	p := types.DefaultParams()
	p.Enabled = true
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := k.SetLastSent(ctx, consA, LastSent{PubKey: []byte{1, 2, 3}, Power: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := k.SetLastSent(ctx, consB, LastSent{PubKey: []byte{4, 5}, Power: 0}); err != nil {
		t.Fatal(err)
	}

	exported := k.ExportGenesis(ctx)
	if len(exported.LastSent) != 2 {
		t.Fatalf("last_sent = %v, want 2 entries", exported.LastSent)
	}
	if err := exported.Validate(); err != nil {
		t.Fatalf("an export must validate: %v", err)
	}
	// Sorted by cons_addr: aa... before bb...
	if exported.LastSent[0].ConsAddr != hex.EncodeToString(consA) {
		t.Fatalf("export is not sorted: %+v", exported.LastSent)
	}

	k2, ctx2 := realStoreKeeper(t)
	if err := k2.InitGenesis(ctx2, *exported); err != nil {
		t.Fatalf("import failed: %v", err)
	}
	restored, err := k2.GetAllLastSent(ctx2)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 2 {
		t.Fatalf("restored %d entries, want 2", len(restored))
	}
	if got := restored[string(consA)]; got.Power != 1000 || !bytes.Equal(got.PubKey, []byte{1, 2, 3}) {
		t.Fatalf("consA restored as %+v", got)
	}
	// The Power-0 record matters MOST: it is how a departed validator stays zeroed.
	if got := restored[string(consB)]; got.Power != 0 || !bytes.Equal(got.PubKey, []byte{4, 5}) {
		t.Fatalf("consB restored as %+v", got)
	}
	if !k2.GetParams(ctx2).Enabled {
		t.Fatal("params did not survive the round trip")
	}
}

func TestVpcapGenesis_EmptyStaysEmpty(t *testing.T) {
	k, ctx := realStoreKeeper(t)
	if err := k.InitGenesis(ctx, *types.DefaultGenesisState()); err != nil {
		t.Fatal(err)
	}
	if gs := k.ExportGenesis(ctx); len(gs.LastSent) != 0 {
		t.Fatalf("fresh genesis must export no last_sent, got %+v", gs.LastSent)
	}
}

func TestVpcapGenesis_RejectsBadLastSent(t *testing.T) {
	for name, gs := range map[string]types.GenesisState{
		"no cons_addr": {Params: types.DefaultParams(), LastSent: []types.LastSentEntry{{Power: 1}}},
		"not hex":      {Params: types.DefaultParams(), LastSent: []types.LastSentEntry{{ConsAddr: "zz", Power: 1}}},
		"negative":     {Params: types.DefaultParams(), LastSent: []types.LastSentEntry{{ConsAddr: "aabb", Power: -1}}},
		"duplicate":    {Params: types.DefaultParams(), LastSent: []types.LastSentEntry{{ConsAddr: "aabb"}, {ConsAddr: "aabb"}}},
	} {
		if err := gs.Validate(); err == nil {
			t.Fatalf("%s: must be rejected", name)
		}
	}
}
