package keeper_test

import (
	"context"
	"testing"

	"cosmossdk.io/math"
	corestore "cosmossdk.io/core/store"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	"github.com/cosmos/evm/x/paymaster/keeper"
	"github.com/cosmos/evm/x/paymaster/types"
)

// memKV is a tiny in-memory KVStoreService/KVStore for tests (keeper uses only Get/Set).
type memKV struct{ m map[string][]byte }

func newMem() *memKV { return &memKV{m: map[string][]byte{}} }

func (s *memKV) OpenKVStore(context.Context) corestore.KVStore   { return s }
func (s *memKV) Get(k []byte) ([]byte, error)                    { return s.m[string(k)], nil }
func (s *memKV) Has(k []byte) (bool, error)                      { _, ok := s.m[string(k)]; return ok, nil }
func (s *memKV) Set(k, v []byte) error                           { s.m[string(k)] = v; return nil }
func (s *memKV) Delete(k []byte) error                           { delete(s.m, string(k)); return nil }
func (s *memKV) Iterator(_, _ []byte) (corestore.Iterator, error)        { panic("unused") }
func (s *memKV) ReverseIterator(_, _ []byte) (corestore.Iterator, error) { panic("unused") }

func newKeeper() (keeper.Keeper, context.Context) { return keeper.NewKeeper(newMem()), context.Background() }

func TestResolveSponsor(t *testing.T) {
	k, ctx := newKeeper()
	sponsor := sdk.AccAddress([]byte("sponsor_address_0001"))
	user := sdk.AccAddress([]byte("user_address_0000001"))
	other := sdk.AccAddress([]byte("other_user_00000001x"))
	send := &banktypes.MsgSend{FromAddress: user.String(), ToAddress: other.String()}
	fee := sdk.NewCoins(sdk.NewCoin("aLIMO", math.NewInt(10000000000)))

	if err := k.SetPolicies(ctx, []types.Policy{{
		Sponsor:       sponsor.String(),
		AllowedSender: user.String(),
		MsgTypeURL:    sdk.MsgTypeURL(&banktypes.MsgSend{}),
		PerTxCap:      "20000000000aLIMO",
	}}); err != nil {
		t.Fatal(err)
	}

	got, ok := k.ResolveSponsor(ctx, []sdk.Msg{send}, user, fee)
	if !ok || !got.Equals(sponsor) {
		t.Fatalf("expected sponsor match, ok=%v got=%s", ok, got)
	}
	if _, ok := k.ResolveSponsor(ctx, []sdk.Msg{send}, other, fee); ok {
		t.Fatal("expected no match for non-allowed sender")
	}
	bigFee := sdk.NewCoins(sdk.NewCoin("aLIMO", math.NewInt(30000000000)))
	if _, ok := k.ResolveSponsor(ctx, []sdk.Msg{send}, user, bigFee); ok {
		t.Fatal("expected no match when fee exceeds per-tx cap")
	}
	if _, ok := k.ResolveSponsor(ctx, []sdk.Msg{&banktypes.MsgMultiSend{}}, user, fee); ok {
		t.Fatal("expected no match for non-allowed msg type")
	}
}

func TestResolveSponsorWildcards(t *testing.T) {
	k, ctx := newKeeper()
	sponsor := sdk.AccAddress([]byte("sponsor_address_0002"))
	anyUser := sdk.AccAddress([]byte("anyone_address_00001"))
	if err := k.SetPolicies(ctx, []types.Policy{{Sponsor: sponsor.String()}}); err != nil {
		t.Fatal(err)
	}
	got, ok := k.ResolveSponsor(ctx, []sdk.Msg{&banktypes.MsgSend{FromAddress: anyUser.String()}}, anyUser, sdk.NewCoins(sdk.NewCoin("aLIMO", math.NewInt(99))))
	if !ok || !got.Equals(sponsor) {
		t.Fatalf("wildcard policy should match anything, ok=%v", ok)
	}
}

func TestResolveSponsorNoPolicies(t *testing.T) {
	k, ctx := newKeeper()
	if _, ok := k.ResolveSponsor(ctx, []sdk.Msg{&banktypes.MsgSend{}}, sdk.AccAddress([]byte("x_address_0000000001")), sdk.NewCoins()); ok {
		t.Fatal("expected no sponsor when no policies set")
	}
}

func TestGenesisRoundTrip(t *testing.T) {
	k, ctx := newKeeper()
	gs := types.GenesisState{Policies: []types.Policy{{Sponsor: sdk.AccAddress([]byte("sponsor_address_0003")).String()}}}
	if err := k.InitGenesis(ctx, gs); err != nil {
		t.Fatal(err)
	}
	out := k.ExportGenesis(ctx)
	if len(out.Policies) != 1 || out.Policies[0].Sponsor != gs.Policies[0].Sponsor {
		t.Fatalf("genesis round-trip mismatch: %+v", out)
	}
}
