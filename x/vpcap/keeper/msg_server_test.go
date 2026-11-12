package keeper

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corestore "cosmossdk.io/core/store"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/vpcap/types"
)

// memKV is a tiny in-memory KVStoreService/KVStore (the params path uses only Get/Set).
type memKV struct{ m map[string][]byte }

func newMem() *memKV { return &memKV{m: map[string][]byte{}} }

func (s *memKV) OpenKVStore(context.Context) corestore.KVStore           { return s }
func (s *memKV) Get(k []byte) ([]byte, error)                            { return s.m[string(k)], nil }
func (s *memKV) Has(k []byte) (bool, error)                              { _, ok := s.m[string(k)]; return ok, nil }
func (s *memKV) Set(k, v []byte) error                                   { s.m[string(k)] = v; return nil }
func (s *memKV) Delete(k []byte) error                                   { delete(s.m, string(k)); return nil }
func (s *memKV) Iterator(_, _ []byte) (corestore.Iterator, error)        { panic("unused") }
func (s *memKV) ReverseIterator(_, _ []byte) (corestore.Iterator, error) { panic("unused") }

func govAuthority() string { return authtypes.NewModuleAddress(govtypes.ModuleName).String() }

func newParamsMsgServer(t *testing.T) (types.MsgServer, Keeper, context.Context) {
	t.Helper()
	k := Keeper{storeService: newMem()}
	ctx := context.Background()
	enabled := types.DefaultParams()
	enabled.Enabled = true
	if err := k.SetParams(ctx, enabled); err != nil {
		t.Fatal(err)
	}
	return NewMsgServerImpl(k), k, ctx
}

func paramsJSON(t *testing.T, p types.Params) []byte {
	t.Helper()
	bz, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return bz
}

// The decentralisation cap has NO admin key: only a passed gov proposal moves it.
func TestVpcapUpdateParams_RejectsNonGovAuthority(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	p := types.DefaultParams()
	p.Enabled = false
	for _, bad := range []string{
		"",
		"cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		authtypes.NewModuleAddress(types.ModuleName).String(),
	} {
		_, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: bad, Params: paramsJSON(t, p)})
		if err == nil {
			t.Fatalf("authority %q must be rejected", bad)
		}
		if !strings.Contains(err.Error(), "expected gov authority") {
			t.Fatalf("authority %q: unexpected error %v", bad, err)
		}
	}
	if !k.GetParams(ctx).Enabled {
		t.Fatal("a rejected message must not have written params")
	}
}

func TestVpcapUpdateParams_GovCanRetuneTheCap(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	p := types.DefaultParams()
	p.Enabled = true
	p.PerValidatorCapBps = 2000
	p.FoundationCapBps = 2500
	p.FoundationValidators = []string{"limovaloper1abc"}
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: paramsJSON(t, p)}); err != nil {
		t.Fatalf("gov update must succeed: %v", err)
	}
	got := k.GetParams(ctx)
	if got.PerValidatorCapBps != 2000 || got.FoundationCapBps != 2500 || len(got.FoundationValidators) != 1 {
		t.Fatalf("params not applied: %+v", got)
	}
}

// Omitting "enabled" would silently switch the cap OFF; refuse the payload instead.
func TestVpcapUpdateParams_RejectsIncompletePayload(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	full := map[string]json.RawMessage{}
	if err := json.Unmarshal(paramsJSON(t, types.DefaultParams()), &full); err != nil {
		t.Fatal(err)
	}
	for _, drop := range []string{"enabled", "per_validator_cap_bps", "foundation_cap_bps", "foundation_validators"} {
		partial := map[string]json.RawMessage{}
		for k2, v := range full {
			if k2 != drop {
				partial[k2] = v
			}
		}
		bz, err := json.Marshal(partial)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: bz})
		if err == nil {
			t.Fatalf("a payload missing %q must be refused", drop)
		}
		if !strings.Contains(err.Error(), drop) {
			t.Fatalf("missing %q: error should name it, got %v", drop, err)
		}
	}
	if !k.GetParams(ctx).Enabled {
		t.Fatal("a refused message must not have written params")
	}
}

func TestVpcapUpdateParams_RejectsUnknownKey(t *testing.T) {
	ms, _, ctx := newParamsMsgServer(t)
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(paramsJSON(t, types.DefaultParams()), &raw); err != nil {
		t.Fatal(err)
	}
	raw["per_validator_cap_bp"] = json.RawMessage(`1`) // typo
	bz, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: bz}); err == nil {
		t.Fatal("a typo'd key must be refused, not silently ignored")
	}
}

// The handler runs the SAME validation as the genesis path: an enabled cap of
// 0 or >= 10000 bps is a no-op cap and must not be installable.
func TestVpcapUpdateParams_RejectsInvalidCap(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	for _, bps := range []uint32{0, 10000, 20000} {
		p := types.DefaultParams()
		p.Enabled = true
		p.PerValidatorCapBps = bps
		_, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: paramsJSON(t, p)})
		if err == nil {
			t.Fatalf("per_validator_cap_bps=%d must be rejected when enabled", bps)
		}
	}
	if got := k.GetParams(ctx).PerValidatorCapBps; got != types.DefaultParams().PerValidatorCapBps {
		t.Fatalf("invalid params must not be written, got %d", got)
	}
}

func TestVpcapUpdateParams_RejectsMalformedJSON(t *testing.T) {
	ms, _, ctx := newParamsMsgServer(t)
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: []byte(`{`)}); err == nil {
		t.Fatal("malformed json must be refused")
	}
}
