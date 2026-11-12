package keeper

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/gassponsor/types"
)

func govAuthority() string {
	return authtypes.NewModuleAddress(govtypes.ModuleName).String()
}

func newParamsMsgServer(t *testing.T) (types.MsgServer, Keeper, context.Context) {
	t.Helper()
	k := Keeper{storeService: newMem()}
	ctx := context.Context(testCtx())
	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
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

// The whole point of the module: a NON-gov signer can never touch the mint knobs.
func TestGassponsorUpdateParams_RejectsNonGovAuthority(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	p := types.DefaultParams()
	p.Enabled = false
	for _, bad := range []string{
		"",
		"cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		authtypes.NewModuleAddress(types.ModuleName).String(), // the module's OWN account
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

func TestGassponsorUpdateParams_GovCanFlipEveryKnob(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	p := types.DefaultParams()
	p.Enabled = false
	p.RefillEnabled = false
	p.RefillDailyMintCap = "123456"
	p.DappDailyCap = "777"
	p.OnboardingDailyCap = "888"
	p.DailyBudget = "999"
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: paramsJSON(t, p)}); err != nil {
		t.Fatalf("gov update must succeed: %v", err)
	}
	got := k.GetParams(ctx)
	if got.Enabled || got.RefillEnabled {
		t.Fatal("kill-switch was not applied")
	}
	if got.RefillDailyMintCap != "123456" || got.DappDailyCap != "777" ||
		got.OnboardingDailyCap != "888" || got.DailyBudget != "999" {
		t.Fatalf("params not applied: %+v", got)
	}
}

// An INCOMPLETE payload is refused: omitting a key would silently reset it, and for
// the cap fields "" means UNLIMITED MINTING.
func TestGassponsorUpdateParams_RejectsIncompletePayload(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	full := map[string]json.RawMessage{}
	if err := json.Unmarshal(paramsJSON(t, types.DefaultParams()), &full); err != nil {
		t.Fatal(err)
	}
	for _, drop := range []string{"enabled", "refill_daily_mint_cap", "dapp_daily_cap", "onboarding_daily_cap"} {
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

func TestGassponsorUpdateParams_RejectsUnknownKey(t *testing.T) {
	ms, _, ctx := newParamsMsgServer(t)
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(paramsJSON(t, types.DefaultParams()), &raw); err != nil {
		t.Fatal(err)
	}
	raw["refil_daily_mint_cap"] = json.RawMessage(`"1"`) // typo
	bz, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: bz}); err == nil {
		t.Fatal("a typo'd key must be refused, not silently ignored")
	}
}

// The handler runs the SAME validation as the genesis path.
func TestGassponsorUpdateParams_RejectsInvalidParams(t *testing.T) {
	ms, k, ctx := newParamsMsgServer(t)
	p := types.DefaultParams()
	p.RefillDailyMintCap = "not-a-number"
	_, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: paramsJSON(t, p)})
	if err == nil {
		t.Fatal("params that genesis would reject must be rejected here too")
	}
	if !strings.Contains(err.Error(), "refill_daily_mint_cap") {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.GetParams(ctx).RefillDailyMintCap != types.DefaultParams().RefillDailyMintCap {
		t.Fatal("invalid params must not be written")
	}
}

func TestGassponsorUpdateParams_RejectsMalformedJSON(t *testing.T) {
	ms, _, ctx := newParamsMsgServer(t)
	if _, err := ms.UpdateParams(ctx, &types.MsgUpdateParams{Authority: govAuthority(), Params: []byte(`{`)}); err == nil {
		t.Fatal("malformed json must be refused")
	}
}
