package keeper

import (
	"strings"
	"testing"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// Before this handler wrote FoundationValidators, the list the decentralisation
// KPI is computed from was frozen at genesis for the life of the chain. These
// tests pin the lever: gov can set it, extend it, and CLEAR it.
func TestValgrantUpdateParams_SetsFoundationValidators(t *testing.T) {
	f := newFixture(t)
	ms := NewMsgServerImpl(f.k)
	if err := f.k.SetParams(f.ctx, types.Params{Admin: "admin-a"}); err != nil {
		t.Fatal(err)
	}

	// 1. set the list from empty
	_, err := ms.UpdateParams(f.ctx, &types.MsgUpdateParams{
		Authority:            f.govAuthority(),
		Admin:                "admin-b",
		FoundationValidators: []string{f.valStr},
	})
	if err != nil {
		t.Fatalf("gov update must succeed: %v", err)
	}
	p := f.k.GetParams(f.ctx)
	if p.Admin != "admin-b" {
		t.Fatalf("admin = %q, want admin-b", p.Admin)
	}
	if len(p.FoundationValidators) != 1 || p.FoundationValidators[0] != f.valStr {
		t.Fatalf("foundation_validators = %v, want [%s]", p.FoundationValidators, f.valStr)
	}

	// 2. extend it
	if _, err := ms.UpdateParams(f.ctx, &types.MsgUpdateParams{
		Authority:            f.govAuthority(),
		Admin:                "admin-b",
		FoundationValidators: []string{f.valStr, "limovaloper1second"},
	}); err != nil {
		t.Fatalf("gov update must succeed: %v", err)
	}
	if got := f.k.GetParams(f.ctx).FoundationValidators; len(got) != 2 {
		t.Fatalf("foundation_validators = %v, want 2 entries", got)
	}

	// 3. CLEAR it - the direction that matters when the foundation exits. This is
	// also the replacement-semantics trap: an update that omits the list wipes it.
	if _, err := ms.UpdateParams(f.ctx, &types.MsgUpdateParams{
		Authority: f.govAuthority(),
		Admin:     "",
	}); err != nil {
		t.Fatalf("gov update must succeed: %v", err)
	}
	p = f.k.GetParams(f.ctx)
	if len(p.FoundationValidators) != 0 {
		t.Fatalf("foundation_validators = %v, want cleared", p.FoundationValidators)
	}
	if p.Admin != "" {
		t.Fatalf("admin = %q, want cleared", p.Admin)
	}
}

func TestValgrantUpdateParams_RejectsNonGovAuthority(t *testing.T) {
	f := newFixture(t)
	ms := NewMsgServerImpl(f.k)
	if err := f.k.SetParams(f.ctx, types.Params{Admin: "admin-a", FoundationValidators: []string{f.valStr}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"",
		"admin-a", // the module admin is NOT the params authority
		authtypes.NewModuleAddress(types.ModuleName).String(),
	} {
		_, err := ms.UpdateParams(f.ctx, &types.MsgUpdateParams{Authority: bad, Admin: "hijacked"})
		if err == nil {
			t.Fatalf("authority %q must be rejected", bad)
		}
		if !strings.Contains(err.Error(), "expected gov authority") {
			t.Fatalf("authority %q: unexpected error %v", bad, err)
		}
	}
	p := f.k.GetParams(f.ctx)
	if p.Admin != "admin-a" || len(p.FoundationValidators) != 1 {
		t.Fatalf("a rejected message must not have written params: %+v", p)
	}
}
