package keeper

import (
	"bytes"
	"testing"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/valgrant/types"

	msgv1 "cosmossdk.io/api/cosmos/msg/v1"
	gogoproto "github.com/cosmos/gogoproto/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// PROBE 1 — AUTHORITY (ante layer): the compiled proto descriptor for
// MsgClawbackGrant must carry option (cosmos.msg.v1.signer) = "authority". If it
// were "grantee" (or missing), a grantee could sign a NORMAL tx, set the
// authority string field to the gov module address, and bypass the gov gate at
// the msg-server. The SDK derives the REQUIRED tx signer from this annotation.
func TestProbe_ClawbackGrantSignerAnnotationIsAuthority(t *testing.T) {
	desc, err := gogoproto.HybridResolver.FindDescriptorByName(
		protoreflect.FullName("cosmos.evm.valgrant.v1.MsgClawbackGrant"))
	if err != nil {
		t.Fatalf("descriptor lookup: %v", err)
	}
	md, ok := desc.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("not a message descriptor: %T", desc)
	}
	ext := proto.GetExtension(md.Options(), msgv1.E_Signer)
	signers, _ := ext.([]string)
	t.Logf("compiled (cosmos.msg.v1.signer) for MsgClawbackGrant = %v", signers)
	if len(signers) != 1 || signers[0] != "authority" {
		t.Fatalf("SIGNER ANNOTATION = %v, want [authority]. If empty/grantee, the gov gate is bypassable via a self-signed tx.", signers)
	}
	// Cross-check the sibling gov msg + the admin msg for contrast.
	for name, want := range map[string]string{
		"cosmos.evm.valgrant.v1.MsgUpdateParams": "authority",
		"cosmos.evm.valgrant.v1.MsgClawback":     "admin",
		"cosmos.evm.valgrant.v1.MsgIssueLocked":  "admin",
	} {
		d, err := gogoproto.HybridResolver.FindDescriptorByName(protoreflect.FullName(name))
		if err != nil {
			t.Fatalf("descriptor %s: %v", name, err)
		}
		got, _ := proto.GetExtension(d.(protoreflect.MessageDescriptor).Options(), msgv1.E_Signer).([]string)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s signer = %v want [%s]", name, got, want)
		}
		t.Logf("OK %s signer=%v", name, got)
	}
}

// helper: bech32 valoper from a 20-byte seed
func valoper(seed byte) string {
	return sdk.ValAddress(bytes.Repeat([]byte{seed}, 20)).String()
}

// PROBE 2 — SLASH SHORTFALL over-seizure. Grant principal was fully delegated,
// then slashed (bonded now < grant.LockedAmount). The immediate sweep computes
// immediatePrincipal = locked - bonded > 0 and sweeps it out of the account's
// SPENDABLE balance — i.e. the grantee's liquid gas allowance / own funds — even
// though the design says gas + own funds are preserved and ONLY foundation
// principal is clawback-able.
func TestProbe_SlashShortfallSeizesGasAndOwnFunds(t *testing.T) {
	f := newFixture(t)

	// Grant of 1000 locked principal, all delegated to own validator, but a slash
	// reduced the live bond to 900 (100 principal destroyed). The grantee also
	// holds 50 gas + 500 of their OWN liquid LIMO in-account (550 spendable).
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(900)) // post-slash live bond
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	f.ak.SetAccount(f.ctx, base)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(550))))

	before := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "slashed-then-clawed"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	after := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	seized := before.Sub(after)

	t.Logf("bonded(post-slash)=900 locked=1000 -> immediatePrincipal=100")
	t.Logf("grantee spendable before=%s after=%s SEIZED(own+gas)=%s", before, after, seized)
	t.Logf("resp principal_returned=%s principal_pending=%s", resp.PrincipalReturned, resp.PrincipalPending)
	if seized.IsPositive() {
		t.Logf("REPRODUCED: %s of the grantee's LIQUID (gas+own) funds swept to the pool to cover the slashed shortfall — violates 'gas + own funds preserved'", seized)
	} else {
		t.Logf("no liquid seizure observed")
	}
}

// PROBE 3 — MULTI-VALIDATOR self-bond force-undelegation. Grantee delegated the
// 1000 grant to own validator V2 and self-delegated 500 own funds to a DIFFERENT
// validator V1 (sorts first). The clawback iterates delegations in address order
// and force-undelegates the V1 self-bond, leaving part of the grant bonded at V2.
func TestProbe_MultiValidatorSelfBondUndelegated(t *testing.T) {
	f := newFixture(t)
	// bech32 sort: seed 0x55 sorts BEFORE 0x22, so the SELF-BOND validator is
	// iterated first by GetDelegatorDelegations.
	vSelf := valoper(0x55)  // OWN self-bond validator, sorts FIRST
	vGrant := valoper(0x22) // grant-funded (own) validator, sorts LAST
	v1, v2 := vSelf, vGrant
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: v2, Status: "active"})
	f.sk.delegate(f.granteeBz, v2, math.NewInt(1000)) // grant -> own validator
	f.sk.delegate(f.granteeBz, v1, math.NewInt(500))  // OWN self-bond -> other validator

	v1Before := f.sk.tokensOf(f.granteeBz, v1)
	v2Before := f.sk.tokensOf(f.granteeBz, v2)
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	v1After := f.sk.tokensOf(f.granteeBz, v1)
	v2After := f.sk.tokensOf(f.granteeBz, v2)
	t.Logf("v1(own self-bond 500) before=%s after=%s", v1Before, v1After)
	t.Logf("v2(grant 1000)        before=%s after=%s", v2Before, v2After)
	t.Logf("resp principal_pending=%s (aggregate reclaim capped at locked=1000)", resp.PrincipalPending)
	if v1After.LT(v1Before) {
		t.Logf("REPRODUCED: %s of the grantee's OWN self-bond at V1 was force-undelegated while %s of the actual grant stayed bonded at V2. Aggregate reclaim is still <= 1000 (no net over-loss), but 'self-bond never touched' is violated compositionally.", v1Before.Sub(v1After), v2After)
	} else {
		t.Logf("V1 self-bond untouched")
	}
}

// PROBE 4 — bound the over-seizure: a fully in-account grant with EXTRA own funds
// only loses grant.LockedAmount; own funds are preserved (net loss <= grant).
func TestProbe_InAccountGrantPreservesOwnFunds(t *testing.T) {
	f := newFixture(t)
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000))))
	if err != nil {
		t.Fatal(err)
	}
	f.ak.SetAccount(f.ctx, plva)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(6000)))) // 1000 grant + 5000 own
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active"})

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "x"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	remaining := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	t.Logf("principal_returned=%s grantee_remaining=%s (want 5000 own preserved)", resp.PrincipalReturned, remaining)
	if !remaining.Equal(math.NewInt(5000)) {
		t.Fatalf("own funds NOT preserved: remaining=%s want 5000", remaining)
	}
}

// PROBE 5 — gov authority derivation matches the standard gov module account.
func TestProbe_GovAuthorityMatchesModuleAccount(t *testing.T) {
	got := authtypes.NewModuleAddress(govtypes.ModuleName).String()
	f := newFixture(t)
	if got != f.govAuthority() {
		t.Fatalf("gov authority mismatch: %q vs %q", got, f.govAuthority())
	}
	t.Logf("gov authority = %s", got)
}
