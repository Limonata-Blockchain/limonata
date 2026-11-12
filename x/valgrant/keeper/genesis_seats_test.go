package keeper

import (
	"bytes"
	"testing"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// ---------------------------------------------------------------------------
// x/valgrant InitGenesis - LES SIEGES DU MAINNET
//
// Ces tests sont la garantie que les 16 sieges naissent VRAIMENT au bloc 1.
// Avant le patch, InitGenesis ne faisait que SetParams + SetGrant: le registre
// annoncait N sieges alors qu'aucun compte, aucun PermanentLockedAccount et
// aucun aLIMO n'existaient (comptabilite fantome), et les gentx des operateurs
// auraient echoue faute de fonds - un mainnet a UN SEUL validateur.
// ---------------------------------------------------------------------------

func acc(b byte) sdk.AccAddress { return sdk.AccAddress(bytes.Repeat([]byte{b}, 20)) }
func val(b byte) sdk.ValAddress { return sdk.ValAddress(bytes.Repeat([]byte{b}, 20)) }

// TestInitGenesis_CreatesTwoSeats: deux grants dans le fichier de genese ->
// deux comptes reellement crees, de type PermanentLockedAccount, portant le bon
// solde, et la reserve du module diminuee d'exactement la somme versee.
func TestInitGenesis_CreatesTwoSeats(t *testing.T) {
	f := newFixture(t)

	a1, a2 := acc(0xA1), acc(0xA2)
	v1, v2 := val(0xB1), val(0xB2)
	locked1, gas1 := math.NewInt(1_000_000), math.NewInt(5_000)
	locked2, gas2 := math.NewInt(2_500_000), math.NewInt(0)
	total := locked1.Add(gas1).Add(locked2).Add(gas2)

	// la reserve est financee au genesis (app_state.bank.balances), avec un
	// surplus qui doit rester intact.
	surplus := math.NewInt(777)
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, total.Add(surplus))))

	gs := types.GenesisState{
		Params: types.Params{Admin: f.granteeStr},
		Grants: []types.Grant{
			{Grantee: a1.String(), LockedAmount: locked1.String(), GasAllowance: gas1.String(), ValidatorOp: v1.String(), Status: "active"},
			{Grantee: a2.String(), LockedAmount: locked2.String(), GasAllowance: gas2.String(), ValidatorOp: v2.String(), Status: "active"},
		},
	}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	for _, tc := range []struct {
		addr   sdk.AccAddress
		locked math.Int
		gas    math.Int
		valop  sdk.ValAddress
	}{{a1, locked1, gas1, v1}, {a2, locked2, gas2, v2}} {
		raw := f.ak.GetAccount(f.ctx, tc.addr)
		if raw == nil {
			t.Fatalf("%s: aucun compte cree (comptabilite fantome)", tc.addr)
		}
		plva, ok := raw.(*vestingtypes.PermanentLockedAccount)
		if !ok {
			t.Fatalf("%s: compte de type %T, attendu *PermanentLockedAccount", tc.addr, raw)
		}
		if got := plva.OriginalVesting.AmountOf(testDenom); !got.Equal(tc.locked) {
			t.Fatalf("%s: original_vesting %s, attendu %s", tc.addr, got, tc.locked)
		}
		if got := plva.EndTime; got != 0 {
			t.Fatalf("%s: end_time %d, un PermanentLockedAccount doit avoir 0", tc.addr, got)
		}
		want := tc.locked.Add(tc.gas)
		if got := f.bank.GetBalance(f.ctx, tc.addr, testDenom).Amount; !got.Equal(want) {
			t.Fatalf("%s: solde %s, attendu %s (principal + gaz)", tc.addr, got, want)
		}
		// le gaz est la seule part DEPENSABLE (spendable = solde - principal verrouille)
		spendable := f.bank.GetBalance(f.ctx, tc.addr, testDenom).Amount.Sub(plva.OriginalVesting.AmountOf(testDenom))
		if !spendable.Equal(tc.gas) {
			t.Fatalf("%s: depensable %s, attendu %s", tc.addr, spendable, tc.gas)
		}
		// le registre de parts est seme (sinon le clawback de gouvernance ne
		// reprendrait RIEN sur un siege ne au genesis)
		g, found := f.k.GetGrant(f.ctx, tc.addr.String())
		if !found {
			t.Fatalf("%s: grant absent du registre", tc.addr)
		}
		wantShares := math.LegacyNewDecFromInt(tc.locked).String()
		if g.GrantedShares != wantShares || g.TrackedShares != wantShares {
			t.Fatalf("%s: granted/tracked = %q/%q, attendu %q", tc.addr, g.GrantedShares, g.TrackedShares, wantShares)
		}
		if g.ValidatorOp != tc.valop.String() {
			t.Fatalf("%s: validator_op %q", tc.addr, g.ValidatorOp)
		}
	}

	// la reserve a diminue d'EXACTEMENT la somme versee
	if got := f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount; !got.Equal(surplus) {
		t.Fatalf("reserve %s, attendu %s (surplus intact)", got, surplus)
	}
}

// La reserve sous-financee doit faire ECHOUER le demarrage, avec le manque exact.
func TestInitGenesis_UnderfundedPoolRefusesToStart(t *testing.T) {
	f := newFixture(t)
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(999))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: acc(0xA1).String(), LockedAmount: "1000", GasAllowance: "0", Status: "active"},
	}}
	err := f.k.InitGenesis(f.ctx, gs)
	if err == nil {
		t.Fatal("InitGenesis a accepte un genesis dont la reserve ne couvre pas les grants")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("short by 1")) {
		t.Fatalf("message d'erreur sans le manque exact: %v", err)
	}
	if f.ak.GetAccount(f.ctx, acc(0xA1)) != nil {
		t.Fatal("un compte a ete cree malgre l'echec du controle de couverture")
	}
}

// x/auth tourne AVANT x/valgrant: le compte du siege peut deja exister en
// BaseAccount. Il doit etre CONVERTI sur place (meme numero de compte), pas
// provoquer un echec ni un doublon.
func TestInitGenesis_ExistingBaseAccountIsConvertedInPlace(t *testing.T) {
	f := newFixture(t)
	a1 := acc(0xA1)
	pre := authtypes.NewBaseAccountWithAddress(a1)
	if err := pre.SetAccountNumber(42); err != nil {
		t.Fatal(err)
	}
	if err := pre.SetSequence(7); err != nil {
		t.Fatal(err)
	}
	f.ak.SetAccount(f.ctx, pre)
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1_000))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "0", Status: "active"},
	}}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	plva, ok := f.ak.GetAccount(f.ctx, a1).(*vestingtypes.PermanentLockedAccount)
	if !ok {
		t.Fatalf("compte non converti: %T", f.ak.GetAccount(f.ctx, a1))
	}
	if plva.GetAccountNumber() != 42 || plva.GetSequence() != 7 {
		t.Fatalf("numero/sequence perdus a la conversion: %d/%d", plva.GetAccountNumber(), plva.GetSequence())
	}
	if got := f.bank.GetBalance(f.ctx, a1, testDenom).Amount; !got.Equal(math.NewInt(1000)) {
		t.Fatalf("solde %s, attendu 1000", got)
	}
}

// Aller-retour export -> import: x/auth restaure deja le PermanentLockedAccount
// et x/bank son solde. valgrant ne doit PAS refinancer (double depense de la
// reserve).
func TestInitGenesis_RoundTripDoesNotRefund(t *testing.T) {
	f := newFixture(t)
	a1 := acc(0xA1)
	base := authtypes.NewBaseAccountWithAddress(a1)
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000))))
	if err != nil {
		t.Fatal(err)
	}
	f.ak.SetAccount(f.ctx, plva)
	f.bank.add(a1, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000)))) // x/bank a restaure le solde
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "0", Status: "active", GrantedShares: "1000.000000000000000000", TrackedShares: "1000.000000000000000000"},
	}}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	if got := f.bank.GetBalance(f.ctx, a1, testDenom).Amount; !got.Equal(math.NewInt(1000)) {
		t.Fatalf("beneficiaire refinance: solde %s, attendu 1000", got)
	}
	if got := f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount; !got.Equal(math.NewInt(1000)) {
		t.Fatalf("reserve entamee a l'import: %s, attendu 1000", got)
	}
}

// Un grant "revoked" est une trace historique: aucun compte, aucun transfert.
func TestInitGenesis_RevokedGrantIsNotFunded(t *testing.T) {
	f := newFixture(t)
	a1 := acc(0xA1)
	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "0", Status: "revoked"},
	}}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	if f.ak.GetAccount(f.ctx, a1) != nil {
		t.Fatal("un grant revoque a cree un compte")
	}
	if got := f.bank.GetBalance(f.ctx, a1, testDenom).Amount; !got.IsZero() {
		t.Fatalf("un grant revoque a ete finance: %s", got)
	}
	if _, found := f.k.GetGrant(f.ctx, a1.String()); !found {
		t.Fatal("la trace historique du grant revoque a disparu")
	}
}

// Un genesis incoherent doit refuser de demarrer, pas demarrer en silence.
func TestInitGenesis_RejectsIncoherentGenesis(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name string
		gs   types.GenesisState
	}{
		{"statut invalide", types.GenesisState{Grants: []types.Grant{{Grantee: acc(0xA1).String(), LockedAmount: "1", GasAllowance: "0", Status: "pending"}}}},
		{"montant illisible", types.GenesisState{Grants: []types.Grant{{Grantee: acc(0xA1).String(), LockedAmount: "beaucoup", GasAllowance: "0", Status: "active"}}}},
		{"beneficiaire non bech32", types.GenesisState{Grants: []types.Grant{{Grantee: "pas-une-adresse", LockedAmount: "1", GasAllowance: "0", Status: "active"}}}},
		{"validator_op invalide", types.GenesisState{Grants: []types.Grant{{Grantee: acc(0xA1).String(), LockedAmount: "1", GasAllowance: "0", ValidatorOp: "cosmosvaloper1zzzz", Status: "active"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f2 := newFixture(t)
			f2.bank.add(f2.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1_000_000))))
			if err := f2.k.InitGenesis(f2.ctx, tc.gs); err == nil {
				t.Fatalf("genesis incoherent accepte (%s)", tc.name)
			}
		})
	}
	_ = f
}

// Le gentx du siege delegue APRES valgrant (genutil tourne ensuite). Les parts
// semees doivent etre CORRIGEES A LA BAISSE par le hook quand le gentx delegue
// moins que le principal verrouille, et laissees intactes quand il delegue tout.
func TestInitGenesis_SeededSharesReconcileWithTheGentx(t *testing.T) {
	f := newFixture(t)
	a1, a2 := acc(0xA1), acc(0xA2)
	v1, v2 := val(0xB1), val(0xB2)
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(3_000))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "0", ValidatorOp: v1.String(), Status: "active"},
		{Grantee: a2.String(), LockedAmount: "2000", GasAllowance: "0", ValidatorOp: v2.String(), Status: "active"},
	}}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	// genutil livre les gentx: a1 delegue tout (1000), a2 seulement 500.
	f.sk.addValidator(v1.String())
	f.sk.addValidator(v2.String())
	f.sk.addDelegationHook(f.ctx, a1, v1.String(), math.NewInt(1000))
	f.sk.addDelegationHook(f.ctx, a2, v2.String(), math.NewInt(500))

	g1, _ := f.k.GetGrant(f.ctx, a1.String())
	if g1.GrantedShares != "1000.000000000000000000" {
		t.Fatalf("a1 granted_shares %q, attendu 1000 (gentx delegue tout le principal)", g1.GrantedShares)
	}
	g2, _ := f.k.GetGrant(f.ctx, a2.String())
	if g2.GrantedShares != "500.000000000000000000" {
		t.Fatalf("a2 granted_shares %q, attendu 500 (le hook corrige a la baisse)", g2.GrantedShares)
	}
	if g2.TrackedShares != "500.000000000000000000" {
		t.Fatalf("a2 tracked_shares %q, attendu 500", g2.TrackedShares)
	}
}

// Le clawback de gouvernance doit pouvoir REPRENDRE le principal d'un siege ne
// au genesis. C'est la raison d'etre du semis de parts (patch #5).
func TestInitGenesis_GenesisSeatIsClawbackable(t *testing.T) {
	f := newFixture(t)
	a1 := acc(0xA1)
	v1 := val(0xB1)
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1_000))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "0", ValidatorOp: v1.String(), Status: "active"},
	}}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	f.sk.addValidator(v1.String())
	f.sk.addDelegationHook(f.ctx, a1, v1.String(), math.NewInt(1000)) // le gentx

	returned, pending, _, _, _, err := f.k.ClawbackGrantGov(f.ctx, a1.String(), "test")
	if err != nil {
		t.Fatalf("ClawbackGrantGov: %v", err)
	}
	if !pending.Add(returned).Equal(math.NewInt(1000)) {
		t.Fatalf("clawback a repris %s (immediat) + %s (differe), attendu 1000 au total - "+
			"un siege ne au genesis sans parts semees rendrait 0", returned, pending)
	}
}

// Un siege deja PRE-FINANCE dans app_state.bank.balances (ligne de la table de
// capitalisation) ne doit PAS etre finance une seconde fois par la reserve:
// ce serait une double depense silencieuse. Le compte est seulement converti en
// PermanentLockedAccount et le grant enregistre.
func TestInitGenesis_PrefundedSeatIsNotDoubleFunded(t *testing.T) {
	f := newFixture(t)
	a1 := acc(0xA1)
	f.ak.SetAccount(f.ctx, authtypes.NewBaseAccountWithAddress(a1))
	f.bank.add(a1, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1_050)))) // 1000 principal + 50 gaz
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(9_999))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "50", Status: "active"},
	}}
	if err := f.k.InitGenesis(f.ctx, gs); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	if _, ok := f.ak.GetAccount(f.ctx, a1).(*vestingtypes.PermanentLockedAccount); !ok {
		t.Fatalf("compte non converti: %T", f.ak.GetAccount(f.ctx, a1))
	}
	if got := f.bank.GetBalance(f.ctx, a1, testDenom).Amount; !got.Equal(math.NewInt(1_050)) {
		t.Fatalf("siege finance deux fois: solde %s, attendu 1050", got)
	}
	if got := f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount; !got.Equal(math.NewInt(9_999)) {
		t.Fatalf("reserve entamee pour un siege deja finance: %s, attendu 9999", got)
	}
}

// Un pre-financement PARTIEL est ambigu (la reserve completerait-elle? doublerait-
// elle?): le genesis doit refuser de demarrer.
func TestInitGenesis_PartialPrefundingIsRejected(t *testing.T) {
	f := newFixture(t)
	a1 := acc(0xA1)
	f.bank.add(a1, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(600))))
	f.bank.add(f.poolAddr, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(9_999))))

	gs := types.GenesisState{Grants: []types.Grant{
		{Grantee: a1.String(), LockedAmount: "1000", GasAllowance: "0", Status: "active"},
	}}
	err := f.k.InitGenesis(f.ctx, gs)
	if err == nil {
		t.Fatal("pre-financement partiel accepte")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("double-spend")) {
		t.Fatalf("message d'erreur peu clair: %v", err)
	}
}
