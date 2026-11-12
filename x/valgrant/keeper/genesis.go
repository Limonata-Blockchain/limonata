package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// InitGenesis loads the x/valgrant params AND REALLY CREATES the seats listed in
// grants[].
//
// POURQUOI (parite mainnet, piece #56 / patch #1): jusqu'ici InitGenesis ne
// faisait que SetParams + SetGrant. Remplir grants[] dans le fichier de genese
// produisait donc de la COMPTABILITE FANTOME - le registre annoncait N sieges
// alors qu'aucun compte, aucun PermanentLockedAccount et aucun aLIMO n'existaient.
//
// MODE DE DEFAILLANCE REEL (a lire avant une ceremonie): sans ce patch, un
// mainnet dont le genesis porte a la fois grants[] et les gentx des sieges NE
// DEMARRE PAS DU TOUT. Il ne produit PAS une chaine mono-validateur degradee.
// Le compte du siege n'existe pas, donc l'ante de la gentx echoue avec
// "account <adresse> does not exist: unknown address"
// (cosmos-sdk x/auth/ante/sigverify.go:636); genutil remonte
// "failed to execute DeliverTx for '<gentx>'" (x/genutil/gentx.go:110) et
// x/genutil/module.go:108 fait panic(err) DANS InitChain. Le noeud avorte a la
// hauteur 0, aucun bloc n'est produit, et tous les operateurs sont bloques a
// l'identique. (La lecture "un seul validateur" ne vaudrait que pour un genesis
// SANS les gentx des sieges, ce qui n'est pas le cas d'une ceremonie.)
//
// InitGenesis rejoue donc maintenant, pour
// chaque grant, exactement la meme sequence que IssueGrant (grant.go:22-88):
// NewBaseAccountWithAddress -> NewAccount -> NewPermanentLockedAccount ->
// SetAccount -> SendCoinsFromModuleToAccount (principal verrouille, puis
// allocation de gaz liquide).
//
// ORDRE DES MODULES: x/valgrant doit passer APRES auth/bank/staking (il lui faut
// le numero de compte global, le solde de la reserve et le bond denom) et AVANT
// genutil (evmd/app.go, genesisModuleOrder), parce que les gentx livres par
// genutil delegent depuis ces comptes: sans les comptes ni les fonds, la
// MsgCreateValidator de chaque siege echoue.
//
// LA DELEGATION N'EST PAS FAITE ICI: au moment ou valgrant tourne, aucun
// validateur n'existe encore (ils naissent des gentx, donc APRES). C'est le gentx
// du siege qui delegue le principal verrouille - deleguer des coins verrouilles
// est licite, bank.DelegateCoins remplit le seau DelegatedVesting du PLVA. Le
// registre de parts (GrantedShares/TrackedShares) est donc SEME ici et corrige
// ensuite par le hook AfterDelegationModified (voir seedGrantShares).
func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	// Un genesis incoherent doit REFUSER de demarrer, pas demarrer en silence.
	if err := gs.Validate(); err != nil {
		return fmt.Errorf("valgrant: invalid genesis: %w", err)
	}
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}

	bondDenom, err := k.stakingKeeper.BondDenom(ctx)
	if err != nil {
		return fmt.Errorf("valgrant: cannot read bond denom (x/staking must init before x/valgrant): %w", err)
	}

	// Controle de couverture AVANT tout mouvement: la reserve doit porter la somme
	// des principaux + allocations de gaz des grants ACTIFS. Sans ce controle
	// prealable, un genesis sous-finance echoue au milieu de la boucle avec un
	// message bancaire opaque; ici il echoue avec le montant manquant exact.
	if err := k.assertGenesisPoolCoverage(ctx, gs.Grants, bondDenom); err != nil {
		return err
	}

	for i, g := range gs.Grants {
		provisioned, perr := k.provisionGenesisGrant(ctx, g, bondDenom)
		if perr != nil {
			return fmt.Errorf("valgrant: genesis grant %d (%s): %w", i, g.Grantee, perr)
		}
		if err := k.SetGrant(ctx, provisioned); err != nil {
			return err
		}
	}

	// Restore the 0x03 deferred-sweep queue. A clawback whose bonded principal is
	// still unbonding exists ONLY here until EndBlock completes it; an import that
	// dropped it would leave the maturing coins with the grantee forever. Nothing
	// is created or funded - these are pure bookkeeping records that the EndBlock
	// sweep resolves against live x/staking unbonding entries.
	for i, pc := range gs.PendingClawbacks {
		if err := k.SetPendingClawback(ctx, pc); err != nil {
			return fmt.Errorf("valgrant: pending_clawbacks[%d] (%s): %w", i, pc.Grantee, err)
		}
	}
	// The KPI snapshot is observational and is rewritten by the very next EndBlock;
	// carrying it only avoids an all-zero answer to a query made before that block.
	if gs.KPISnapshot != nil {
		if err := k.SetKPISnapshot(ctx, *gs.KPISnapshot); err != nil {
			return err
		}
	}
	return nil
}

// assertGenesisPoolCoverage checks the valgrant reserve holds enough bondDenom to
// fund every ACTIVE grant that still needs funding, and reports the exact
// shortfall. Grants whose grantee account is already a PermanentLockedAccount
// (export -> import round-trip: x/auth + x/bank already restored account AND
// balance) are excluded, since they are not re-funded.
func (k Keeper) assertGenesisPoolCoverage(ctx context.Context, grants []types.Grant, bondDenom string) error {
	needed := math.ZeroInt()
	for _, g := range grants {
		if g.Status == "revoked" {
			continue
		}
		granteeBz, err := k.accountKeeper.AddressCodec().StringToBytes(g.Grantee)
		if err != nil {
			// reported precisely by provisionGenesisGrant
			continue
		}
		if _, already := k.accountKeeper.GetAccount(ctx, granteeBz).(*vestingtypes.PermanentLockedAccount); already {
			continue
		}
		locked, _ := math.NewIntFromString(g.LockedAmount)
		gas, _ := math.NewIntFromString(g.GasAllowance)
		due := locked.Add(gas)
		// siege deja pre-finance dans app_state.bank.balances: la reserve n'a rien
		// a verser (voir provisionGenesisGrant).
		if k.bankKeeper.GetBalance(ctx, granteeBz, bondDenom).Amount.GTE(due) && due.IsPositive() {
			continue
		}
		needed = needed.Add(due)
	}
	if !needed.IsPositive() {
		return nil
	}
	poolAddr := k.accountKeeper.GetModuleAddress(types.ModuleName)
	if poolAddr == nil {
		return fmt.Errorf("valgrant: module account address is unknown")
	}
	have := k.bankKeeper.GetBalance(ctx, poolAddr, bondDenom).Amount
	if have.LT(needed) {
		return fmt.Errorf(
			"valgrant: reserve pool %s holds %s%s but genesis grants require %s%s (short by %s%s) - "+
				"seed the valgrant module account in app_state.bank.balances before the ceremony",
			poolAddr.String(), have, bondDenom, needed, bondDenom, needed.Sub(have), bondDenom,
		)
	}
	return nil
}

// provisionGenesisGrant materializes ONE genesis grant and returns the grant
// record to store (share ledger seeded).
//
// Pieges traites explicitement:
//   - IssueGrant refuse un compte deja existant (grant.go:47-51) et c'est le cas
//     NORMAL au genesis: x/auth InitGenesis tourne AVANT et peut avoir cree le
//     compte du siege. Paniquer serait absurde. On distingue donc trois cas: pas
//     de compte -> creation complete; BaseAccount -> conversion SUR PLACE en
//     PermanentLockedAccount (meme numero de compte, meme pubkey) puis
//     financement; PermanentLockedAccount -> deja provisionne (aller-retour
//     export/import), on ne refinance PAS. Tout autre type de compte est une
//     ambiguite: on refuse de demarrer.
//   - un grant "revoked" dans le fichier est une trace historique: aucun compte
//     n'est cree, aucun aLIMO ne bouge.
func (k Keeper) provisionGenesisGrant(ctx context.Context, g types.Grant, bondDenom string) (types.Grant, error) {
	if g.Status != "revoked" {
		operator, err := k.bindMainnetGrantValidator(ctx, g.Grantee, g.ValidatorOp)
		if err != nil {
			return g, err
		}
		g.ValidatorOp = operator
	}
	granteeBz, err := k.accountKeeper.AddressCodec().StringToBytes(g.Grantee)
	if err != nil {
		return g, fmt.Errorf("invalid grantee address %q: %w", g.Grantee, err)
	}

	// validator_op, quand il est renseigne, doit etre un valoper decodable: une
	// faute de frappe ici rendrait le registre de parts (et donc le clawback de
	// gouvernance) inoperant en silence sur ce siege.
	if g.ValidatorOp != "" {
		if _, verr := k.stakingKeeper.ValidatorAddressCodec().StringToBytes(g.ValidatorOp); verr != nil {
			return g, fmt.Errorf("invalid validator_op %q: %w", g.ValidatorOp, verr)
		}
	}

	out := g
	if out.Status == "" {
		out.Status = "active"
	}

	locked, ok := math.NewIntFromString(g.LockedAmount)
	if !ok || locked.IsNegative() {
		return g, fmt.Errorf("invalid locked_amount %q", g.LockedAmount)
	}
	gas, ok := math.NewIntFromString(g.GasAllowance)
	if !ok || gas.IsNegative() {
		return g, fmt.Errorf("invalid gas_allowance %q", g.GasAllowance)
	}

	if out.Status == "revoked" {
		// trace historique: rien a creer, rien a transferer.
		return k.seedGrantShares(out, locked), nil
	}

	if k.bankKeeper.BlockedAddr(granteeBz) {
		return g, fmt.Errorf("grantee address %s is blocked from receiving funds", g.Grantee)
	}

	lockedCoins := sdk.NewCoins(sdk.NewCoin(bondDenom, locked))
	gasCoins := sdk.NewCoins()
	if gas.IsPositive() {
		gasCoins = sdk.NewCoins(sdk.NewCoin(bondDenom, gas))
	}

	// Qui finance ce siege? La reserve du module, SAUF si le fichier de genese
	// pre-finance deja le compte dans app_state.bank.balances (ligne de la table
	// de capitalisation). Financer les deux serait une DOUBLE DEPENSE silencieuse
	// de la reserve, et c'est exactement le genre d'erreur qu'un genesis ne
	// pardonne pas: on la rend impossible plutot que discrete.
	due := locked.Add(gas)
	preBal := k.bankKeeper.GetBalance(ctx, granteeBz, bondDenom).Amount
	fund := true
	switch {
	case preBal.IsZero():
		// nominal: la reserve verse.
	case due.IsPositive() && preBal.GTE(due):
		// pre-finance par app_state.bank: on ne verse rien, on convertit le compte
		// et on enregistre le grant.
		fund = false
	default:
		return g, fmt.Errorf(
			"grantee %s already holds %s%s in app_state.bank but the grant requires %s%s: "+
				"pre-fund the seat fully in bank OR not at all - a partial pre-funding would "+
				"double-spend the valgrant reserve",
			g.Grantee, preBal, bondDenom, due, bondDenom,
		)
	}

	switch existing := k.accountKeeper.GetAccount(ctx, granteeBz).(type) {
	case nil:
		// Cas nominal d'un mainnet neuf: le compte n'existe pas encore.
		baseAcc := authtypes.NewBaseAccountWithAddress(granteeBz)
		created, castOK := k.accountKeeper.NewAccount(ctx, baseAcc).(*authtypes.BaseAccount)
		if !castOK {
			return g, fmt.Errorf("account keeper returned an unexpected account type for %s", g.Grantee)
		}
		plva, verr := vestingtypes.NewPermanentLockedAccount(created, lockedCoins)
		if verr != nil {
			return g, fmt.Errorf("failed to create permanent locked account: %w", verr)
		}
		k.accountKeeper.SetAccount(ctx, plva)

	case *authtypes.BaseAccount:
		// x/auth a deja cree ce compte au genesis (il figure dans
		// app_state.auth.accounts). On le CONVERTIT sur place en
		// PermanentLockedAccount en conservant son numero de compte, sa sequence
		// et sa cle publique - creer un second compte ecraserait ces champs.
		plva, verr := vestingtypes.NewPermanentLockedAccount(existing, lockedCoins)
		if verr != nil {
			return g, fmt.Errorf("failed to convert existing base account to permanent locked account: %w", verr)
		}
		k.accountKeeper.SetAccount(ctx, plva)

	case *vestingtypes.PermanentLockedAccount:
		// Aller-retour export -> import: x/auth a restaure le PLVA et x/bank son
		// solde. Refinancer viderait la reserve une deuxieme fois.
		fund = false

	default:
		return g, fmt.Errorf(
			"grantee %s already exists as %T; a valgrant seat requires a fresh account or a base/permanent-locked account",
			g.Grantee, existing,
		)
	}

	source := "genesis_reserve"
	if fund {
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, granteeBz, lockedCoins); err != nil {
			return g, fmt.Errorf("failed to send locked principal from pool: %w", err)
		}
		if !gasCoins.IsZero() {
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, granteeBz, gasCoins); err != nil {
				return g, fmt.Errorf("failed to send gas allowance from pool: %w", err)
			}
		}
	} else {
		source = "genesis_prefunded"
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if out.IssuedHeight == 0 {
		out.IssuedHeight = uint64(sdkCtx.BlockHeight())
	}
	if out.IssuedTime == 0 {
		out.IssuedTime = sdkCtx.BlockTime().Unix()
	}
	sdkCtx.EventManager().EmitEvent(sdk.NewEvent(
		"valgrant_issued",
		sdk.NewAttribute("grantee", g.Grantee),
		sdk.NewAttribute("locked_amount", lockedCoins.String()),
		sdk.NewAttribute("gas_allowance", gasCoins.String()),
		sdk.NewAttribute("source", source),
	))

	return k.seedGrantShares(out, locked), nil
}

// seedGrantShares fills the per-validator granted-share ledger for a genesis seat.
//
// POURQUOI (patch #5): reconcileGrantShares (hooks.go) n'AUGMENTE jamais
// GrantedShares - une hausse des parts a grant.ValidatorOp est par construction du
// self-bond libre du beneficiaire. Un siege ne au genesis avec GrantedShares vide
// resterait donc a 0 pour toujours et le clawback de gouvernance ne pourrait
// RIEN reprendre sur le principal delegue: il reclame exactement
// min(GrantedShares, parts vivantes a grant.ValidatorOp).
//
// La valeur semee est le principal verrouille lui-meme: au genesis la premiere
// auto-delegation d'un validateur neuf se fait au taux 1 (parts == jetons), donc
// le gentx du siege mintera exactement LockedAmount parts. Et la valeur est
// AUTO-CORRIGEE a la baisse par le hook: si le gentx ne delegue que D < L, le hook
// voit nowShares = D < tracked = L et decremente GrantedShares a D. Semer haut est
// donc sur dans les deux sens (sur-decrementer ne fait que sous-reclamer, la
// fondation absorbe; sous-decrementer saisirait des parts libres).
//
// Une valeur granted_shares explicitement ecrite dans le fichier de genese est
// TOUJOURS respectee (aller-retour export/import, ou siege dont on connait le
// taux de change reel).
func (k Keeper) seedGrantShares(g types.Grant, locked math.Int) types.Grant {
	if g.Status == "revoked" || g.ValidatorOp == "" {
		return g
	}
	if g.GrantedShares == "" && locked.IsPositive() {
		g.GrantedShares = math.LegacyNewDecFromInt(locked).String()
	}
	// Invariant du registre: GrantedShares <= TrackedShares.
	granted := parseDecOrZero(g.GrantedShares)
	tracked := parseDecOrZero(g.TrackedShares)
	if tracked.LT(granted) {
		g.TrackedShares = granted.String()
	}
	return g
}

func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx), Grants: []types.Grant{}}
	k.IterateGrants(ctx, func(g types.Grant) { gs.Grants = append(gs.Grants, g) })
	// 0x03: clawbacks still unbonding. Store iteration is key-ordered (grantee), so
	// the exported list is deterministic across nodes.
	k.IteratePendingClawbacks(ctx, func(pc types.PendingClawback) {
		gs.PendingClawbacks = append(gs.PendingClawbacks, pc)
	})
	// 0x04: latest decentralisation snapshot.
	if snap, ok := k.GetKPISnapshot(ctx); ok {
		s := snap
		gs.KPISnapshot = &s
	}
	return gs
}
