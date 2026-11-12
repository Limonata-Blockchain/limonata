# Ligne de build mainnet

Branche `mainnet-build-line`. Ce depot n'est PAS la chaine vivante: c'est le
binaire vise pour la genese du mainnet. Les faits ci-dessous sont MESURES, avec
le test ou la commande qui les prouve.

## 1. Ce binaire ne doit JAMAIS resynchroniser 10777 depuis le bloc 1

**Preuve:** `x/contest/types/genesis_live10777_test.go`
(`~/go-sdk/bin/go test -tags=test -run TestLiveChain10777 ./x/contest/types/`).

Le genesis de `limonata_10777-1` porte `app_state.contest.params` avec
`passkey_enabled: true` et AUCUN `passkey_rp_id` ni `passkey_allowed_origins`
(ces champs n'existaient pas a la naissance de 10777; le lien RP a ete pose plus
tard, en etat). Le `GenesisState.Validate()` fail-closed de cette ligne de build
refuse ce document:

```
passkey_enabled requires passkey_rp_id and at least one passkey_allowed_origins entry
```

`x/contest/keeper/genesis.go` remonte l'erreur, `x/contest/module.go`
(`AppModule.InitGenesis`) fait `panic(err)` DANS `InitChain`. Un noeud qui rejoue
10777 depuis la hauteur 0 avec ce binaire meurt avant le bloc 1.

Pour 10777, utiliser le binaire de la chaine vivante, ou un state sync. Un
genesis corrige (avec `passkey_rp_id` + `passkey_allowed_origins`) changerait le
hash du genesis: ce ne serait plus le meme reseau.

## 2. Sans le patch InitGenesis de x/valgrant, le noeud ne demarre pas

Le message du commit `9a06f79b` annonce un mauvais mode de defaillance ("le
mainnet naitrait avec UN SEUL validateur"). Rectifie par `91037f28` et dans
l'entete de `x/valgrant/keeper/genesis.go`. La verite, chaine d'appels verifiee
dans le SDK v0.54.3 epingle par `go.mod`:

1. le compte du siege n'existe pas,
2. ante de la gentx: `account <adresse> does not exist: unknown address`
   (`x/auth/ante/sigverify.go:636`),
3. `failed to execute DeliverTx for '<gentx>'` (`x/genutil/gentx.go:110`),
4. `panic(err)` dans `x/genutil/module.go:108`, a l'interieur d'`InitChain`.

Le noeud avorte a la hauteur 0. Il n'y a pas de chaine mono-validateur a
rejoindre. La lecture "un seul validateur" ne vaudrait que pour un genesis
portant `grants[]` SANS les gentx des sieges, ce qui n'est pas le cas d'une
ceremonie.

## 3. Le clawback valgrant n'est pas une garantie de reprise integrale

Corrige (HIGH-ERODE, commit `baacbdac`): un beneficiaire pouvait mettre
`GrantedShares` a zero en deleguant puis retirant son propre liquide au meme
validateur, et le clawback ne reprenait plus rien. La regle est desormais le
clamp `GrantedShares = min(GrantedShares, parts vivantes)`, c'est-a-dire une
imputation aux parts LIBRES d'abord - la meme politique que le
`TrackUndelegation` de `x/auth`. Sondes: `x/valgrant/keeper/audit_erosion_probe_test.go`.

**Limite qui subsiste, a ne pas masquer dans la communication:** les parts
REDELEGUEES hors de `grant.ValidatorOp` echappent a la reprise, qui ne touche que
`grant.ValidatorOp`. Suivre le grant a travers une redelegation demande le cote
destination du mouvement, qu'aucun hook de staking ne rapporte
(`BeginRedelegation` ecrit son enregistrement APRES que `Unbond` et `Delegate`
ont declenche leurs hooks). C'est un item de conception, pas un patch.

Formulation exacte de la garantie: le beneficiaire ne perd jamais plus que le
grant, et sa mise propre est preservee en VALEUR AGREGEE entre validateurs. La
promesse plus forte "ses parts propres A `grant.ValidatorOp` ne sont jamais
touchees" n'est plus vraie et ne doit plus etre annoncee.

## 4. Les params ne sont plus graves au bloc 1 (x/vpcap, x/gassponsor)

`x/vpcap` et `x/gassponsor` n'avaient AUCUN type Msg: leurs `RegisterServices`
etaient des no-op, donc les 4 params de vpcap et les 13 de gassponsor n'etaient
inscriptibles qu'a `InitGenesis`. Un mainnet ne avec `refill_daily_mint_cap: "0"`
(plafond de mint QUOTIDIEN illimite) n'aurait pas pu etre resserre sans une mise a
jour binaire coordonnee.

Ajoute: `proto/cosmos/evm/{vpcap,gassponsor}/v1/tx.proto` -> `MsgUpdateParams`
GOUVERNANCE SEULE (rejet si l'autorite n'est pas le compte du module gov; aucune
cle admin sur ces deux modules), `keeper/msg_server.go`, `types/codec.go`,
`RegisterServices` branche. Meme forme que `x/encmempool`: le message porte le
JSON des params (ces modules stockent leurs params en JSON, pas en proto), et le
handler rejoue la MEME validation qu'au genesis avant d'ecrire.

**Semantique de REMPLACEMENT et son piege.** Le JSON est decode dans une struct
Params ZERO: une proposition qui omet une cle la REMET A ZERO. Pour vpcap une cle
`enabled` omise ETEINT le plafond de pouvoir de vote; pour gassponsor un plafond
omis vaut `""` que le module lit comme ILLIMITE. `x/encmempool` a du poser un
cliquet a posteriori pour cette exacte classe de bug. Un cliquet serait faux ici
(la gouvernance doit pouvoir bouger ces valeurs dans les DEUX sens), donc la
regle est: `types.RequireCompleteParamsJSON` REFUSE une charge incomplete - tous
les champs doivent etre presents, et une cle inconnue (faute de frappe) est
refusee aussi. Aucune valeur n'est restreinte; il faut seulement les enoncer, la
ou les votants les lisent.

`x/valgrant.MsgUpdateParams` gagne `foundation_validators` (il n'ecrivait que
`admin`, donc la liste servant a la KPI de pouvoir de vote de la fondation etait
figee au genesis). Meme semantique de remplacement: une proposition qui veut
garder la liste doit la re-enoncer. Note de rejeu dans le `.proto`.

## 5. ExportGenesis: les etats qui manquaient

Non bloquant pour une genese neuve, bloquant a la PREMIERE migration par export
d'un mainnet vivant. Ajoute avec un test aller-retour export -> import par module
(`*/keeper/genesis_roundtrip_test.go`):

| module | prefixes ajoutes a l'export | ce qui etait perdu |
|---|---|---|
| `x/sponsorpool` | `0x01` escrow, `0x02` contributions | les depots des developpeurs. Les pieces sont dans le compte du gas pool (exporte par x/bank), mais la comptabilite disant A QUI elles sont et QUEL contrat elles financent n'existe QUE la: escrows a zero, plus aucun retrait possible, fonds absorbes en silence. |
| `x/valgrant` | `0x03` PendingClawback, `0x04` KPISnapshot | un clawback de gouvernance dont le principal est encore en desdelegation n'existe QUE sous `0x03` jusqu'au balayage EndBlock (jusqu'a 21 jours plus tard). Export dans cette fenetre = les pieces qui murissent restent chez le beneficiaire. |
| `x/contest` | `0x03` DevStats, `0x04` TesterPoints, `0x05` DailyUAW, `0x06` SnapshotDone | le classement lui-meme, c'est-a-dire la carte des versements. Et `SnapshotDone` est un verrou a sens unique: le perdre DEGELE en silence un concours termine. |
| `x/vpcap` | `0x02` LastSent | la base de diff. Quand le plafond est actif, vpcap POSSEDE tout l'ensemble `ValidatorUpdates`; sans la carte, un validateur parti reste dans l'ensemble CometBFT a sa puissance d'avant plafond. |

Piege documente pendant ce travail: dans `x/sponsorpool`, `Keeper.Reserve` debite
l'escrow d'un contrat mais NE touche PAS les contributions. Une contribution
superieure a l'escrow restant est donc un etat NORMAL, pas une insolvabilite;
`Validate()` ne doit surtout pas la refuser (`Withdraw` borne deja le versement a
`min(contribution, escrow restant)`).

## 6. Garde vote-extensions au genesis (x/encmempool)

`MsgUpdateParams` refusait deja d'armer le DKG TRANSPARENT sur une chaine vivante
dont les vote extensions ne sont pas programmees. Rien ne refusait la meme
configuration dans un fichier de GENESE, qui aurait fige la chaine a la premiere
ouverture de DKG.

`GenesisState.Validate()` ne peut pas porter ce controle: c'est une fonction pure
sans params de consensus, et `AppModuleBasic.ValidateGenesis` ne recoit que
`app_state.encmempool`, jamais la section `consensus` du document. Et
`sdk.Context.ConsensusParams()` est INUTILISABLE dans `InitChain`: dans
cosmos-sdk v0.54.3, `baseapp/state.Manager.SetState` n'appelle jamais
`WithConsensusParams` (les params ne sont poses sur le contexte que dans
FinalizeBlock / PrepareProposal / ProcessProposal), donc le contexte y porte la
valeur ZERO et le controle rejetterait toute genese transparente.

Donc: fonction PURE ajoutee dans un fichier NEUF
(`x/encmempool/types/genesis_ve_guard.go`), appelee depuis `evmd/app.go`
`InitChainer` ou `req.ConsensusParams` est disponible. Tous les fichiers
PREEXISTANTS de `x/encmempool` restent octet pour octet identiques a `effa377d`
(verifiable: `git diff effa377d -- x/encmempool/` ne montre que des ajouts de
fichiers). Le fragment `app_state.encmempool` du genesis vivant de 10777 est
`{"params":{"reveal_delay":2,"max_reveal_window":200},...}`: ni `dkg_enabled` ni
`dkg_transparent`, donc la garde y est un no-op (test
`TestGenesisVoteExtensions_Live10777IsUnaffected`).

## 7. Comment compiler et tester

```bash
# binaire (toujours vers /tmp, jamais par-dessus ~/go/bin/limonatad)
cd /home/prepauto/mainnet-build-wt/evmd
~/go-sdk/bin/go build -buildvcs=false -o /tmp/evmd-mainnet ./cmd/evmd

# suite complete (le tag est OBLIGATOIRE)
cd /home/prepauto/mainnet-build-wt
~/go-sdk/bin/go test -tags=test ./...
```

`~/go-sdk/bin/go` et non le `go` du PATH. `evmd` est un module imbrique
(`replace cosmos/evm => ../`).

## 8. Invariants a ne pas casser

- `x/encmempool` doit rester octet pour octet identique a `limonata/main`: toute
  divergence casse le rejeu de la chaine vivante. Les seuls ajouts tolerables
  sont des FICHIERS NEUFS jamais appeles depuis un chemin de consensus (voir la
  section 6); `git diff effa377d -- x/encmempool/` doit rester sans modification
  de fichier existant.
- Aucun amont git sur cette branche (retire deliberement).
- Les 27 variables `DECISION_REQUISE` de `~/limonata-genesis.sh` bloquent le mode
  mainnet volontairement: ne jamais les remplir d'une valeur inventee.
