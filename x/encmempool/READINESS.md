# Readiness v0.3.0 - DKG validateur + mempool chiffre + EncExec

Date: 2026-07-09. Branche `limonata-dkg-transparent`. Ce document est le go/no-go FACTUEL pour
activer ce module en prod dans la 0.3.0. Verdict d'abord, preuves ensuite.

---

## Verdict

- **Shipper le CODE dans le binaire 0.3.0, params OFF (gated)** : **GO.** Le binaire build, charge, et
  le module reste inerte tant que `EncEnabled`/`DkgEnabled`/`EncExecEnabled` sont false. Zero risque.
- **ACTIVER le DKG validateur complet + EncExec en prod maintenant** : **NO-GO.** Blockers concrets
  ci-dessous. Deux d'entre eux ne sont pas negociables (topologie + audit firme).

---

## Ce qui EST verifie (vert, teste)

1. **Le chemin complet active marche end-to-end sur l'app reelle** quand la topologie le permet.
   `evmd/tests/encmempool_readiness` : DKG (committee = validateurs bondes) -> installation d'une cle
   seuil -> une VRAIE tx EVM signee, chiffree a cette cle -> submit -> shares DLEQ -> BeginBlock
   **dechiffre ET execute** la tx (destinataire credite, nonce incremente, sender debite value+gas).
2. **La crypto DKG multi-parti (3-sur-2)** : dealer/complaint/finalize -> cle agregee -> dechiffrement,
   au niveau keeper (`x/encmempool/keeper` TestOnChainDKG_FinalizeAndDecrypt).
3. **L'execution EVM des tx dechiffrees** : fees exacts, nonce, pas de replay, gas borne, pas de
   depassement, precompiles bloquees a toute profondeur, net-cap applique
   (`evmd/tests/encmempool` TestReinjection, 8 sous-tests).
4. **Le durcissement des 12 rounds d'audit** : replay/PoK, maturity gate, genesis, byzantine legacy,
   var-env consensus (etait CRITICAL), etc. Suites completes vertes.

---

## Blockers a fermer AVANT d'activer

### 1. Concentration du stake - BLOCKER MECANIQUE (le code lui-meme refuse)
Le garde `CommitteeConcentrationBreached` fait que `SubmitEncrypted` **rejette toute soumission** des
qu'un operateur possede >= le seuil de points de dechiffrement. Ton stake est ~70% sur un validateur,
le seuil est ~66.7%. Donc **aujourd'hui, active, le module rejette 100% de son trafic** - et c'est
volontaire : il refuse de vendre une confidentialite que la topologie ne fournit pas (le whale
dechiffre seul). Preuve : `TestSubmitEncrypted_FailsClosedOnConcentratedCommittee`.
**A faire : decentraliser le stake sous le seuil (aucun operateur/coalition proche de 2/3 des points).**

### 2. Audit firme externe sur EncExec - NON NEGOCIABLE
EncExec execute des tx EVM **attaquant-controlees dans BeginBlock**, hors du pipeline ante normal.
J'ai ferme les trous connus (precompiles a toute profondeur, ante, fees), mais faire tourner du code
attaquant arbitraire dans le consensus sur une chaine live sans audit professionnel = le plus gros
risque de halt/exploit. **A faire : audit d'une firme crypto/consensus sur `keeper/evm_exec.go` + le
chemin de decrypt/execute.**

### 3. Flux DKG multi-NOEUD ABCI++ - PROUVE sur un vrai reseau 4-noeuds (2026-07-09)
Un testnet throwaway de 4 validateurs (stake equilibre, chain-id dkgtest_20777-1, isole de la chaine
live) a fait tourner le binaire hardened avec DKG transparent + vote extensions actives. RESULTAT :
round ouvert (h4 : dkg_round_opened + dkg_ve_consumed = dealings/shares circulent entre noeuds via
ABCI++), **DKG FINALISE (h18 : epoch 1, QUAL=[1,2,3,4] les 4 validateurs, cle seuil installee,
threshold=86)**. Les 4 noeuds en SYNC PARFAITE (meme height, catching_up=false, ZERO CONSENSUS
FAILURE) => deterministe, pas de fork. Une seule convergence propre, pas de re-run. **Le flux ABCI++
multi-noeud tient.** (Test de CONVERGENCE, EncExec OFF pour eviter l'exigence de bond ; le
decrypt+execute est prouve par le test de readiness single-node. Un run multi-noeud AVEC
decrypt+execute reste le complement optionnel.)

### 4. Items de design deferres (niveau protocole)
- **Censure-proposer** : un proposer peut omettre l'injection ; la liveness DKG en depend (limite
  ABCI++). Borne par le force-advance + le cap de fenetre, pas ferme.
- **Poison-offline** : detection + rekey-sante seulement ; l'exclusion automatique est un changement
  consensus non fait (ta decision).
Ces deux-la devraient etre valides/tranches avec la firme.

---

## Path to GO (ordre)

1. **Decentraliser le stake** sous le seuil (sinon le code refuse - blocker #1). C'est la premiere
   etape, sans elle rien d'autre ne compte.
2. **Run multi-noeud** (4-5 validateurs reels) : prouver le DKG ABCI++ end-to-end sur le reseau
   (blocker #3).
3. **Audit firme externe** sur EncExec + le consensus (blockers #2 et #4), avec `AUDIT_HANDOFF.md`.
4. **Fermer** ce que la firme demande (censure-proposer, auto-rekey si retenu).
5. **Activer par gouvernance** (le chemin baked deterministe, pas d'env-var - c'est deja le seul
   chemin de prod depuis le fix round-12 #1).

Tant que 1-4 ne sont pas faits : **ship le code gated OFF dans 0.3.0**, active plus tard par gov.

---

## Ce qui N'A PAS ete teste (honnete)

- Le flux DKG **sur un vrai reseau multi-noeud** (seulement simule en process).
- L'activation via un **vrai upgrade gouvernance** de bout en bout sur un testnet live.
- Le comportement **sous charge reelle** (sybil finance, censure active) sur un reseau.
- Le chemin **transparent stake-weighted** end-to-end avec EncExec (le test de readiness utilise le
  chemin DECLARE non-pondere ; le stake-weighted est teste au niveau keeper mais pas +EncExec+reseau).
