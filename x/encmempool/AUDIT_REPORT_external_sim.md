# Security Audit Report — Limonata Transparent DKG + Encrypted (Anti-MEV) Mempool

**Module:** `x/encmempool` (on-chain validator DKG, threshold ElGamal, commit-reveal encrypted mempool)
**Codebase:** `~/cosmos-evm-dkg` (branch `limonata-dkg-integration`)
**Review type:** Internal adversarial security audit (simulated external engagement)
**Report date:** 2026-07-05
**Classification:** Confidential — pre-enable decision input

---

## 1. Executive Summary

This report presents the findings of a full-surface security audit of the Limonata transparent Distributed Key Generation (DKG) subsystem and the threshold-encrypted anti-MEV mempool it protects. The subsystem's job is to keep pending transactions confidential until execution (defeating front-running / MEV) while producing a validator-held threshold decryption key entirely on-chain, transparently, and deterministically.

Across five domains we raised 23 candidate issues, refuted 4 during verification, and **confirmed 19 findings**: **3 CRITICAL, 4 HIGH, 5 MEDIUM, 6 LOW, and 1 INFO (positive assurance)**.

### Overall verdict: **NO-GO to enable.** Dormant merge is acceptable.

The distinction is load-bearing and is the single most important conclusion of this report:

- **Merging the code in a dormant state (`EncEnabled = false`, DKG idle) is SAFE.** The committed-write / consensus path was independently verified fork-safe (INFO-1): canonical ordering before writes, no map-iteration into state, no wall-clock/rand/float on the commit path, saturating deadline math, exact bigint stake math, and pure recompute fallbacks. No first-order app-hash divergence was found. The confirmed defects live almost entirely on the **enabled** execution path (PreBlock/BeginBlock/EndBlock DKG and decrypt bodies) and on **governance-reachable parameter space**; none of them fires while the feature is switched off.

- **Enabling the feature on the live chain today is NOT safe.** Three independent CRITICAL issues each individually break a core guarantee:
  1. a **cryptographic full break** of confidentiality under a Byzantine minority (DLEQ deterministic-nonce reuse extracts a keyper's persistent encryption private key on-chain — CRIT-1);
  2. a **sybil-sustained consensus DoS** in PreBlock that pins `FinalizeBlock` at its verify ceiling (CRIT-2);
  3. an **O(t²) decrypt path in BeginBlock** that scales block time with backlog and threshold size to a practical halt (CRIT-3).

  Layered on top, the deployed **stake topology itself voids the confidentiality claim**: the security proof assumes no single party holds ≥ ~54.7% of committee stake, but Limonata operates a ~70%-VP validator (MED-3 / MED-1). Against its own largest block producer — precisely the most capable MEV extractor — the mempool provides *zero* confidentiality today, independent of any code fix.

**Bottom line:** the design is promising and the deterministic core is sound, but the enable path carries a cryptographic break, three DoS/liveness halt-class issues, several governance foot-guns that can brick the feature from a single valid parameter, and a deployment-topology mismatch that nullifies the headline guarantee. The must-fix set in Section 5 is a prerequisite to any enable decision, and a real third-party firm engagement (Section 6) should precede mainnet exposure.

---

## 2. Scope & Methodology

### 2.1 Scope — five domains

1. **Cryptography** — DLEQ/Chaum-Pedersen proofs, Feldman commitments, threshold ElGamal, share encryption (ECDH), nonce derivation, complaint proofs.
2. **Consensus & determinism** — vote-extension ingest, `ExtendedCommitInfo` injection, PreBlock/BeginBlock/EndBlock bodies, app-hash fork safety, recover semantics.
3. **Liveness & DoS** — per-block crypto work ceilings, decrypt scheduling, finalize cost, sybil admission control, grace-window behavior.
4. **Protocol & state machine** — DKG round transitions, complaint round, rekey triggers, genesis import/export, epoch lifecycle and pruning.
5. **Governance & parameters** — validity bounds vs. safe bounds for every operator-tunable parameter (share budget, committee size, windows, delays).

### 2.2 Method

Independent code review of the module followed by adversarial verification of each candidate finding against the source. Every finding was traced to concrete file:line evidence and, where it asserts an attack, to a reachable call path from a Byzantine or governance actor. Findings that could not be substantiated against the code were **refuted and dropped** (4 of 23). Surviving findings carry one of two verification verdicts:

- **CONFIRMED** — the defect and its reachability were verified in source (15 findings).
- **PLAUSIBLE** — the defect is real and evidenced, but full exploit reachability or exact impact bound depends on assumptions we could not close in-audit (4 findings). These are ranked conservatively and flagged.

Performance/DoS claims cite the module's own instrumentation where available (e.g. the measured 10.3s block at 46 in-flight ciphertexts, and ~18s/ciphertext decrypt at governance-max threshold) and otherwise derive asymptotic work bounds from the code.

---

## 3. Findings by Severity

### CRITICAL

---

#### CRIT-1 — DLEQ deterministic nonce omits the index the challenge binds → keyper enc-private-key extraction (crypto) · CONFIRMED
**Location:** `x/encmempool/dkg/proof.go:164` (`deriveDLEQNonce`) vs `proof.go:137` (`dleqChallenge`); reached via `evmd/dkg_voteext.go:349` (`ProveDecryptShare`, `Xi=ek.Priv`, `A=enc.A`, `Index=p`).

**Impact — full confidentiality break under a Byzantine minority.** The Chaum-Pedersen response is `z = k + c·x`. The challenge `c = H(index, A, D, Y, T1, T2)` **binds** the index, but the deterministic commitment nonce `k = H(x, A, D, Y)` does **not**. Two proofs over the same secret scalar `x` and ephemeral `A` but different `index` therefore share `k` while `c1 ≠ c2`, and any observer recovers `x = (z1 − z2)/(c1 − c2)`. This is directly reachable in the framing-resistant complaint path: `buildDkgComplaints` proves `S = x·A` with `x = ek.Priv` (the node's *one persistent* encryption private key, reused across every eval point it owns) and `A = enc.A` (dealer-controlled, only shape-checked — `ValidCompressedPoint`, `keeper/voteext.go:530`, not uniqueness-checked). A single vote extension may carry multiple complaints, each with a `DleqProof` at a distinct `index=EvalPoint`. The honest victim thus publishes two nonce-reusing proofs **in its own signed extension**, leaking its enc private key on-chain. With that key an attacker decrypts every enc-share addressed to the victim, reconstructs the victim's Shamir shares for the epoch, and by harvesting a few honest members' keys pushes a <1/3-stake coalition over the decrypt threshold — unsealing the entire mempool.

**Recommendation.** Enforce the invariant *identical nonce ⇔ identical challenge*: derive `k` over the exact transcript the challenge commits to — add `index` (and ideally epoch + a caller domain tag) into `deriveDLEQNonce`, mirroring `dleqChallenge`. As defense-in-depth, enforce enc-share `A` uniqueness per dealing at ingest, and reconsider revealing the raw ECDH point `S` in complaints (it is a chosen-input static-DH oracle on the victim's key). Add a regression that produces two proofs with equal `(x,A)` and distinct `index` and asserts `k` differs and `x` is unrecoverable.

**Status:** Open — hard blocker.

---

#### CRIT-2 — Sybil-sustained PreBlock DLEQ-verify DoS; per-submitter rate limit cannot bound O(cap·S) per-block work (consensus/liveness) · CONFIRMED
**Location:** `x/encmempool/keeper/keeper.go:320` (`maxEncSubmitsPerBlockPerSubmitter = 4`, per-submitter); `keeper/voteext.go:642,818` (`maxVerifyCiphertextsPerBlock = 128`, `globalCeiling = 128·S`); `keeper/msg_server.go:190`.

**Impact.** `ingestDecryptSharesBounded` runs in **PreBlock** (inside `FinalizeBlock`, consensus-blocking, serial) and admits up to `maxVerifyCiphertextsPerBlock (128) · S` first-time O(t) DLEQ verifications per block (~32,768 at default `S=256`; ~262,144 at governance-max `S=2048`). The only per-block admission control is keyed **per submitter** at a fixed 4/block, and submitter identity is a free, unauthenticated account string. A sybil fleet keeps the oldest-128 processed set perpetually full, pinning `FinalizeBlock` at its ceiling. The module's own measurement shows 10.3s blocks at only 46 in-flight ciphertexts on an unloaded 56-core host; at governance-max S this is minutes/block — a practical halt of the anti-MEV liveness property (timely decrypt-within-grace).

**Recommendation.** Bound the **cross-ciphertext** work per block by a small constant `K_max` (drain the oldest few maturing ciphertexts to completion with a guaranteed heal-before-grace scheduler), making total work `O(S·K_max)` with `K_max` small enough that block time stays flat. Add a **global** per-block maturing-ciphertext admission limit (not just per-submitter) and price/stake-gate submitter identity so a sybil fleet cannot sustain inflow. Re-audit under a sustained (non-stopping) attacker.

**Status:** Open — hard blocker.

---

#### CRIT-3 — Decrypt path recomputes uncached O(t) `SharePubKey` per share → O(t²)/ciphertext in BeginBlock (liveness) · CONFIRMED
**Location:** `x/encmempool/keeper/abci.go:540` (`recoverSharedSecret → dkg.RecoverVerified`); `dkg/proof.go:245` (`SharePubKey` per partial, uncached); `abci.go:167,274` (`maxDecryptAttemptsPerBlock = 2048`).

**Impact.** `decryptMatured` runs in **BeginBlock** (consensus) on every node. For each maturing ciphertext, `RecoverVerified` computes `Y_index = SharePubKey(...)` — an O(t) Horner of variable-base scalar-mults — for **each** of the `t` partials, i.e. **O(t²) EC ops per ciphertext**. It ignores the `getShareKeyCache` the module already populates at ingest (`voteext.go:927`) and redundantly re-DLEQ-verifies shares already verified at ingest. `selectFairDecrypts` admits up to `maxDecryptAttemptsPerBlock = 2048` recover attempts with no flat cap on per-block crypto work, so block time scales `O(#maturing · t²)`. Governance may set `DkgShareBudget = 2048` (valid), pushing `t` to ~1238–1350; the module measured ~18s/ciphertext at that setting. Even at default `S=256` (`t=155`), a backlog of a few dozen ciphertexts stalls blocks tens of seconds. Practical halt / severe decrypt-path liveness break.

**Recommendation.** Route recover through the existing precomputed Y-cache instead of recomputing `SharePubKey`; better, skip re-verification of shares already DLEQ-verified at ingest and perform only the Lagrange combine of `t` stored shares (O(t), not O(t²)). Cap total per-block recover work by a constant EC-op budget (not a ciphertext count), and/or lower `maxDkgShareBudget`. Add a regression asserting per-block decrypt CPU is bounded independent of S and backlog.

**Status:** Open — hard blocker.

---

### HIGH

---

#### HIGH-1 — Byzantine QUAL dealer poisoning only offline/colluding-owned points survives the complaint round and bricks epoch decryption (consensus) · CONFIRMED
**Location:** `evmd/dkg_voteext.go:300-361` (`buildDkgComplaints`); `keeper/voteext.go:430-502` (`IngestComplaintFromVE`); `keeper/dkg.go:454-523` (`finalizeRound` disqualification).

**Impact.** The complaint channel disqualifies a dealer only when an **online** honest member that **owns** a poisoned eval point files a justified complaint in the `(DealDeadline, ComplaintDeadline]` window. A Byzantine QUAL dealer can seal valid shares to points owned by honest online members and garbage shares only to points owned by **offline** members or its own <1/3 coalition. No honest complaint is generated, the dealer stays in QUAL, and its bad polynomial is summed into the aggregate key at finalize. Honest members holding victimized points then cannot derive correct decryption shares; the epoch's ciphertexts never reach `t` valid shares and strand after the 32-block grace. DLEQ-at-recover prevents *wrong* decryption but converts it to a hard liveness strand, with no on-chain recourse (the deferred "MF4" derive-belt / early-rekey is not implemented).

**Recommendation.** Implement MF4 (derive-belt + early-rekey on repeated decrypt-share shortfall) so a poisoned-but-uncomplained dealer is caught at the decrypt layer and the epoch re-genesises against the healthy set. Alternatively, require each dealer's full enc-share set to be publicly verifiable against its Feldman commitments **at ingest**, catching a structurally inconsistent seal without needing an online victim. Design change — must be externally audited before enable.

**Status:** Open — structural; requires design + external audit.

---

#### HIGH-2 — Injected `ExtendedCommitInfo` has no aggregate size cap; a stake minority bloats every block or silently stalls DKG (consensus) · CONFIRMED
**Location:** `evmd/dkg_voteext.go:433-436` (PrepareProposal fallback when blob ≥ `MaxTxBytes`); `types/voteext.go:32` (`VoteExtMaxBytes = 1<<20`); `dkg_voteext.go:372-374,396` (per-VE 1 MiB cap only).

**Impact.** The proposer injects the whole H-1 `ExtendedCommitInfo` (extensions from *every* precommitting validator) as `Txs[0]`. `VerifyVoteExtension` caps each extension at 1 MiB but nothing caps the aggregate. Any bonded validator can pad its own signed extension to ~1 MiB. With a few dozen validators, a <1/3 coalition padding to the cap either (a) bloats every committed block by tens of MB, or (b) exceeds `MaxTxBytes`, whereupon `PrepareProposal` **silently falls back** to the plain handler (no injection) on every honest proposer — the DKG consumes nothing, no dealings/shares/complaints land, and the mempool never decrypts for as long as padding continues. Liveness/availability DoS reachable by a stake minority.

**Recommendation.** Shrink `VoteExtMaxBytes` to the true honest maximum (committee-capped dealing + `VoteExtShareCap` shares + ≤n complaints is tens of KB at default S; size against `EffectiveShareBudget`, not a flat 1 MiB). Add an aggregate injected-commit budget and **drop over-budget individual extensions deterministically** (canonical operator order) rather than skipping injection entirely. Tighten `VerifyVoteExtension` structural caps to param-derived maxima.

**Status:** Open.

---

#### HIGH-3 — `finalizeRound` `PrecomputeShareKeys` is a single synchronous ~30s EndBlock burst at gov-max S (liveness) · CONFIRMED
**Location:** `keeper/dkg.go:501` (`PrecomputeShareKeys` at finalize) → `dkg.go:255` → `dkg/onchain.go:196` (`ShareKeysCompressedUpTo` loops `SharePubKey` S times, O(S·t)).

**Impact.** `finalizeRound` runs inside `EndBlockDKG` (consensus). On success it computes `Y_1..Y_S` via S Horner evaluations of degree `t` = O(S·t) variable-base scalar-mults, as one synchronous call on every node in a single block. The in-code comment (`dkg.go:253`) calls this a "~1-2s finalize cost that a future change should chunk" — but no chunking exists and the true cost is ~15-30× larger (~30s at `S=2048`). Finalize occurs **every epoch**: first start, every member change, every stake-drift rekey, every successful retry. A ~30s EndBlock blows CometBFT round timeouts across the set, causing missed rounds and a crawling/stalling chain on each rekey. `DkgShareBudget = 2048` (valid even with the default 16-seat committee) arms this permanently.

**Recommendation.** Implement the chunked precompute the comment promises (build the Y-cache incrementally over the first blocks of the new epoch; the on-the-fly `SharePubKey` fallback keeps verification correct meanwhile); or compute `Y_1..Y_S` with a single O(S+t) simultaneous evaluation instead of S independent O(t) Horners; or compute lazily-and-memoize. Lower `maxDkgShareBudget` until one finalize fits comfortably in a block. Add a regression bounding finalize CPU.

**Status:** Open.

---

#### HIGH-4 — `DkgShareBudget` up to 2048 is a valid config making finalize O(S²) one-shot and per-block verify O(cap·S) (governance) · CONFIRMED
**Location:** `types/types.go:578` (`maxDkgShareBudget = 2048`), `:613`; `keeper/dkg.go:255-266,501` (unchunked `PrecomputeShareKeys` in EndBlock); `keeper/voteext.go:818` (`globalCeiling = maxVerifyCiphertextsPerBlock · S`).

**Impact.** With `DkgShareBudget = 2048` (valid; coupling only needs committee ≤ 256), finalize computes ~O(S²) ≈ 2.8M EC ops in a single EndBlock inside consensus at every finalize/rekey, and the per-block decryption-share DLEQ-verify ceiling is `128 · S` ≈ 262k verifies/block. Governance can therefore push `FinalizeBlock`/`PreBlock` into multi-second-to-minute territory **at a valid parameter**, risking CometBFT proposal timeouts and cascading missed-block instability — worst-case at each rekey (frequent if `DkgMaxEpochBlocks` is also small). This confirms the internally-tracked HIGH-U on the finalize axis, independently of the per-block-verify axis (HIGH-3, CRIT-2).

**Recommendation.** Lower `maxDkgShareBudget` to a value whose finalize precompute and per-block verify are provably sub-second on target hardware, OR chunk `PrecomputeShareKeys` (the verify fallback keeps it correct) AND replace `maxVerifyCiphertextsPerBlock = 128` with a small `K_max`. Do not enable while S can be set to 2048.

**Status:** Open — governance guardrail.

---

### MEDIUM

> **Note on MED-1 / MED-3:** these are the same root cause (no per-member eval-point cap → a whale owns ≥ t points) viewed through the crypto lens (MED-1, PLAUSIBLE on exact bound) and the deployed-topology lens (MED-3, CONFIRMED against Limonata's ~70%-VP validator). They are reported separately to preserve both the general design gap and its concrete live-chain instantiation; the enable gate in Section 5 addresses both.

---

#### MED-1 — No maximum cap on per-member eval points: a single validator above the ~54.7% decrypt bar decrypts the whole mempool alone (crypto) · PLAUSIBLE
**Location:** `keeper/stakeweight.go:56-64` (policy: no max cap, "decrypt alone"), `:263` (`t = floor(2S/3) − n + 1`); `keeper/voteext.go:222-241` (`DecryptingSetMeetsStake` strict-majority gate); `keeper/abci.go:499-540`.

**Impact.** Threshold security rests entirely on "no single party owns ≥ t eval points." `AllocateEvalPoints` applies faithful proportional apportionment with **no maximum cap** (explicit policy), and the proven decrypt bar is only `f > 2/3 − 2n/S` (~54.7% of committee stake at defaults). A validator above that bar owns ≥ t points, holds ≥ t Shamir shares, and can (a) recover `x·A` for every in-flight ciphertext unilaterally and offline, and (b) Lagrange-interpolate the master secret `msk`, decrypting all current and future epoch ciphertexts. The on-chain stake-majority gate is trivially met by such a whale. This is not hypothetical on Limonata's topology (MED-3).

**Recommendation.** Confidentiality against a specific validator cannot exceed `1 − (its committee-stake fraction)`; with a >54.7% validator it is zero. This is a design decision, not a tweak: cap per-member points strictly below t (forces redesign of the liveness math), enforce a max committee-stake share per operator, or explicitly scope the security claim and gate enable on it holding. At minimum, block enable while any member's allocation ≥ t.

**Status:** Open — design/deployment gate.

---

#### MED-2 — Finalized-but-undecryptable epoch has no recovery/re-genesis trigger → permanent soft-brick (protocol) · PLAUSIBLE
**Location:** `keeper/endblock.go:129-218` (rekey switch); `keeper/abci.go:327` (strand-drop); `keeper/dkg.go:483` (`Failed` only set at finalize); `keeper/msg_server.go:197-204` (new ct stamps active epoch).

**Impact.** The rekey switch fires only on (a) `MembersHash` change, (b) stake-drift/cadence (both default-off), or (c) `Status==Failed`→retry. A round that **finalizes** (`Status=Active`) but whose honest online committee cannot assemble ≥ t decryptable points is never retired — not `Failed`, membership unchanged, drift off. `Status = DkgStatusFailed` is only ever set inside `finalizeRound`; nothing demotes an already-Active epoch. Meanwhile `SubmitEncrypted` keeps stamping every new ciphertext to the dead epoch, and all strand after grace. The feature wedges indefinitely with no automatic recovery while still silently dropping user submissions. Two otherwise-transient faults become permanent bricks: (i) the HIGH-1 uncomplained-poison dealer; (ii) members that stay bonded but stop serving shares past grace.

**Recommendation.** Add a decryption-health rekey trigger: if the Active epoch accrues N consecutive `encmempool_decrypt_stranded` maturities, or produces no successful decrypt within a bounded window, force a fresh round against the current set. Interim: ship a non-zero `DkgMaxEpochBlocks` default so cadence rekey caps any soft-brick to one epoch period. Consider allowing a post-finalize justified complaint to invalidate the epoch.

**Status:** Open.

---

#### MED-3 — A single party at ≥ ~54.7% stake owns ≥ t points and decrypts every ciphertext alone; guarantee void on Limonata's real ~70%-VP topology (protocol) · CONFIRMED
**Location:** `keeper/stakeweight.go:54-63` (no-max-cap policy), `:242-276` (`stakeThreshold`); `keeper/voteext.go:222` (`DecryptingSetMeetsStake`).

**Impact.** `AllocateEvalPoints` applies no maximum cap; the proven decrypt bar is `f > (t−n+1)/S ≈ 2/3 − 2n/S` (~54.7% at S=256, n=16, t=155). A 70% validator receives ~179-180 of 256 points (≥ 155), reconstructs the epoch master secret off-chain by itself, and sees every encrypted transaction before execution — the exact front-running capability the mempool exists to prevent. It also passes the on-chain stake-majority gate alone. The **safety proof only covers a ≤1/3-stake adversary**; Limonata operates a ~70%-VP validator (per project state), so the deployed system provides **no confidentiality against its own largest block producer**. The design explicitly refuses both a max cap (harms liveness) and a min floor (enables dust-sybil), so this cannot be mitigated in-module — only by the deployed stake distribution.

**Recommendation.** Gate any ENABLE on a hard invariant that no single operator (and no realistically-colluding set) holds ≥ `(t−n+1)/S` of committee stake — enforced at round-open with a loud refuse-to-finalize or automatic committee-composition adjustment — and document that confidentiality is contingent on that distribution. **For Limonata's current 70%-VP reality the feature must not be enabled as-is.**

**Status:** Open — hard deployment blocker.

---

#### MED-4 — `InitGenesis`/`ExportGenesis` omit all threshold + DKG state → export/import silently strands every in-flight ciphertext and resets DKG to epoch 0 (protocol) · CONFIRMED
**Location:** `keeper/genesis.go:9-31` (only Params/Commits/Pending exported/imported).

**Impact.** Genesis handling covers only Params, Commits, Pending. It does **not** persist `EncTx`, `DkgRound`, `ActiveThresholdKey`, the epoch/global/per-submitter ref-counts, `CurrentEpoch`/`ActiveEpoch`, or the precomputed share-key cache. An `export → new genesis → restart` (genesis-migration upgrade) therefore: (1) silently drops every in-flight ciphertext with no strand event or `releaseEncTx` accounting; (2) resets the DKG to epoch 0; and (3) is internally inconsistent (plaintext commit/reveal state carries across while threshold state does not). On a confidentiality-critical chain this is silent loss of user ciphertexts at an upgrade boundary.

**Recommendation.** Export/import the full encrypted + DKG state (`EncTx`, shares, `DkgRound` records, `ActiveThresholdKey`, share-key cache, `CurrentEpoch`/`ActiveEpoch`, and all ref-counts — rebuilding counters on import), OR explicitly refuse `ExportGenesis` when `getGlobalEncCount > 0` and document that only in-place upgrades are supported while enabled.

**Status:** Open.

---

#### MED-5 — Over-large (but valid) `DkgDealWindow`/`DkgComplaintWindow` opens a round `EndBlockDKG` can never close or reopen — governance-unrecoverable freeze (governance) · CONFIRMED
**Location:** `keeper/endblock.go:110-118, 287, 299`; `types/types.go:527` (`maxDkgWindowBlocks = 10_000_000`), `:591` (`ValidateDkgWindows` accepts up to that).

**Impact.** The only transition out of `DkgStatusOpen` is `finalizeRound`, which `EndBlockDKG` runs solely at `h ≥ ComplaintDeadline`; `endblock.go:116` then `return`s for any Open pre-deadline round **before** the member_change, stake-drift, and retry cases can be reached. A round's deadlines are frozen at `openRound` from the params in effect at open. `DkgDealWindow`/`DkgComplaintWindow` are settable anywhere in `[1, 10_000_000]` blocks. A plausible fat-finger (blocks-vs-seconds, or `86400` thinking "one day") opens the round with a deadline up to ~230 days out. During that window no threshold key can finalize and, with `EncEnabled`, the mempool rejects all submissions ("no active threshold key yet"). Critically it is **unrecoverable by governance**: re-voting the window does not rewrite frozen deadlines; toggling `DkgEnabled` still hits the early-return; a validator-set change cannot trigger member_change re-genesis because line 116 returns first. Recovery needs waiting out the deadline or a coordinated binary/state upgrade.

**Recommendation.** Add an operational upper bound far below the 10M saturation guard (a few thousand blocks), and/or an escape hatch: before the line-116 early-return, allow member_change or an explicit gov "abort-open-round" to purge a far-deadline Open round, OR re-derive the open round's effective deadline from current params each block so a corrective vote can unstick it. At minimum, document that these windows are frozen at open.

**Status:** Open — governance guardrail.

---

### LOW

---

#### LOW-1 — `recover()`-in-consensus with un-branched store writes can mask a future node-local panic as a silent app-hash fork (consensus) · PLAUSIBLE
**Location:** `keeper/voteext.go:261-269` (`ConsumeVoteExtensions`); `keeper/endblock.go:81-89` (`EndBlockDKG`); `keeper/abci.go:36-45` (`BeginBlock`).

**Impact.** The consume / DKG-state-machine / decrypt bodies write directly to `k.store(ctx)` (no `CacheContext` branch) under a top-level defer-recover that emits an event and **continues**. A panic mid-body leaves partially-applied committed writes with no rollback. Safe *only* while every panic is a pure deterministic function of committed state (true today). But on the #1 fork-risk path this is fragile: any future change introducing a panic with a node-local trigger (OOM, a nil map populated only on some nodes, a lib that panics on an allocation limit) would make some nodes write full state and others partial state — a silent app-hash divergence instead of an honest halt.

**Recommendation.** Run each consensus body inside `ctx.CacheContext()` and `Write()` only on clean completion, so a recovered panic rolls back to a deterministic clean state on all nodes. Keep the event for observability. If rollback-on-panic is undesirable, prefer fail-stop halt over recovering with partial writes.

**Status:** Open — hardening.

---

#### LOW-2 — Injected `Txs[0]` pseudo-tx relies on decode failure to avoid execution (consensus) · CONFIRMED
**Location:** `evmd/app.go:1069-1072` (PreBlocker consumes `req.Txs` but does not strip `Txs[0]`); `evmd/dkg_voteext.go:462-491` (ProcessProposal strips only for inner validation).

**Impact.** ProcessProposal strips `Txs[0]` only for its own validation; the committed block still carries the `0x00`-marker blob at index 0, and baseapp's `FinalizeBlock` DeliverTx loop attempts to decode/run it. It fails (`0x00` is not valid protobuf) and yields an `ErrTxDecode` result deterministically every DKG block — benign for app-hash today, but brittle: it silently consumes a tx-result slot each DKG block and would break if a future SDK/CometBFT change treated an undecodable proposer-injected tx as fatal, or if a real tx could share the prefix. Determinism holds only incidentally.

**Recommendation.** Explicitly recognize and remove the marker tx before the normal execution loop (custom AnteHandler/txDecoder short-circuit or app-level FinalizeBlock filtering) rather than depending on decode-failure semantics. Assert marker invariants (exactly one, index 0).

**Status:** Open — hardening.

---

#### LOW-3 — Rejected decryption-share chaff has no negative cache; a Byzantine member re-charges DLEQ verifies every block during grace (liveness) · CONFIRMED
**Location:** `keeper/voteext.go:837,869,887` (per-block-only `seen[slot]` dedup); `:740` (`hasEncShareAt` short-circuits only stored/verified shares); `:749-761` (failed DLEQ verify is neither stored nor negative-cached — contrast the complaint path `SetComplaintRejected` at `:473,497`).

**Impact.** `ingestDecryptSharesBounded` dedups repeated slots only within a block and short-circuits only successfully-stored shares. A chaff share (valid shape, bad D/proof) fails, is not stored, and — unlike rejected complaints — leaves no record, so next block it re-passes classification and re-charges a full DLEQ verify. A Byzantine member re-sends chaff at every owned point for each of up to 128 grace-window ciphertexts, forcing `owned_points·128` verifies/block, sustained per grace window. Bounded (O(cap·S)) but at gov-max the global ceiling `128·2048 = 262,144` verifies ≈ 130s of ingest CPU in the worst burst; a 1/3-stake coalition sustains tens of seconds/block during grace. Amplifier on CRIT-2, not an independent permanent halt.

**Recommendation.** Negative-cache rejected decryption shares like complaints (a per-`(decryptHeight,seq,index)` rejected marker, expired when the ciphertext leaves state), so re-sent chaff costs an O(1) lookup; or persist the per-`(operator,ciphertext)` attempt count across blocks. Add a regression that identical chaff each block incurs at most one verify per slot per epoch.

**Status:** Open.

---

#### LOW-4 — Negative complaint cache keyed by `(epoch, against, accuser)` without eval-point blocks all future complaints from that accuser against that dealer (protocol) · PLAUSIBLE
**Location:** `keeper/dkg.go:96-111` (`SetComplaintRejected`/`HasComplaintRejected` key omits eval-point); `keeper/voteext.go:465, :497`.

**Impact.** `IngestComplaintFromVE` short-circuits on `HasComplaintRejected(epoch, against, accuser)` before per-eval-point logic. A member owns a *block* of points; if any complaint from accuser V against dealer D is ever verified-and-rejected (frivolous/framing) or hits the no-dealing path, the cache permanently drops **every** subsequent complaint from V against D — including a legitimate one about a *different* owned point where D actually cheated, making that fault uncomplainable. Currently defused only because the off-chain detector emits at most one complaint per dealer, targeting the first bad point and skipping valid ones. Latent coupling: any future detector change re-opens a byzantine-dealer brick channel, and on-chain safety should not depend on an off-chain node invariant.

**Recommendation.** Key the negative cache by `(epoch, against, accuser, evalPoint)`, or gate it behind an explicit per-point check; alternatively document and assert the detector invariant as a load-bearing on-chain assumption.

**Status:** Open.

---

#### LOW-5 — No minimum committee size or per-member share cap: `DkgMaxMembers = 1/2` collapses threshold encryption to single/dual-party decryption (governance) · CONFIRMED
**Location:** `types/types.go:604-608` (`ValidateDkgWindows` rejects only `DkgMaxMembers > 128`; no lower bound), `:640-645` (coupling only checks `S ≥ 8·members`); `keeper/stakeweight.go:56-63` (documented no-floor/no-cap, "whale can decrypt alone"); `keeper/voteext.go:165`.

**Impact.** `DkgMaxMembers` has only an upper bound. `=1` is valid (needs only `S≥8`): a single-member committee owns all S points and `t = floor(2S/3) ≤ S`, so it decrypts every ciphertext — threshold-of-one. With `=2` and realistic skew, an 80%-of-committee validator's ~0.8S points already exceed `t≈0.667S`. This mirrors Limonata's real topology, so a small committee cap hands unilateral front-running to the top validator with a perfectly valid governance param — the strongest possible confidentiality break. Even at larger committees, a single >2/3-committee-stake validator decrypts everything (same root cause as MED-1/MED-3).

**Recommendation.** Enforce a minimum committee size (e.g. `DkgMaxMembers ≥ 4`), reject/clamp any single member being allocated ≥ t points at `openRound` (or cap any member's stake fraction used for allocation), and document that the guarantee is void whenever one entity holds > ~2/3 committee stake. Gate enable on the live top-validator VP being below that.

**Status:** Open — governance guardrail (couples with MED-3).

---

#### LOW-6 — `DecryptDelay` settable up to 10M pins each superseded epoch's `DkgRound` + up to S cached share-keys until its lone ciphertext matures (governance) · CONFIRMED
**Location:** `types/types.go:435-437` (`DecryptDelay ≤ 10_000_000`); `keeper/dkg.go:255-266,501` (per-epoch Y-cache of S entries), `:338-347` (`maybePruneEpoch` gated on `epochEncCount==0`).

**Impact.** A superseded epoch's `DkgRound` + `ActiveThresholdKey` + its Y-cache (up to 2048 KV entries) are pinned until its last in-flight ciphertext matures. `DecryptDelay` (submit→mature gap) is settable up to 10M blocks. One cheap sybil ciphertext per rekeyed epoch, with a small `DkgMaxEpochBlocks` (frequent rekeys) and a high in-flight ceiling, keeps up to `O(MaxInFlightEncTx)` epochs each retaining ~S cache entries + a round record for up to 10M blocks. The per-epoch Y-cache (a fix for HIGH-U) multiplies prior retention by up to 2048×. Bounded, but the bound is very large and governance-reachable — a state-bloat amplifier the `DecryptDelay` cap predates.

**Recommendation.** Bound `DecryptDelay` to a small multiple of the grace window rather than 10M, and/or cap simultaneously-pinned superseded epochs (evict the oldest, stranding its stragglers) so retained per-epoch cache state is O(small constant) independent of `DecryptDelay` and rekey frequency.

**Status:** Open.

---

### INFO (positive assurance)

---

#### INFO-1 — Determinism: committed-write path independently verified fork-safe · CONFIRMED
**Location:** `keeper/voteext.go:281-290,812-904`; `keeper/stakeweight.go:76-174`; `keeper/dkg.go:454-523`; `keeper/keeper.go:41-51`.

**Assurance for the enable decision.** Independently confirmed (not on trust): (1) entries are canonicalized by a **stable operator-sort + first-wins dedup** before any write; (2) **no Go map is range-iterated** to produce committed state — `processed`/`seen`/`spent`/`owned` and finalize's `byDealer`/`disq`/`weightOf` are lookup-only, and every output loop walks a sorted slice or store-ordered iterator; (3) **no time/rand/float** on the commit path (`rand.Reader` confined to node-local `ExtendVote` dealing + client encryption); (4) the share-key cache is a committed-state read with a pure recompute fallback yielding identical `Y_index`; (5) deadline math saturates (`addSat`) and stake/drift math is exact bigint; (6) `GetParams` and the consensus-param VE gate fall back to identical defaults on every node; (7) PreBlock consumes the same committed `Txs[0]` bytes ProcessProposal self-certified, and per-block budget maps are rebuilt from committed state and never persisted. **No first-order app-hash divergence was found.**

**Recommendation.** Preserve these invariants under any future change: canonicalize before writes, never iterate a map into state, keep the recover bodies branched (LOW-1), and keep all new KV writes keyed by/rebuilt from committed state only. Add a CI determinism harness (two independent app instances replaying the same block) to guard regressions.

---

## 4. Systemic Observations

**A. Dormant-merge-safe vs. enable-safe is the governing distinction.** INFO-1 establishes that the committed-write path is deterministic and fork-safe, which is exactly the property that makes merging the code with the feature *off* low-risk. Every CRITICAL and HIGH lives on the **enabled** execution path or in **governance parameter space**; none can fire while `EncEnabled=false` and the DKG is idle. The review therefore cleanly separates a *merge* decision (acceptable, dormant) from an *enable* decision (blocked). Reviewers and operators must not conflate the two: a green merge here is not a green enable.

**B. Recurring theme #1 — per-block consensus crypto work is not bounded by a small constant.** CRIT-2, CRIT-3, HIGH-3, HIGH-4, and LOW-3 are the same structural mistake in five places: expensive EC/DLEQ work (verify, recover, precompute) is admitted per-block by *counts of items* (`128`, `2048`, `S`) rather than a flat *EC-op budget*, so an adversary or a governance param scales consensus-critical block time linearly-to-quadratically. The correct remediation pattern is uniform: replace item-count ceilings with a small constant work budget (`K_max`), add a *global* (not per-submitter) admission limit, and cache/skip already-verified work. Fixing these together is more effective than one-by-one.

**C. Recurring theme #2 — governance validity ≠ safety.** HIGH-4, MED-5, LOW-5, LOW-6 (and MED-1/MED-3 indirectly) all stem from parameter bounds that are *valid* but *unsafe*: `DkgShareBudget=2048`, `DkgMaxMembers=1`, `DkgDealWindow=10_000_000`, `DecryptDelay=10_000_000`. Several are unrecoverable (MED-5) or void the core guarantee (LOW-5). The validity ranges were set as sanity guards, not safety guards. A single pass tightening every operator-tunable to its *provably-safe* range (and adding escape hatches for the frozen-at-open values) closes a whole class.

**D. Recurring theme #3 — Byzantine faults degrade to permanent strands with no recovery path.** HIGH-1, MED-2, and LOW-4 form a chain: a poison-and-hide dealer survives the complaint round (HIGH-1), the resulting undecryptable-but-finalized epoch has no rekey trigger (MED-2), and a cache-key bug can suppress the very complaint that would have caught it (LOW-4). The deferred "MF4" derive-belt / early-rekey is the common remediation and its absence is felt across all three. Anti-MEV liveness needs a decrypt-health-driven re-genesis path.

**E. The confidentiality guarantee is topology-contingent and currently false on Limonata.** MED-1/MED-3/LOW-5 converge on one fact the design openly acknowledges but does not enforce: security holds only when no operator holds ≳54.7% of committee stake. Limonata runs a ~70%-VP validator, so the headline property does not hold today regardless of code. This is the one blocker no code fix resolves — only a stake-distribution change or an enforced committee-composition cap.

---

## 5. Conditions to Enable & Residual Risks

### 5.1 Must-fix set (all required before any enable)

Ranked by blocker weight:

1. **CRIT-1 (crypto full break).** Bind `index` (+ epoch + domain) into the DLEQ nonce; enforce enc-share `A` uniqueness; add the nonce-reuse regression. *Non-negotiable — currently extractable on-chain.*
2. **MED-3 / MED-1 / LOW-5 (topology void).** Enforce, at round-open, that no single operator (and no realistic colluding set) holds ≥ `(t−n+1)/S` of committee stake, with a loud refuse-to-finalize; enforce a minimum committee size; gate enable on the **live** top-validator VP being below the bar. *Today Limonata's ~70% validator fails this — enable is impossible without a stake/composition change.*
3. **CRIT-2 & CRIT-3 (consensus DoS / decrypt halt).** Replace item-count ceilings with a small constant EC-op budget (`K_max`); add a global per-block maturing-ciphertext admission limit; route decrypt through the Y-cache and skip re-verification of ingest-verified shares; stake/price-gate submitter identity. Re-audit under a sustained attacker.
4. **HIGH-3 & HIGH-4 (finalize burst / share-budget).** Chunk `PrecomputeShareKeys` (or single O(S+t) evaluation) and lower `maxDkgShareBudget` until finalize and per-block verify are provably sub-second on target hardware.
5. **HIGH-2 (commit-info bloat).** Shrink `VoteExtMaxBytes` to the honest maximum, add an aggregate injected-commit budget, and drop over-budget extensions deterministically instead of skipping injection.
6. **HIGH-1 + MED-2 (poison-and-hide + no recovery).** Implement the MF4 derive-belt / decrypt-health early-rekey, or ingest-time full-share verifiability, plus an undecryptable-epoch re-genesis trigger. *Design change — must be externally audited.*
7. **MED-5 & MED-4 (governance freeze / genesis loss).** Add operational window bounds + abort-open-round escape hatch; export/import full DKG+ciphertext state (or refuse export while ciphertexts are in flight).
8. **Governance guardrail sweep (LOW-6) + hardening (LOW-1, LOW-2, LOW-3, LOW-4).** Tighten remaining param ranges; branch the recover bodies through `CacheContext`; strip the marker tx explicitly; negative-cache rejected chaff; re-key the complaint negative cache.

### 5.2 Residual risks after the must-fix set

- **Topology risk persists operationally.** Even with round-open enforcement (item 2), the guarantee remains contingent on the live stake distribution staying below the bar; a stake shift after enable can silently re-void confidentiality. This needs continuous monitoring and an automatic disable/refuse on breach, not a one-time check.
- **Structural DKG faults (HIGH-1) are design-level.** The MF4 remediation is new and unaudited; it must be reviewed by a third party before it is trusted as the recovery backstop.
- **Determinism is verified only to first order.** INFO-1 found no first-order divergence, but LOW-1 shows the recover pattern is one node-local panic away from a silent fork; the CI determinism harness is a residual-risk control that should exist before enable.
- **Performance bounds are partly from the module's own instrumentation** on specific hardware; the post-fix `K_max` budgets must be re-measured on the actual validator fleet.

---

## 6. Nature of This Engagement

**This report is the product of an internal adversarial simulation of an external security audit.** It was conducted by an in-house reviewer role-playing an independent auditor: reading the module cold, raising candidate findings adversarially, and verifying or refuting each against the source (23 raised, 4 refuted, 19 confirmed). It is deliberately structured, scoped, and severity-ranked to the standard of a third-party report so that the enable decision can be made on rigorous ground.

It is **not** a substitute for a real third-party firm engagement. An internal reviewer shares tooling, assumptions, and blind spots with the team that wrote the code, and cannot provide the independence, cryptographic specialist depth (the CRIT-1 nonce-reuse class and the threshold-ElGamal security proof in particular warrant a dedicated cryptographer), or liability posture of an external auditor. Two findings carry design-level remediations (HIGH-1 / MF4, and the topology-cap enforcement) whose *fixes* will themselves be new, unaudited code.

**Recommendation:** treat this report as the pre-audit hardening pass. Complete the Section 5 must-fix set, then commission a real external audit — with an explicit cryptography scope — before enabling the encrypted mempool on any chain carrying value, and before mainnet. Enable is NO-GO until both are done.

---

*End of report. All file:line references are to `~/cosmos-evm-dkg`, branch `limonata-dkg-integration`, as reviewed 2026-07-05.*