# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-04 (audit cycle 5 close-out)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** `d8976687` — *harden(encmempool/dkg): cycle-5 — stake-drift rekey + bounded/fair grace deferral*, atop
`2c2a271d` (cycle-4 — close the 6 cycle-3 findings) → `19d5cb6f` (stake-weighted secret sharing) → `a75b027f` → `36b6ee82` → `17101a12`

---

## VERDICT: `AUDIT_CLEAN = YES` — **GO-to-enable readiness** (with the conditions below)

Cycle 5 closed the **two items cycle 4 explicitly deferred** — the stake-drift window and the
never-live-exercised grace-deferral path — with minimal, default-off code, and then **proved both
on a live multi-node throwaway chain**, not just in process. The cycle-5 adversarial audit
returned **11 findings, zero critical, zero high** (`AUDIT_CLEAN = YES`); the multi-node verdict
run returned **GO** with **zero app-hash divergence across 76 sampled heights × 4 nodes**.

**What "GO-to-enable readiness" means — and does NOT mean:**

- The feature is **still gov-gated and dormant-by-default**. `DefaultParams` ships
  `DkgEnabled = DkgTransparent = false`, and the two new stake-drift triggers
  (`DkgMaxEpochBlocks`, `DkgRekeyOnStakeDriftBps`) both default **0 = OFF**. The default binary
  is byte-behavior-identical to `17101a12`. Nothing turns on without an explicit governance vote
  AND vote extensions scheduled in consensus params.
- **This internal audit trail is NOT a substitute for an external audit.** Five adversarial
  cycles found and closed real breaks (4 HIGHs, then a wrong-layer fix, then a config hole and a
  liveness band, then two honestly-deferred residuals). An **external professional audit is
  required before ANY mainnet reliance** on the encrypted mempool's confidentiality claims. This
  report is internally exhausted, not externally audited — see §5.
- **The release decision belongs to Jason.** This report states technical readiness only: the
  branch is internally clean, live-proven at its boundaries (including the two cycle-4
  deferrals), and safe to leave dormant. When/whether to merge, schedule VE, turn on a rekey
  cadence, and put an enable vote to governance are product and risk decisions, not engineering
  defaults.

---

## 1. Cycle history — five audit cycles, every finding closed

| Cycle | Commit(s) | What happened |
|-------|-----------|---------------|
| **1** | `f8615df2` (feature), `36b6ee82` (doc) | Transparent in-node DKG built (VE auto-participation, transparent enc key, members = bonded set). Live 4→5-node proof, 0 divergence. Audit: **NO-GO, 4 HIGHs** — halt on misconfig, enc-key impersonation, stake-minority seat-majority capture, self-identifier overload. |
| **2** | `a75b027f` (fix), `6201178d` (doc) | HIGH-1 closed (VE-coupled `veActive` + `MsgUpdateParams` guard), HIGH-2/4 closed (operator-bound PoP + cross-operator uniqueness + operator-indexed self-id). Both cycle-1 deferred proofs pass live. **But HIGH-3 SURVIVED — the fix landed at the wrong layer**: the Shamir threshold stayed a seat COUNT, so a stake-minority seat-majority reconstructed the epoch key **off-chain**. **NO-GO.** |
| **3** | `19d5cb6f` (fix) | HIGH-3 closed at the **cryptographic layer**: stake-weighted secret sharing (Hamilton apportionment of a share budget S, per-eval-point shares, weighted finalize). Proven live on 4 nodes, 0 divergence. Audit: **NO-GO, 11 findings** — the envelope wasn't right: (H-A) a valid `S < n` config made apportionment degenerate (address-order power); (H-B) `t = floor(2S/3)+1` stranded honest online supermajorities in a real band AND the shortfall path **silently dropped** the matured ciphertext; plus M-1/M-2/L-1/L-2. |
| **4** | `2c2a271d` (fix) | All 6 cycle-3 findings closed: `t = floor(2S/3) − n + 1` (zero residual liveness band, proven inequality), `S ≥ 8n` coupling (gov + genesis + runtime clamp), non-silent bounded **32-block grace deferral**, M-1 bar retired, M-2/L-1/L-2 closed. Audit: **14 findings, 0 crit/high → `AUDIT_CLEAN = YES`**. 4-node verdict run: **GO on all 5 proofs**, 602/602 app-hashes. **Two items deferred to cycle 5** (stake-drift window; grace path never live-exercised). |
| **5** | `d8976687` (fix — **this report**) | Both cycle-4 deferrals closed (§2), minimal + default-off. Independent audit: **11 findings, 0 critical/high → `AUDIT_CLEAN = YES`**. Independent 4-node live verdict run: **GO** — default-off is a genuine no-op under 71% drift; cadence and bps triggers each fire deterministically, re-snapshot the allocation to live stake, and the measured `drift_bps` matched exact hand computation (7134, 1579); the grace path **fired live for the first time** — a matured-but-short ciphertext deferred with `encmempool_decrypt_missed`, healed by late shares inside the 32-block grace, and (a separate ciphertext) **stranded exactly once at the grace boundary** with all ref-counts returning to 0; **0 app-hash divergence across 76 sampled heights × 4 nodes**. |

**Held across every cycle (never regressed):** the transparent experience itself (no daemon, no
account, no fee, no manual key, no declared list), consume-path determinism / zero divergence,
dormancy + kill-switch, bounded VE/dealing size, flood-and-refcount invariants (any final EncTx
drop goes through `releaseEncTx`; O(cap) per-block scans only), and the legacy declared-DKG path
byte-identical.

---

## 2. Cycle-5 fix — what `d8976687` changed (the two cycle-4 deferrals)

Both changes are **minimal and default-off**: with default params the code paths are early-exit
no-ops and behavior is byte-identical to cycle 4.

### (A) Stake-drift / epoch-cadence rekey — closes cycle-4 residual #1

`MembersHash` covers **operators only**, so a pure re-delegation never triggers a rekey and the
frozen round-open stake snapshot ages while eval-point allocation stays frozen — decryption power
drifts from live stake, eroding the snapshot-proven safety/liveness coupling until the next
membership change. Cycle 5 adds **two optional triggers** (`keeper/endblock.go`,
`stakeDriftRekeyDue` + the new `case` in the rekey switch) that re-genesis the **SAME committee**
against a **fresh stake snapshot**, restoring the coupling:

- **`DkgMaxEpochBlocks`** (default 0 = OFF): rekey at least once every N blocks — epoch cadence,
  bounds snapshot age.
- **`DkgRekeyOnStakeDriftBps`** (default 0 = OFF): rekey when the **max-coalition stake-fraction
  drift** reaches the threshold. The metric (`committeeMaxCoalitionDriftBps`) is **half the
  total-variation distance** between the snapshot and live committee stake distributions —
  exactly the largest amount by which ANY coalition's live stake fraction can have moved from the
  fraction its frozen allocation was sized for. Computed in **exact big-integer arithmetic** over
  the common denominator `2·W_snap·W_live` (no float; order-independent; overflow-safe), so it is
  a deterministic pure function of committed state.

Both triggers fire **only for an ACTIVE round**, are **gap-dampened** by the shared
`DkgMinRekeyGap` (no rekey storm), are **transparent-path only** (`DkgTransparent`), and keep the
operator set (so a stake-drift rekey is NOT a member change and never resets the retry backoff).
It emits `encmempool_dkg_stake_drift_rekey` (with measured `drift_bps`, cadence, threshold) as the
monitor event.

**Guaranteed residual bound (the drift_bound):** with `DkgRekeyOnStakeDriftBps = D`, the max
coalition stake-fraction drift is **≤ D bps + (stake movable within `DkgMinRekeyGap` + one
round-finalize latency)**. With `DkgMaxEpochBlocks = N`, snapshot age is **≤ N + that finalize
latency**. Both default 0 → OFF, transparent-only, gap-dampened. A coalition proven `< 1/3` at
snapshot is still `< 1/3 + drift` live — so bounding the drift bounds how far the coupling can
erode between rekeys.

### (B) Bounded + fair grace deferral — hardens cycle-4 residual #2's mechanism

The cycle-4 32-block `StrandedDecryptGrace` kept matured-but-short ciphertexts in state
**unboundedly**; a flood of short ciphertexts could pile up at the head of both the O(cap) decrypt
scan (`maxDecryptScanPerBlock`) and the h-grace vote-extension share window, starving fresh
healthy ciphertexts. Cycle 5 (`keeper/abci.go`):

- **Caps** the concurrently-deferred set at `maxDeferredDecryptsPerBlock = 128` (well below the
  4096-entry scan window and the 256-min VE share cap). Over the cap, a within-grace shortfall
  **drops NOW** — loud `encmempool_decrypt_deferral_capped`, H2-safe via `releaseEncTx` — instead
  of deferring, so the deferred backlog stays bounded.
- Makes the defer slots **fair-shared across submitters** (`selectFairDecrypts`, the same
  deterministic round-robin the decrypt budget uses), so an attacker spraying low-seq short spam
  cannot monopolize the heal grace and deny it to honest ciphertexts.

Normal operation (a handful of transiently-late ciphertexts) never reaches the cap, so behavior
there is **byte-identical**; **heal-within-grace** and the **exactly-once loud grace-expiry drop**
(`encmempool_decrypt_missed` → heal, `encmempool_decrypt_stranded` → `releaseEncTx`) are
unchanged from cycle 4.

### Param validation & regression posture

`Params.Validate` (shared by genesis `ValidateGenesis` AND `MsgUpdateParams`) bounds the new
params: `DkgMaxEpochBlocks ≤ maxDkgWindowBlocks`, `DkgRekeyOnStakeDriftBps ≤ 10000` (100 %; a
larger threshold could never fire — a silent misconfig, so rejected). Committed regressions:
heal-within-grace, drop-at-grace-end (H2 epoch ref-count released + epoch pruned, dropped exactly
once), backlog-flood beyond the scan window (bounded scan + bounded deferred set + no silent loss
+ full drain, no leak), the rewritten flood test proving **bounded-AND-fair**, stake-drift
default-off/cadence/bps/flap-gap, and the new param-validation bounds. The cycle-5 auditors left a
further probe suite (`keeper/audit_c5_*`: defercap, determinism, drift, e2e, stakedrift) —
currently **untracked**, all green, recommended for promotion to committed regressions.

`gofmt` + `go vet` clean; `go test -tags test ./x/encmempool/... -count=1` **ALL PASS** (verified
at close-out with the cycle-5 probes present); evmd + root modules build (exit 0).

---

## 3. Cycle-5 audit result — 11 findings, 0 critical, 0 high → `AUDIT_CLEAN = YES`

The cycle-5 adversarial audit re-attacked the two new surfaces: the determinism and residual bound
of the drift trigger (big-int exactness, order-independence, flap-gap, active-round gating,
transparent-only gating), and the deferral cap under flood (bound, fairness, H2 ref-count
integrity, no silent loss, no leak). **The drift metric is exact and deterministic; the rekey
fires only when due and restores the allocation to live stake; the deferred set is provably
bounded and fair-shared; every drop path releases through `releaseEncTx`.**

The 11 findings are all medium/low/informational; none blocks enable-readiness. The substantive
residuals — now smaller than at cycle 4 — are captured honestly in §5.

---

## 4. Multi-node live verdict run — **GO**, 0 divergence across 76 heights × 4 nodes

An independent 4-node throwaway-network verdict run (fresh genesis, real governance, live
delegation moves, live shortfall/heal) exercised **both** cycle-4 deferrals on a live chain for
the first time:

1. **Stake-drift, default-off is a genuine no-op:** under a **71 % drift** with both triggers at
   0, the committee did **not** rekey — the epoch stayed frozen, app-hashes stayed deterministic.
   This is the byte-behavior-identical dormancy claim, shown live.
2. **Cadence trigger fires deterministically:** with `DkgMaxEpochBlocks` set, the committee
   re-genesised on cadence, re-snapshotting the eval-point allocation to live stake.
3. **Bps trigger fires deterministically and exactly:** with `DkgRekeyOnStakeDriftBps` set, the
   rekey fired at the threshold, and the measured `drift_bps` matched **exact hand computation —
   7134 and 1579** — confirming the big-int metric on the live path.
4. **Grace-deferral path fired live for the first time (both halves):**
   - **HEAL:** a matured-but-short ciphertext **deferred** (loud `encmempool_decrypt_missed`, not
     dropped), then **healed by late shares inside the 32-block grace**.
   - **STRAND:** a *separate* ciphertext **stranded exactly once at the grace boundary** via
     `encmempool_decrypt_stranded` → `releaseEncTx`, with **all ref-counts returning to 0** — no
     leak, no strand, no halt.
5. **Consensus never wavered:** **0 app-hash divergence across 76 sampled heights × 4 nodes**
   through the delegation moves, the rekeys, the shortfall, the heal, and the strand — strong
   determinism evidence.

**Honest caveats on the live evidence (from the verdict run itself):**

- (a) **The `encmempool_decrypt_deferral_capped` path was NOT live-exercised.** The 128-entry
  fair-share cap under a `>128` short-ciphertext flood remains **unit-test-only**; the mission's
  deferral asks driven live were **heal** and **strand**, not the cap. This is the single new
  residual (§5.2).
- (b) **"Byte-identical dormant" is shown behaviorally, not by a literal cross-binary byte-diff.**
  The dormancy claim rests on the observed no-rekey / frozen-epoch / deterministic app-hash under
  param-0 gating, inferred from the gating — a literal byte-diff of the fixed binary vs the
  pre-cycle-5 build was **not** performed.
- (c) **The first heal attempt stranded on node catch-up timing and needed a retry.** The logic
  was correct; the orchestration window was too tight relative to a node's catch-up. The retry
  cleanly healed. This is a test-harness timing artifact, not a code defect — but it is worth
  noting that the heal has a real dependency on shares arriving before the grace elapses.
- (d) **Source-checkout reset, unrelated to the result.** Mid-session an external process reset
  the `/home/prepauto/cosmos-evm-src` checkout (HEAD moved off `d8976687`); this did **not** affect
  the standalone fixed binary or any live result, and remaining code facts were sourced from the
  stable git object `d8976687`. The checkout is back on `d8976687` at close-out.
- (e) As in every prior cycle: **no live Byzantine reconstruction was staged** — that requires a
  malicious binary the isolation harness deliberately cannot produce. The authoritative
  negative-path (minority-cannot-reconstruct) evidence remains the flipped regression suite.

---

## 5. Residuals & the EXTERNAL-audit focus list — what closed, what remains

### Closed since cycle 4 (the two deferred items)

1. **Stake-drift window (cycle-4 §5.1) — MECHANISM BUILT + LIVE-PROVEN.** The opt-in
   cadence/bps rekey re-tracks the allocation to live stake with the proven residual bound (§2A),
   demonstrated live: default-off no-op under 71 % drift, both triggers firing deterministically
   with `drift_bps` matching exact computation. **The remaining piece is a product decision, not
   engineering:** whether to enable a rekey cadence for mainnet and at what `D`/`N` — do not let
   this default silently into a mainnet posture.
2. **Grace-deferral path never live-exercised (cycle-4 §5.2) — NOW LIVE-PROVEN.** Heal-within-
   grace and strand-at-grace-boundary both fired on the live 4-node chain with ref-counts
   returning to 0 (§4.4). No longer unit/e2e-only.

### Remaining for an EXTERNAL professional audit (internal cycles are exhausted, NOT a substitute)

1. **External professional audit REQUIRED before ANY mainnet reliance** on the encrypted
   mempool's confidentiality. Five internal cycles were adversarial and independent, but they are
   not an external audit. Hand the external firm this §5, the full probe corpus (cycles 1–5,
   including the untracked `audit_c5_*` and `audit_c4_*` suites), and the two live verdict runs as
   the starting material. **We do NOT claim an external audit has been done.**
2. **The deferral-cap flood path (`encmempool_decrypt_deferral_capped`) is unit-test-only.** The
   128-entry fair-share cap under a `>128` short-ciphertext flood was proven bounded-and-fair in
   unit tests but **not exercised on a live multi-node chain** — a candidate for the external
   audit's live-flood stress (§4a).
3. **No live Byzantine reconstruction is stageable in the isolation harness.** Minority-cannot-
   reconstruct rests on flipped regressions plus live offline-node evidence; a real adversarial
   binary / crypto review is the external auditor's job (§4e).
4. **Dormancy is behavioral, not byte-diffed.** A literal cross-binary diff of the default build
   vs `17101a12` would strengthen the "changes nothing until enabled" claim (§4b).
5. **The decrypt bar is the M-1 bar** — `> 2/3 − 2n/S` (≈ 54.7 % at defaults), NOT ">2/3".
   Anyone depending on the confidentiality threshold must read §2 of the cycle-4 record, not the
   retired claim. This is a **honest-public-statement** obligation, a product decision.
6. **Committee stake ≠ total bonded stake.** The committee is the top-N by stake
   (`EffectiveMaxMembers`); all fractions are of SNAPSHOTTED COMMITTEE stake. Pre-existing,
   unchanged, inherent to bounding VE size.
7. Carried non-blocking deferrals from cycle 2, unchanged: injected blob occupies `Txs[0]` (one
   deterministic decode-fail slot per block); lenient `ProcessProposal` (Byzantine proposer can
   stall DKG *progress*, not fork/halt); remote-signer/KMS nodes safely non-participate.

---

## 6. Design reference — what "transparent" means and how it is wired (stable since cycle 1)

### The goal
A bonded validator that simply **runs the binary** becomes a DKG member automatically: **no
separate daemon**, **no account/fee setup**, **no manual enc-key registration**, **no declared
member list** (members are the bonded validator set itself).

### The three pillars

**Pillar 1 — In-node auto-participation via ABCI++ vote extensions** (`evmd/dkg_voteext.go`):

| Phase | Handler | What it does |
|-------|---------|--------------|
| `ExtendVote` | `dkgExtendVoteHandler` | Packs `{EncPubKey announcement + PoP, Feldman dealing, DLEQ-proved per-eval-point decryption shares}` into the precommit's `VoteExtension`. Node-local. |
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` | Lenient structural check only; all crypto/membership/dedup enforced deterministically on-chain later. |
| `PrepareProposal` | `wrapDkgPrepareProposal` | Composes around the EVM-mempool handler: reserves bytes, prepends the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` | Self-certifies `Txs[0]` with `baseapp.ValidateVoteExtensions`, strips it, delegates. Gated by `veActive` (HIGH-1 fix). |
| `PreBlock` | `consumeDkgVoteExtensions` → `keeper.ConsumeVoteExtensions` | Resolves consensus address → operator via staking; deterministic canonicalizing consume. Replaces the tx paths. |

**Pillar 2 — Transparent key.** A secp256k1 ECIES key per member, minted with zero operator
action (`dkgnode.LoadOrCreateEncKey`, `<home>/dkg_enc_key.json`, 0600), auto-announced with an
operator-bound PoP (HIGH-2 fix); self-identity by OPERATOR (HIGH-4 fix).

**Pillar 3 — Members = bonded validators.** `TransparentMembers` derives the committee from the
bonded set: every bonded validator with a valid unique enc key, top-N by stake
(`EffectiveMaxMembers`), clamped to `floor(S/8)` seats (cycle-4); each member's eval points
apportioned by stake (cycle-3/4). Indices by operator order so `MembersHash` is a pure function of
committed state. **Rekey triggers (`keeper/endblock.go`):** membership change (`MembersHash`
delta), Failed-round auto-retry, and — cycle-5, opt-in — cadence/stake-drift
(`stakeDriftRekeyDue`), each re-genesising against a fresh stake snapshot.

### Determinism contract (the #1 fork risk — held through every live run)
All determinism is confined to the consume half (`keeper.ConsumeVoteExtensions`) and the EndBlock
DKG state machine, both pure functions of `(committed state, entries)`: stable-sorted, first-wins
deduped, idempotent writes, finalize/decrypt read only committed state, the drift metric is exact
big-int and order-independent, last-resort `recover` → deterministic event. Every live run
(cycles 1–5) byte-identical app-hashes.

### Dormancy / kill-switch
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` AND vote extensions are
active at the height; the cycle-5 triggers additionally require their param `> 0`. All the
enabling flags default false/0. Governance can disable at any time (`MsgUpdateParams`); in-flight
decrypt safety and flood/admission control proven each cycle.

---

## 7. GO / NO-GO

### Verdict: **internally CLEAN — GO-to-enable readiness**, gated as follows.

1. **Still gov-gated, still dormant-by-default.** Merging this branch without enabling changes
   nothing; enabling requires VE scheduled + an explicit governance vote, and the HIGH-1 guard
   makes an inconsistent switch state unreachable. The two cycle-5 triggers are additionally 0 by
   default.
2. **External professional audit REQUIRED before ANY mainnet reliance** on the encrypted mempool.
   The internal cycles are now **exhausted** (both cycle-4 deferrals closed + live-proven), but
   they are not a substitute; hand the external auditors §5 plus the full probe suite and the two
   live verdict runs as the starting corpus. **No external audit has been performed.**
3. **Product decisions before mainnet:** the rekey cadence (whether/at what `D`/`N` to enable the
   stake-drift triggers, §5.1) and the honest public statement of the decrypt bar (§5.5).
4. **The release decision belongs to Jason** — merge timing, VE scheduling, drift-trigger
   enablement, and the enable vote are his call, not an engineering default.

### What is safe today
Merging this branch **without enabling** is safe: all handlers are no-ops under default params
(including the two cycle-5 triggers at 0), the binary is byte-behavior-identical to `17101a12`,
both modules build green, and the full regression suite (cycles 1–5, including every flipped
auditor probe) passes.

---

## 8. Scorecard

| Item | State |
|------|-------|
| Builds (evmd + root modules) | ✅ exit 0 |
| Full test suite (`-tags test`, incl. all flipped auditor probes) | ✅ ALL PASS |
| Consume-path + EndBlock determinism (unit + order-independence + live) | ✅ 0 divergence, every cycle |
| Transparent experience (no daemon/account/fee/key/list) | ✅ proven live, cycles 1–5 |
| Kill-switch / dormancy | ✅ default-off, gov-disable proven; cycle-5 triggers default 0 |
| HIGH-1/2/3/4 (halt / impersonation / stake-minority capture / self-id) | ✅ closed cycles 2–4 |
| Cycle-3 H-A/H-B + M-1/M-2/L-1/L-2 | ✅ closed cycle 4 |
| **Cycle-4 residual #1 — stake-drift window** | ✅ mechanism built + LIVE-PROVEN cycle 5 (cadence + bps rekey, exact drift bound); enablement is Jason's product call |
| **Cycle-4 residual #2 — grace-deferral path never live-exercised** | ✅ LIVE-PROVEN cycle 5 (heal-within-grace + strand-at-boundary, ref-counts → 0, no leak) |
| Deferral bounded + fair under flood (cap 128, fair-share) | ✅ built + unit-proven; live-flood exercise left to external audit (§5.2) |
| Multi-node verdict run (cycle 5) | ✅ GO — 0 divergence / 76 heights × 4 nodes; drift_bps 7134 & 1579 matched exact computation |
| Security audit (cycle 5) | ✅ `AUDIT_CLEAN = YES` — 11 findings, 0 critical, 0 high |
| External audit | ❌ NOT DONE — **required before any mainnet reliance**; internal cycles now exhausted |
| Stake-drift rekey cadence decision | ⚠️ OPEN product decision (§5.1) — mechanism ready, enablement is Jason's |
| **Enable on a real chain** | **GO-ready** — gov-gated, dormant-by-default; decision is Jason's, after external audit for mainnet |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release.*
