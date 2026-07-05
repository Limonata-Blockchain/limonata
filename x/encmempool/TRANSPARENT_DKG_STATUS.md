# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-05 (audit cycle 6 close-out — exhaustive re-audit)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** `abd6457e` — *test(encmempool/dkg): cycle-6 exhaustive re-audit — drive the never-live paths, all green*, atop
`73b1dd1e` (cycle-5 AUDIT_CLEAN close-out) → `d8976687` → `2c2a271d` → `19d5cb6f` → `17101a12`

---

## VERDICT: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE** (dormant-by-default MERGE still safe; external audit still required regardless)

This is a reversal from cycle 5, and it is the whole point of pushing harder. Jason asked for a
**bigger, exhaustive re-audit to be CERTAIN everything is green.** The live multi-node run *is*
green — all five mission objectives were proven LIVE on a 6-node throwaway, including the marquee
128-entry defer-cap that cycle 5 could only unit-test. But the **6-lens adversarial code audit that
ran alongside it found 3 HIGH-severity liveness breaks** (of **19 total findings**) on the exact
paths a live *honest-binary* network structurally cannot exercise. So:

- **The live network is green.** `multinode` returned **GREEN**: defer-cap, boundary liveness,
  stake-drift storm, absent-dealer byzantine, and cross-node determinism all proven live,
  fork-free, on 6 nodes. Nothing that an honest binary can be driven to do broke.
- **The branch is NOT audit-clean.** `AUDIT_CLEAN = NO`. Three HIGH liveness findings (§4) survive:
  two of them are **unhealable** (a single Byzantine QUAL dealer permanently bricks an epoch's
  decryption, with **no complaint/justify recourse on the transparent path**), and one lets a
  **`< 1/3`-stake committee member convert the cycle-3 H-B healable grace-deferral into a hard
  drop**. All three were reproduced as passing repro tests driving the REAL consensus entry points.
- **These two facts are not in tension** — see §3. The live run used honest binaries, which
  *provably cannot* emit a well-shaped-but-corrupt VE dealing or pad unverified shares with intent;
  the audit drove the deterministic on-chain consume/finalize/decrypt functions directly with the
  adversarial inputs a **malicious validator** (or a small-stake committee member) *can* produce.

**What this means concretely:**

- **NO-GO to ENABLE** the transparent DKG (on any chain, even a testnet you rely on for
  confidentiality) until HIGH-1/2/3 are fixed and re-audited. The findings are liveness/DoS on the
  encrypted-mempool decrypt guarantee, not consensus safety — no fork, no halt — but they defeat the
  confidentiality/anti-MEV purpose the feature exists to provide.
- **Merging the branch DORMANT is still safe.** All three HIGH findings live on the *enabled*
  transparent decrypt/DKG path. With `DkgEnabled = DkgTransparent = false` (the shipped default) the
  binary is byte-behavior-identical to `17101a12`; none of the three is reachable. Merging without
  enabling changes nothing.
- **External professional audit is STILL REQUIRED before ANY mainnet reliance**, independent of the
  three findings above. Six internal adversarial cycles are not a substitute for an external audit.
  We do NOT claim an external audit has been performed.
- **The release decision belongs to Jason.** This report states technical readiness only.

---

## 1. Cycle history — six adversarial cycles

| Cycle | Commit(s) | Result |
|-------|-----------|--------|
| **1** | `f8615df2` | Transparent in-node DKG built (VE auto-participation, transparent enc key, members = bonded set). Live 4→5-node, 0 divergence. Audit: **NO-GO, 4 HIGHs** (halt on misconfig, enc-key impersonation, stake-minority seat-majority capture, self-id overload). |
| **2** | `a75b027f` | HIGH-1 closed (VE-coupled `veActive` guard), HIGH-2/4 closed (operator-bound PoP + operator-indexed self-id). **HIGH-3 SURVIVED — fix at wrong layer** (threshold stayed a seat COUNT). **NO-GO.** |
| **3** | `19d5cb6f` | HIGH-3 closed at the **crypto layer**: stake-weighted secret sharing. Audit: **NO-GO, 11 findings** — H-A (degenerate `S<n`), H-B (`t` stranded honest supermajorities AND the shortfall path **silently dropped** the ciphertext), + M/L. |
| **4** | `2c2a271d` | All 6 cycle-3 findings closed: `t = floor(2S/3) − n + 1`, `S ≥ 8n` coupling, non-silent **32-block grace deferral**. Audit: **14 findings, 0 crit/high → CLEAN**. 4-node run **GO**. Two items deferred to cycle 5. |
| **5** | `73b1dd1e` (was `d8976687`) | Both cycle-4 deferrals closed (stake-drift rekey; grace path live-proven heal+strand), minimal + default-off. Audit: **11 findings, 0 crit/high → CLEAN**. 4-node run **GO**, 0 divergence / 76 heights. **Defer-cap remained unit-test-only.** |
| **6** | `abd6457e` (**this report**) | Exhaustive re-audit on 6 nodes: **all 5 mission objectives proven LIVE** incl. the defer-cap (§2). 6-lens audit: **19 findings, 3 HIGH → `AUDIT_CLEAN = NO`** (§4). The bigger push worked exactly as intended — it surfaced real, previously-unexercised byzantine-dealer / unverified-share liveness breaks that five green live runs had masked. |

**Held across every cycle (never regressed):** the transparent experience (no daemon/account/fee/key/list),
consume-path + EndBlock determinism / zero app-hash divergence, dormancy + kill-switch, bounded
VE/dealing size, flood/refcount invariants (any final EncTx drop goes through `releaseEncTx`), legacy
declared-DKG path byte-identical.

---

## 2. Cycle-6 multi-node LIVE run — **GREEN** on all 5 mission objectives (6-node throwaway)

An independent 6-node throwaway network (fresh genesis, real governance, live delegation moves, live
flood) exercised every mission path — including the ones cycle 5 could not drive live — with **zero
app-hash divergence across 40+ sampled heights and two node resyncs**.

1. **(a) 128-entry defer-cap — PROVEN LIVE (the marquee result).** Cycle 5 could only unit-test this.
   Under a `>128`-concurrent-shortfall flood on the DKG-epoch path: the cap **engages** (152 loud
   `encmempool_decrypt_deferral_capped` emissions), the deferred set is **bounded at exactly 128
   concurrent**, defer slots are **per-submitter fair to the exact split (38/38/38/38)**, it is
   **H2-safe** (epoch-1 ref-count released + epoch pruned at h1678), an **honest ciphertext heals
   under the flood**, and there is **no leak, no halt**, deterministic across all 6 nodes.
2. **(b) Boundary liveness — PROVEN LIVE.** With **32 % of committee stake offline**, the **68 %
   online supermajority decrypts** cleanly; sub-quorum shortfalls defer-and-heal. (Scope: committees
   were **n = 5–6**, the 6-node constraint — NOT toward the `DkgMaxMembers = 16` cap; larger-n
   threshold behavior is covered by the `fuzz_stakeweight` + `TestC6_StakeCapture_*` unit probes, not
   live.)
3. **(c) Stake-drift storm — PROVEN LIVE.** Under **8 rapid re-delegations**, the `DkgMinRekeyGap`
   dampener held: **only 2 rekeys fired, exactly 20 blocks apart** — the storm was killed, the
   feature did not thrash.
4. **(d) Byzantine dealer (the live-injectable variant) — PROVEN LIVE.** An **absent dealer** was
   **QUAL-excluded and the round finalized** fork-free on the real 6-node network. (The
   corrupt-dealing / wrong-point-share / equivocating-VE variants were driven through the REAL
   deterministic consensus entry points in the keeper tests — NOT over live p2p — because an honest
   binary cannot emit them; see §3. This is exactly where the audit found HIGH-2/3.)
5. **(e) Determinism — PROVEN LIVE.** `app_hash` never diverged across all of the above, over 40+
   sampled heights and two node resyncs.

**Infra bring-up was ROUGH but the scenarios ran clean once up** (recorded for the next runner):
`evmd` needs `mempool.type = app`; chain-id must be resolved via `client.toml` not the flag; all
ports were remapped off the live `8545`/`26657` and the concurrent clawback `26659`; `pkill` by
command-line pattern self-killed the harness (exit-144 flakiness) until moved into script files;
foreground `sleep` is blocked (use a Monitor/until-loop); autocli binary flags decode hex-before-
base64; and there is a gov proposal-id race to sequence around. **Verdict on the live run: workable
— every scenario produced exactly-as-designed results.**

---

## 3. Why the live run is GREEN and the audit is NO — both are true

This is the crux, and it must be read before trusting either number in isolation.

- The **live 6-node harness runs honest binaries.** An honest binary *provably cannot*:
  (i) emit a **well-shaped-but-cryptographically-corrupt VE dealing** (it seals every enc-share
  honestly), nor (ii) **pad the decryption-share count with unverified chaff** at its own eval
  points with intent. So the live run — correctly — reported GREEN: every path an honest node can
  be driven down is bounded, fair, deterministic, and heals.
- The **audit drove the REAL deterministic on-chain functions directly** —
  `ConsumeVoteExtensions` → `IngestDealingFromVE` / `IngestDecryptShareFromVE`, `EndBlockDKG` →
  `finalizeRound` → `FinalizePublicWeighted`, and `recoverSharedSecret` — with the adversarial
  inputs a **malicious validator running modified software** (or a small-stake committee member)
  *can* produce. Those inputs enter the *same committed-state path* a live proposer would ingest,
  so the break is real on-chain, not a test artifact.
- **Neither caveat is a defect in the harness; both are inherent to what an honest transparent
  binary can be made to do over p2p.** The value of the bigger cycle-6 push is precisely that it
  reached past the honest-binary envelope and found the breaks five green live runs could not.

**Net:** the feature is live-clean under honesty and **NOT robust to a byzantine committee member.**
For an encrypted mempool whose entire value proposition is confidentiality/anti-MEV under partial
adversity, that is a NO-GO to enable.

---

## 4. Cycle-6 exhaustive re-audit — **19 findings, 3 HIGH → `AUDIT_CLEAN = NO`**

The 6-lens audit re-attacked: the defer-cap under flood/sybil, boundary liveness at extreme stake
distributions, the drift/cadence rekey under storms and overflow, byzantine dealers + the
complaint/justify path, unverified-share handling, and cross-height/cross-node determinism. Three
findings are HIGH; all three are **confirmed with passing repro tests** that drive the real
consensus entry points. **None is a consensus-safety break** (no fork, no halt — determinism held
in every probe); all three are **liveness/confidentiality DoS** on the enabled transparent path.

### HIGH-1 — Unverified VE decryption-share COUNT PADDING turns a healable grace-deferral into a HARD DROP (`< 1/3`-stake adversary; defeats the cycle-3 H-B fix)

- **Where:** `x/encmempool/keeper/voteext.go:453` (`IngestDecryptShareFromVE` stores a share
  **without verifying its DLEQ proof** — verification is deferred to combine time) →
  `x/encmempool/keeper/abci.go:488` (`recoverSharedSecret` count gate is `len(shares) < need` on the
  **RAW stored count**) → `abci.go:504-514` (`DecryptingSetMeetsStake` marks a member "present" from
  those same raw shares) → `abci.go:341` (any non-`errNotEnoughShares` error is the **HARD-DROP**
  branch) ; verification finally happens too late at `x/encmempool/dkg/proof.go:239`
  (`RecoverVerified` drops unverified partials, then errors).
- **Mechanism:** a committee member submits **structurally-valid but cryptographically-invalid**
  decryption shares at **its OWN owned eval points** via a vote extension. That chaff (1) inflates
  the RAW count past `need` (count gate passes), and (2) marks the member "present" (stake gate
  passes). `RecoverVerified` then drops the chaff (verified `< need`) and returns a **non-
  `errNotEnoughShares`** error → the matured ciphertext is **hard-dropped** (`encmempool_decrypt_
  failed`) *instead of* being deferred into the 32-block grace to heal from late honest shares.
- **Impact:** during the honest-share-arrival window the grace exists to protect, a **stake-MINORITY
  Byzantine coalition** can force matured ciphertexts to drop rather than decrypt — an anti-MEV /
  liveness DoS that **weakens the cycle-3 H-B fix.** Deterministic (no fork); loud-but-**mislabeled**
  (`decrypt_failed`, masking the attack as a bad ciphertext).
- **Proof:** `TestC7_UnverifiedShareCountPadding_ForcesDropInsteadOfGrace` **PASSES** — a **25 %-stake
  minority dropped a healable ciphertext**; the CONTROL (identical honest shares, no chaff) deferred
  then healed. The *only* difference between DROP and HEAL is attacker-supplied unverified shares.

### HIGH-2 — A Byzantine QUAL dealer permanently breaks an epoch's decryption, with NO complaint recourse on the transparent path

- **Where:** `x/encmempool/dkg/onchain.go:92` (`FinalizePublicWeighted` admits a dealer to QUAL by
  checking only the **commitment SHAPE** — count + point-parse — never that its enc-shares open and
  match the commitments) → `x/encmempool/keeper/endblock.go:392` (`finalizeRound` →
  `FinalizePublicWeighted`) ; and there is no way to accuse it: `x/encmempool/keeper/voteext.go:191`
  (`TransparentMembers` sets **no `AccountAddr`**) and `x/encmempool/types/voteext.go:34`
  (`VoteExtension` has **no complaint field**).
- **Mechanism:** a QUAL dealer sends a well-shaped dealing (valid commitments, own eval points
  honest) but **corrupts every enc-share addressed to points it does NOT own** — either unopenable
  (AES-GCM tag fails) or openable-but-wrong (seals a wrong scalar). It passes the shape gate, enters
  QUAL, and mixes into the group key. Every honest member that derives a share touching that dealer
  gets a **wrong share**, so the epoch key is **undecryptable**. On the transparent path there is no
  channel to complain: transparent members carry no account, so `MsgDkgComplaint`'s
  `memberIndexByAccount` returns 0 → **"not a member"** for everyone.
- **Impact:** a **single** Byzantine dealer surviving in QUAL **permanently bricks an epoch's
  decryption. Unhealable** — no complaint, no justify, no recovery short of a full membership-change
  rekey (which the same dealer can re-poison).
- **Proof:** `TestRepro_ByzantineDealerInQual_BreaksLiveness_NoComplaintRecourse` **PASSES** —
  variant-1 (unopenable) and variant-2 (openable-but-wrong) each leave **only 8/14 partials passing
  DLEQ**; the `[no-recourse]` assertion confirms the complaint path is unreachable on the transparent
  path. (Contrast: `TestOnChainDKG_ComplaintDisqualifiesCheater` PASSES — the complaint machinery
  **works on the legacy DECLARED/account path**; it is only the transparent VE path that has no way
  to reach it.)

### HIGH-3 — The transparent (vote-extension) DKG has NO complaint/justify round at all (root cause of HIGH-2; unhealable liveness DoS)

- **Where:** `x/encmempool/keeper/voteext.go:307` (`ConsumeVoteExtensions` ingests announcements,
  dealings, and shares **by shape only — there is no complaint phase**) ; root cause also
  `x/encmempool/types/voteext.go:34` (no complaint field on the VE) +
  `x/encmempool/dkgnode/enckey.go:177` (`DeriveShares` sums `X_p = Σ_{i∈QUAL} f_i(p)` over **ALL**
  QUAL dealers — one bad dealer corrupts every derived share) + `x/encmempool/keeper/dkg.go:385`
  (`finalizeRound`'s `disq` set is populated **only** from `IterateComplaints`, which is **never
  written on the transparent path**).
- **Relationship to HIGH-2:** HIGH-2 is the exploit; HIGH-3 is the structural root — the transparent
  path traded away the GJKR-style complaint+justify round that the declared path retains, so a
  proven-bad dealer can never be excluded from QUAL. Fixing HIGH-3 (add the round) closes HIGH-2.
- **Impact:** unhealable liveness DoS on epoch decryption by any single Byzantine QUAL dealer.
- **Proof:** same repro as HIGH-2.

### Notable additional residuals (part of the 19; medium-class, non-blocking-but-material)

- **Defer-cap fairness is per-SUBMITTER, and submitter identity is free → sybil defeats it.**
  `TestProbe_SybilDefeatsDeferCapFairness` **PASSES**: the fair-share cap holds against 1 flooding
  identity but is **DEFEATED by 200 sybil identities of equal volume** (honest ciphertext
  `granted_grace = false`, `cap_dropped = true`). **This qualifies mission objective (a)'s "fair"
  claim:** the live 38/38/38/38 fairness was proven with a **small fixed set of submitters**; it
  does NOT hold under a sybil spray. Whether this matters depends on whether encmempool submission is
  permissioned/costly enough to price sybils — a design decision to record, not silently assume.
- **Overflow-magnitude stake silently kills the stake-drift rekey.**
  `TestC7_BB_OverflowRecoveredNoHaltNoRekey` **PASSES**: pathological stake magnitudes make the drift
  metric panic every block — **recovered, no halt, no fork** — but the enabled rekey then **NEVER
  fires (feature silently dead) + per-block panic-event spam.** Default-off, so not a live risk
  today; but an operator who enables `DkgRekeyOnStakeDriftBps` on a chain with extreme stake
  magnitudes gets a silently-dead feature.

The remaining ~14 findings are medium/low/informational and are the external auditor's starting
material (§5). Cycle-6's committed GREEN regressions landed in `abd6457e`
(`byzantine_dkg_test.go`, `deferral_cap_live_test.go`, `fuzz_stakeweight_test.go`,
`storm_determinism_test.go`). The adversarial repros that DEMONSTRATE the three HIGH findings live in
the independent audit-probe suites (`audit_c6_*` / `audit_c7_*` / `zzz_audit6_*` / `zzz_audit_c7_*`),
**currently untracked** in the worktree — promote them to committed regressions on the fix cycle
(same disposition as the cycle-5 `audit_c5_*` probes).

---

## 5. Residuals & the EXTERNAL-audit focus list

### The three HIGH blockers to ENABLE (must fix + re-audit before turning the feature on)

1. **HIGH-1 — verify decryption-share DLEQ proofs at INGEST.** In `IngestDecryptShareFromVE`
   (`voteext.go`, before `SetEncShare` at :453) compute `Y = SharePubKey(commitments, s.Index)` from
   the epoch's committed public commitments and reject any share that fails
   `VerifyDecryptShare(e.A, share, Y, proof)` — so only verified shares are ever stored and the
   raw-count gate at `abci.go:488` equals the verified count. (Defence-in-depth: in
   `recoverSharedSecret`, route `RecoverVerified`'s "too few VERIFIED partials" outcome to the
   **defer/heal** branch, i.e. treat it as `errNotEnoughShares`, not the hard-drop branch — so even a
   missed verification cannot skip the grace.)
2. **HIGH-2 / HIGH-3 — add a share-validity gate and a complaint/justify round to the transparent
   path.** This is the deep fix and the primary escalation target:
   (i) on consuming dealings, each member verifies that every enc-share addressed to a point IT owns
   opens AND matches the dealer's Feldman commitments (`VerifyShareAgainstCommitments`);
   (ii) add a **complaint field to `types.VoteExtension`** and a **complaint→justify phase to
   `ConsumeVoteExtensions`** so `finalizeRound`'s `disq` set is actually populated on the transparent
   path (today it is only ever written from the never-reached `IterateComplaints`);
   (iii) `FinalizePublicWeighted` must **exclude a complaint-proven-bad dealer from QUAL**, and
   `DeriveShares` must sum only over the healthy QUAL set. Without a justify step an honest dealer
   can be griefed out; without the complaint step a bad dealer can never be removed — the round needs
   both.

### Required regardless of the above

3. **External professional audit REQUIRED before ANY mainnet reliance** on the encrypted mempool's
   confidentiality. Six internal adversarial cycles are exhaustive but are **not** an external audit.
   Hand the firm this §4/§5, the full `audit_c6_*`/`audit_c7_*` probe corpus, and the two live
   verdict runs (cycle 5, cycle 6) as starting material. **No external audit has been performed.**
4. **Sybil-vs-defer-cap-fairness (§4 residual).** Decide whether encmempool submission is costly
   enough to price sybils, or add a per-cost/stake weighting to the defer-cap fair-share.
5. **Drift-metric overflow robustness (§4 residual).** If the stake-drift rekey will ever be enabled,
   make the metric overflow-total (it self-recovers today but the feature silently dies).
6. **The decrypt bar is `> 2/3 − 2n/S`** (≈ 54.7 % at defaults), NOT ">2/3" — an honest-public-
   statement obligation for anyone quoting the confidentiality threshold.
7. **Committee stake ≠ total bonded stake** (top-N by stake; all fractions are of snapshotted
   committee stake) — pre-existing, inherent to bounding VE size.
8. Carried non-blocking deferrals from cycle 2, unchanged: injected blob occupies `Txs[0]`; lenient
   `ProcessProposal` (a Byzantine proposer can stall DKG *progress*, not fork/halt); remote-signer/KMS
   nodes safely non-participate.

---

## 6. Design reference — what "transparent" means and how it is wired (stable since cycle 1)

### The goal
A bonded validator that simply **runs the binary** becomes a DKG member automatically: **no separate
daemon**, **no account/fee setup**, **no manual enc-key registration**, **no declared member list**.

### The three pillars

**Pillar 1 — In-node auto-participation via ABCI++ vote extensions** (`evmd/dkg_voteext.go`):

| Phase | Handler | What it does |
|-------|---------|--------------|
| `ExtendVote` | `dkgExtendVoteHandler` | Packs `{EncPubKey + PoP, Feldman dealing, DLEQ-proved per-eval-point decryption shares}` into the precommit's `VoteExtension`. Node-local. |
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` | Lenient structural check only; all crypto/membership/dedup enforced deterministically on-chain later. **(Note: HIGH-1/2/3 are exactly the "enforced later" gaps — shape is checked, share/dealing validity is not, and there is no complaint channel.)** |
| `PrepareProposal` | `wrapDkgPrepareProposal` | Prepends the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` | Self-certifies `Txs[0]` with `ValidateVoteExtensions`, strips it, delegates. Gated by `veActive` (HIGH-1/cycle-1 fix). |
| `PreBlock` | `consumeDkgVoteExtensions` → `keeper.ConsumeVoteExtensions` | Resolves consensus address → operator; deterministic canonicalizing consume. **No complaint phase (HIGH-3).** |

**Pillar 2 — Transparent key.** A secp256k1 ECIES key per member, minted with zero operator action
(`dkgnode.LoadOrCreateEncKey`, `<home>/dkg_enc_key.json`, 0600), auto-announced with an operator-bound
PoP (cycle-2), self-identity by OPERATOR (cycle-2).

**Pillar 3 — Members = bonded validators.** `TransparentMembers` derives the committee from the bonded
set: top-N by stake (`EffectiveMaxMembers`), clamped to `floor(S/8)` seats, each member's eval points
apportioned by stake. **Members carry NO account address (`voteext.go:191`) — which is why the
account-based complaint path is unreachable (HIGH-2/3).** Rekey triggers: membership change, failed-
round retry, and the opt-in cadence/stake-drift (cycle-5, default-off).

### Determinism contract (the #1 fork risk — held through every live run, including cycle 6)
All determinism is confined to the consume half and the EndBlock DKG state machine, both pure
functions of `(committed state, entries)`. **Cycle-6 confirms this held even under every adversarial
probe** — the 3 HIGH findings are liveness/DoS, NOT divergence: `app_hash` never diverged (§2.5).

### Dormancy / kill-switch
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` AND vote extensions are active;
the cycle-5 triggers additionally require their param `> 0`. All enabling flags default false/0.
**All three HIGH findings are on the ENABLED path — none is reachable while dormant.**

---

## 7. GO / NO-GO

### Verdict: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE**; dormant-by-default MERGE is safe.

1. **NO-GO to enable the transparent DKG** on any chain relied on for confidentiality until HIGH-1/2/3
   (§4) are fixed and re-audited. They are liveness/anti-MEV DoS on the encrypted-mempool guarantee
   (no fork, no halt), reproduced against the real consensus entry points.
2. **Merging DORMANT is safe.** With default params (`DkgEnabled = DkgTransparent = false`, drift
   triggers 0) the binary is byte-behavior-identical to `17101a12`; none of the three HIGH findings is
   reachable; both modules build green; the full regression + probe suite passes.
3. **External professional audit REQUIRED before ANY mainnet reliance**, independent of (1). The
   internal cycles are exhaustive but not a substitute. **No external audit has been performed.**
4. **The release decision belongs to Jason** — merge timing, the HIGH-1/2/3 fix cycle, VE scheduling,
   drift-trigger enablement, and the enable vote are his call.

### What is safe today
Merging this branch **without enabling** is safe. What is NOT safe is turning the feature on: three
HIGH liveness findings are open.

---

## 8. Scorecard

| Item | State |
|------|-------|
| Builds (evmd + root modules) | ✅ exit 0 (root, evmd, `go vet` all clean) |
| Full test + probe suite (`-tags test`) | ✅ PASS (the repro tests pass by DEMONSTRATING the findings) |
| Consume-path + EndBlock determinism (unit + live) | ✅ 0 divergence, every cycle incl. cycle-6 (40+ heights × 6 nodes, 2 resyncs) |
| Transparent experience (no daemon/account/fee/key/list) | ✅ proven live, cycles 1–6 |
| Kill-switch / dormancy | ✅ default-off; all 3 HIGH findings unreachable while dormant |
| HIGH-1/2/3/4 (cycles 1–4) + cycle-3 H-A/H-B + M/L | ✅ closed |
| **(a) 128-entry defer-cap** | ✅ **PROVEN LIVE (marquee)** — cap engages, bounded 128, H2-safe, heals, deterministic … ⚠️ **but fairness is sybil-defeatable (§4)** |
| **(b) Boundary liveness** | ✅ live at 32% offline / 68% online, n=5–6; larger-n via unit fuzz (not live) |
| **(c) Stake-drift storm** | ✅ live — 8 delegations → 2 rekeys 20 blocks apart (dampener held) |
| **(d) Byzantine dealer — absent-dealer (live-injectable)** | ✅ live QUAL-exclusion + finalize, fork-free |
| **(d) Byzantine dealer — corrupt-dealing / no-complaint-round** | ❌ **HIGH-2 / HIGH-3** — single QUAL dealer permanently bricks epoch decryption, NO recourse (§4) |
| **Unverified-share count padding** | ❌ **HIGH-1** — `<1/3`-stake adversary converts healable deferral → hard drop (§4) |
| **(e) Determinism through all of the above** | ✅ 0 app-hash divergence (the 3 HIGHs are liveness/DoS, not forks) |
| Multi-node live verdict run (cycle 6) | ✅ GREEN on all 5 objectives, 6 nodes |
| Security audit (cycle 6) | ❌ **`AUDIT_CLEAN = NO`** — 19 findings, **3 HIGH** (§4) |
| External audit | ❌ NOT DONE — **required before any mainnet reliance** regardless |
| **Enable on a real chain** | ❌ **NO-GO** — fix HIGH-1/2/3 + re-audit first |
| **Merge DORMANT (feature off)** | ✅ safe — byte-behavior-identical to `17101a12` |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release,
and do NOT enable the transparent DKG until the three HIGH findings are closed and re-audited.*
