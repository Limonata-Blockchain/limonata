# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-05 (audit cycle 7 — DLEQ-verify-at-ingest fix + adversarial re-audit)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** `e6e198c1` — *harden(encmempool/dkg): cycle-7 — DLEQ-verify VE decryption
shares at ingest; route insufficient-verified to the grace defer*, atop `abd6457e` (cycle-6
exhaustive re-audit) → `b25c89dc` → `73b1dd1e` → `d8976687` → `2c2a271d` → `19d5cb6f` → `17101a12`

---

## VERDICT: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE** (dormant-by-default MERGE still safe; external audit still required regardless)

The cycle-7 fix **genuinely closes the targeted HIGH** — the `<=1/3`-stake chaff-padding hole that
turned the cycle-3 H-B healable grace-deferral into a hard drop — and that closure was **proven LIVE
end-to-end on a fresh isolated 8-node network** (§3). That is real, verified progress on the exact
thing cycle 6 flagged as HIGH-1.

**But the fix is NOT a net-clean win, and it is NOT ready to enable.** The same cycle-7 adversarial
re-audit that validated the closure found the fix **introduced TWO NEW HIGH-severity DoS findings**
(§4), both on the *new* crypto it added to the consensus-critical PreBlock path — and one of them is
**halt-class**, strictly worse than the deterministic-drop DoS it replaced. Separately, the two
cycle-6 HIGHs this fix did not scope (Byzantine QUAL dealer / no complaint round) **remain open**.

Net inventory of OPEN HIGH findings going into any enable decision: **4**.

| # | HIGH finding | Origin | Status after cycle-7 |
|---|--------------|--------|----------------------|
| — | Unverified VE decryption-share COUNT PADDING → healable defer becomes hard DROP | cycle-6 HIGH-1 | ✅ **CLOSED** (this fix; live-proven §3) |
| **A** | **Unbounded per-VE ingest-DLEQ-verify → single committee member stalls consensus every block (halt-class liveness DoS)** | **cycle-7 (introduced by the fix)** | ❌ **OPEN — NEW** |
| **B** | **`<=1/3`-stake PreBlock compute DoS: uncapped, re-verified-every-block DLEQ verification of REJECTED chaff** | **cycle-7 (introduced by the fix)** | ❌ **OPEN — NEW** |
| **2** | Byzantine QUAL dealer permanently bricks an epoch's decryption, no complaint recourse | cycle-6 HIGH-2 | ❌ **OPEN** (out of scope for this fix; surfaces untouched) |
| **3** | Transparent VE-DKG has no complaint/justify round at all (root cause of #2) | cycle-6 HIGH-3 | ❌ **OPEN** (out of scope for this fix; surfaces untouched) |

**What this means concretely:**

- **NO-GO to ENABLE** the transparent DKG on any chain relied on for confidentiality. One HIGH was
  closed; **two new HIGHs (one halt-class) were opened by the closure itself**, and two pre-existing
  unhealable HIGHs are untouched. The fix moved an expensive pure-crypto verification (`O(t)`
  elliptic-curve ops per share) onto the PreBlock consensus path **without a per-block compute/count
  bound and without caching rejections** — trading a `<=1/3`-stake *forced-drop* DoS for a `single-
  member` *stall-every-block* DoS. That is a lateral-to-worse move for the enable decision, even
  though the specific chaff-padding mechanism is genuinely gone.
- **Merging the branch DORMANT is still safe.** All four HIGH findings live on the *enabled*
  transparent decrypt/DKG path. With `DkgEnabled = DkgTransparent = false` (the shipped default) the
  binary is byte-behavior-identical to `17101a12`; none is reachable. Landing the branch dormant
  preserves the work + the committed probe corpus and changes nothing operationally.
- **Do NOT represent "the chaff hole is closed" as "the branch is fixed."** The closure is real, but
  in isolation it is misleading: the enable-blocking HIGH count went **3 → 4**, not 3 → 2.
- **External professional audit is STILL REQUIRED before ANY mainnet reliance**, independent of the
  four findings above. Seven internal adversarial cycles are not a substitute. We do NOT claim an
  external audit has been performed.
- **The release decision belongs to Jason.** This report states technical readiness only.

---

## 1. Cycle history — seven adversarial cycles

| Cycle | Commit(s) | Result |
|-------|-----------|--------|
| **1** | `f8615df2` | Transparent in-node DKG built (VE auto-participation, transparent enc key, members = bonded set). Live 4→5-node, 0 divergence. Audit: **NO-GO, 4 HIGHs**. |
| **2** | `a75b027f` | HIGH-1 closed (VE-coupled `veActive` guard), HIGH-2/4 closed (operator-bound PoP + operator-indexed self-id). **HIGH-3 SURVIVED — fix at wrong layer.** **NO-GO.** |
| **3** | `19d5cb6f` | HIGH-3 closed at the **crypto layer**: stake-weighted secret sharing. Audit: **NO-GO, 11 findings** — H-A (degenerate `S<n`), H-B (`t` stranded honest supermajorities AND the shortfall path **silently dropped** the ciphertext), + M/L. |
| **4** | `2c2a271d` | All 6 cycle-3 findings closed: `t = floor(2S/3) − n + 1`, `S ≥ 8n` coupling, non-silent **32-block grace deferral**. Audit: **14 findings, 0 crit/high → CLEAN**. 4-node run **GO**. |
| **5** | `73b1dd1e` | Both cycle-4 deferrals closed (stake-drift rekey; grace path live-proven heal+strand), minimal + default-off. Audit: **11 findings, 0 crit/high → CLEAN**. 4-node run **GO**. Defer-cap remained unit-test-only. |
| **6** | `abd6457e` / `b25c89dc` | Exhaustive re-audit on 6 nodes: **all 5 mission objectives proven LIVE** incl. the 128-entry defer-cap. 6-lens audit: **19 findings, 3 HIGH → `AUDIT_CLEAN = NO`** (HIGH-1 chaff-padding, HIGH-2 Byzantine QUAL dealer, HIGH-3 no complaint round). |
| **7** | `e6e198c1` (**this report**) | Fix for cycle-6 HIGH-1: **DLEQ-verify decryption shares at INGEST** + verified-count-by-construction + defer-routing backstop. **HIGH-1 CLOSED, live-proven on 8 nodes** (§3). But the re-audit found **the fix introduced 2 NEW HIGH DoS findings** (§4-A/B, one halt-class); cycle-6 HIGH-2/HIGH-3 remain open. **24 findings, `AUDIT_CLEAN = NO`.** |

**Held across every cycle (never regressed):** the transparent experience (no daemon/account/fee/key/
list), consume-path + EndBlock determinism / zero app-hash divergence, dormancy + kill-switch, bounded
VE/dealing *bytes*, flood/refcount invariants (any final EncTx drop goes through `releaseEncTx`),
legacy declared-DKG path byte-identical.

---

## 2. The cycle-7 fix — what it does

Cycle-6 HIGH-1: `IngestDecryptShareFromVE` (`voteext.go`) stored a decryption share carried on a vote
extension after checking only operator-membership + point-ownership + first-wins — it did **not**
verify the share's DLEQ proof. So a committee member (a `<=1/3`-stake MINORITY) could store
structurally-valid-but-cryptographically-garbage **chaff** shares at its own owned eval points. That
chaff (1) inflated the RAW stored count past `need` (`abci.go:499` count gate) and (2) marked the
member "present" in the `DecryptingSetMeetsStake` map (`abci.go:516-522`) — both computed from the RAW
shares BEFORE any DLEQ check. Control reached `dkg.RecoverVerified`, which dropped the chaff and
returned a **non-`errNotEnoughShares`** error → `decryptMatured` hit the **hard-drop** branch
(`abci.go:341`, `encmempool_decrypt_failed`) instead of the within-grace **DEFER** branch
(`abci.go:319`). A 25%-stake coalition could thereby force any matured-but-transiently-short ciphertext
to DROP at maturity rather than defer + heal from late honest shares — nullifying the 32-block
`StrandedDecryptGrace` exactly in its protection window (anti-MEV / liveness DoS).

**The belt-and-suspenders fix (commit `e6e198c1`):**

1. **DLEQ-verify at ingest** — `IngestDecryptShareFromVE` now calls `verifyDecryptShareDLEQ`
   (`voteext.go:469`, :498-513) **before** `SetEncShare`: it recomputes `Y = SharePubKey(commitments,
   index)` from the epoch's installed `ActiveThresholdKey` commitments and verifies `D = x·A` against
   the ciphertext's ephemeral `A`, the exact check `RecoverVerified` does at combine time. A chaff
   share is rejected at ingest (`encmempool_dkg_ve_share_rejected`) and **never enters state**, so it
   can neither inflate the count nor mark its member present. Verification is a **pure function** of
   committed state + share bytes — identical verdict on every node, mandatory in this PreBlock path.
2. **Verified-count-by-construction** — because only verified shares are stored, the `abci.go:499`
   count gate and the `abci.go:516-522` `memberPresent` stake map now govern on the DLEQ-verified count
   automatically (`stored == verified` on the transparent path). No separate gate needed.
3. **Defer-routing backstop** — `dkg.RecoverVerified` now wraps a sentinel `ErrInsufficientVerified`
   (`proof.go:255`, `abci.go:541`) when fewer than `t` partials pass DLEQ; `recoverSharedSecret` routes
   that into the **same within-grace DEFER branch** as `errNotEnoughShares`, not the hard-drop branch.
   This defends any share that reached state WITHOUT ingest verification (a legacy/declared msg path or
   a genesis import). **By design it is UNREACHABLE on the transparent path** (fix #1 pre-verifies
   every stored share), so it is a pure backstop, exercised only by the committed `SetEncShare`-inject
   test.

Preserves every cycle-1..6 fix (defer-cap, boundary liveness, stake-drift rekey, byzantine handling,
threshold inequalities, dormant-by-default); the stake gate and `errStakeMinority` path are unchanged.
The fix touches only `voteext.go`, `abci.go`, `proof.go` (plus tests) — it does **not** touch
`onchain.go` / `endblock.go` / the complaint path, which is why cycle-6 HIGH-2/HIGH-3 are untouched.

---

## 3. Live chaff-attack proof — GREEN on a fresh isolated 8-node network

The fix was driven end-to-end on a fresh 8-node throwaway (real genesis, live delegation, live flood,
a mixed **real-fix / variant** binary set), attacking the exact vulnerable gates:

1. **The fix closes the hole on a scenario that GENUINELY reaches the vulnerable gates.** Honest serve
   at maturity = **116 points**; the attacker adds **chaff = 64** → `serve+chaff = 180 >= t = 163`,
   i.e. the chaff *would have crossed the count threshold* pre-fix (`180 >= 163`) while honest-alone is
   short (`116 < 163`). The fixed ingest verification kept the stored/verified count at **exactly 116
   (not 180)** — **384 chaff shares rejected at ingest**, attacker never marked present — so the
   matured-but-short ciphertext **DEFERRED** (`encmempool_decrypt_missed`) instead of hard-dropping,
   and **HEALED to the correct plaintext** from late honest shares within the 32-block grace. The
   `have = 116-not-180` count is direct causal evidence that ingest verification is what prevents the
   threshold crossing.
2. **The fix does NOT mask real faults.** A genuinely-malformed ciphertext still **hard-drops** (AEAD
   failure at `decrypt_failed`) — the defer-routing does not launder a real fault into the heal grace.
3. **Determinism is airtight.** **135 heights** across every scenario show **byte-identical app-hash**
   across the mixed real-fix/variant network, and a node **resynced from genesis reproduces every
   attack height byte-for-byte** — confirming VE-ingest DLEQ verification is the required pure /
   deterministic consensus function it must be.
4. **All five cycle-6 greens re-proven LIVE:** defer-cap bounded + fair, boundary liveness, stake-drift
   rekey dampened, absent-dealer QUAL exclusion, honest decrypt.

**Two honest caveats — neither undermines the closure, both are recorded:**

- **(a) The counterfactual is arithmetic + a unit test, not a live pre-fix drop.** The run proved the
  FIXED behavior on the vulnerable-path scenario rather than also booting a pre-fix binary live to
  watch the drop. The "would-have-dropped" claim rests on the committed unit test `TestC7...` plus the
  `have = 116-not-180` arithmetic (`180 >= t=163` pre-fix vs `116 < t=163` post-fix). That is direct
  causal evidence, but it is not a side-by-side live A/B.
- **(b) Fix #3 is by-design unreachable on the live transparent path.** Because fix #1 pre-verifies
  every stored share, the live run exercises **fix #1 + #2 only**; fix #3's `ErrInsufficientVerified →
  defer` backstop is covered by the committed test that injects an unverified share via `SetEncShare`
  (the legacy/genesis door it exists to guard), not by the live network.

**Operational note (recorded for the next runner):** the core proofs ran cleanly; the resync/teardown
hit friction from the documented `pkill` self-kill gotcha (command strings containing the node path)
and a node7 double-process blockstore corruption — both resolved via **port-targeted `fuser` kills**,
neither affecting any proven behavior.

**Net on the live run: GREEN — the fix demonstrably closes the chaff-padding hole and heals.** What the
live run did NOT and could NOT surface is the *cost* of the new verification under adversarial volume;
that is what the code audit found next (§4).

---

## 4. Cycle-7 re-audit — **24 findings, `AUDIT_CLEAN = NO`**, TWO NEW HIGH DoS introduced by the fix

The re-audit re-attacked the change with the same discipline as cycle 6, plus a dedicated
**consensus/halt lens** and **defer-routing lens** on the new code (committed probes:
`zzz_audit_c7_consensus_probe_test.go`, `zzz_audit_c7_defer_lens_probe_test.go`,
`audit_c7_defer_drop_probe_test.go`). Total findings rose **19 → 24**. The chaff-padding HIGH is
closed, but the closure opened two new HIGHs on the crypto it moved onto the hot path. **Neither is a
consensus-safety break** (the probes prove the verify path never panics, and the ingest verdict is
order-independent + deterministic — app-hash held across all 135 live heights); both are **liveness /
availability DoS on the enabled path**, and finding A is **halt-class**.

### HIGH-A (NEW) — Unbounded per-VE ingest-DLEQ-verify: a single committee member stalls consensus every block (halt-class liveness DoS)

- **Where:** `x/encmempool/keeper/voteext.go:322-328` (`ConsumeVoteExtensions` Phase 3 loops over
  **every** share in **every** extension with **no count cap**) → `:469` (per-share `verifyDecryptShare
  DLEQ` call) → `:498-513` (`verifyDecryptShareDLEQ` — `ParseCommitmentPoints` + `SharePubKey` +
  `VerifyDecryptShare`, an **`O(t)` elliptic-curve** computation per share). The only bound on how many
  shares a member can submit is **byte size**: `VoteExtMaxBytes = 1 MiB` (`x/encmempool/types/voteext.go:32`),
  and `evmd/dkg_voteext.go` `VerifyVoteExtension` caps **bytes only** — never share count.
- **Mechanism:** a decryption share is ~100–200 bytes, so a 1 MiB vote extension carries **thousands**
  of them. A single committee member packs its extension with thousands of shares (chaff or not) →
  thousands of `O(t)` DLEQ verifications executed in **PreBlock, on every node, every block**. PreBlock
  is on the consensus-critical path; a large enough batch stalls block production network-wide.
- **Impact:** **halt-class liveness DoS from ONE committee member.** This is strictly worse than the
  cycle-6 HIGH-1 it replaced (that was a deterministic *drop*, no halt). The fix removed a forced-drop
  DoS and introduced a stall-the-chain DoS.
- **Remediation (cycle-8):** cap the **number** of shares verified per extension / per member per block
  (a small multiple of the member's owned eval-point count is sufficient — a member can never
  legitimately owe more shares than it owns points across in-flight ciphertexts), independent of the
  byte cap.

### HIGH-B (NEW) — `<=1/3`-stake PreBlock compute DoS: uncapped, re-verified-EVERY-BLOCK DLEQ verification of REJECTED chaff

- **Where:** `x/encmempool/keeper/voteext.go:462-466` (the first-wins dedup consults `CollectShares`,
  i.e. **already-STORED** shares only) + `:479` (a REJECTED chaff share returns `false` **before**
  `SetEncShare` — it is never stored) + `:469`/`:498-513` (the verify) + `:322-328` (the uncapped loop).
- **Mechanism:** the fix's own comment (`voteext.go:459-461`) claims verification "runs exactly ONCE
  per share … never a per-block one." **That holds only for shares that PASS.** A rejected chaff share
  is never stored, so the first-wins dedup never suppresses it; the attacker re-sends the identical
  chaff on a fresh vote extension **every block**, and because nothing recorded the prior rejection it
  is **re-verified from scratch every block** until the target ciphertext matures or drops. A
  `<=1/3`-stake minority sustains a per-block DLEQ-verification tax on **all** nodes for the full life
  of every in-flight ciphertext.
- **Impact:** sustained `<=1/3`-stake compute DoS on PreBlock; compounds HIGH-A (the uncapped loop is
  the multiplier, the missing negative-cache is the persistence). Deterministic, no fork — availability.
- **Remediation (cycle-8):** short-circuit before the `O(t)` verify (cheap structural pre-checks first),
  and/or negatively-cache a rejected `(decryptHeight, seq, index)` for the ciphertext's lifetime so
  identical chaff is rejected in `O(1)` on re-send rather than re-verified.

**Both new HIGHs share one root cause:** the fix added an **expensive, uncapped, un-cached pure-crypto
verification into the consensus-critical PreBlock path.** The functional closure (§3) is correct; the
*cost* of the closure is unbounded. Cycle-8 must bound it before the chaff-padding fix is a net
positive.

### Carried-open cycle-6 HIGHs (out of scope for this fix; surfaces untouched — verified from the diff)

- **HIGH-2 — Byzantine QUAL dealer permanently bricks an epoch's decryption, no complaint recourse.**
  A QUAL dealer that corrupts enc-shares to points it does not own passes the shape-only gate
  (`onchain.go` `FinalizePublicWeighted`), enters QUAL, and poisons every derived share; the transparent
  path carries no account (`voteext.go` `TransparentMembers`) so `MsgDkgComplaint` is unreachable. **Still
  open** — `e6e198c1` touches neither `onchain.go` nor `endblock.go`.
- **HIGH-3 — the transparent VE-DKG has NO complaint/justify round at all** (root cause of HIGH-2;
  `finalizeRound`'s `disq` set is only ever written from the never-reached `IterateComplaints`). **Still
  open** — the fix adds no complaint field/phase.

### Notable residuals carried from cycle-6 (medium-class, non-blocking-but-material)

- **Defer-cap fairness is per-SUBMITTER and submitter identity is free → sybil defeats it** (fair share
  holds vs 1 flooding identity, defeated by 200 sybils). Qualifies mission objective (a)'s "fair" claim.
- **Overflow-magnitude stake silently kills the stake-drift rekey** (recovered, no halt, but the enabled
  rekey never fires + per-block panic-event spam). Default-off, so not a live risk today.

The remaining findings are medium/low/informational — the external auditor's starting material (§5).

---

## 5. Residuals & the EXTERNAL-audit focus list

### The FOUR HIGH blockers to ENABLE (must fix + re-audit before turning the feature on)

1. **HIGH-A (cycle-7, NEW) — bound the per-block ingest-verify work.** Cap the number of decryption
   shares verified per vote extension / per member per block (a small multiple of owned eval points),
   independent of `VoteExtMaxBytes`. Without this, one member can stall consensus every block.
2. **HIGH-B (cycle-7, NEW) — stop re-verifying rejected chaff every block.** Negatively-cache a rejected
   share (or cheap-pre-check before the `O(t)` DLEQ) so identical chaff costs `O(1)` on re-send, for the
   ciphertext's lifetime. Fixing A+B makes the cycle-7 chaff-padding closure a genuine net-positive.
3. **HIGH-2 / HIGH-3 (cycle-6, carried) — add a share-validity gate AND a complaint/justify round to the
   transparent path.** The deep fix: (i) verify every enc-share against the dealer's Feldman commitments
   on consume; (ii) add a complaint field to `types.VoteExtension` + a complaint→justify phase to
   `ConsumeVoteExtensions` so `finalizeRound`'s `disq` set is populated on the transparent path;
   (iii) exclude a complaint-proven-bad dealer from QUAL and sum `DeriveShares` only over the healthy set.

### Required regardless of the above

4. **External professional audit REQUIRED before ANY mainnet reliance** on the encrypted mempool's
   confidentiality. Seven internal adversarial cycles are exhaustive but are **not** an external audit.
   Hand the firm §3/§4/§5, the full `audit_c6_*` / `audit_c7_*` / `zzz_audit_c7_*` probe corpus, and the
   cycle-5/6/7 live verdict runs. **No external audit has been performed.**
5. **Sybil-vs-defer-cap-fairness** (cycle-6 residual) — price sybils or weight the defer-cap fair-share.
6. **Drift-metric overflow robustness** (cycle-6 residual) — make the metric overflow-total if the
   stake-drift rekey will ever be enabled.
7. **The decrypt bar is `> 2/3 − 2n/S`** (≈ 54.7 % at defaults), NOT ">2/3" — honest-statement obligation.
8. **Committee stake ≠ total bonded stake** (top-N by stake; fractions are of snapshotted committee
   stake) — inherent to bounding VE size.
9. Carried non-blocking deferrals from cycle 2, unchanged: injected blob occupies `Txs[0]`; lenient
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
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` | Lenient structural check + **BYTE** cap only (`VoteExtMaxBytes`). **(Note: cycle-7 HIGH-A/B are exactly here — there is no per-block SHARE-COUNT cap, so bytes-only bounding lets one member submit thousands of shares that each cost an `O(t)` DLEQ verify in PreBlock.)** |
| `PrepareProposal` | `wrapDkgPrepareProposal` | Prepends the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` | Self-certifies `Txs[0]` with `ValidateVoteExtensions`, strips it, delegates. Gated by `veActive`. |
| `PreBlock` | `consumeDkgVoteExtensions` → `keeper.ConsumeVoteExtensions` | Resolves consensus address → operator; deterministic canonicalizing consume. **Cycle-7: now DLEQ-verifies each decryption share at ingest (fix), but the consume loop is uncapped in share count (HIGH-A) and rejected chaff is re-verified every block (HIGH-B). No complaint phase (HIGH-3).** |

**Pillar 2 — Transparent key.** A secp256k1 ECIES key per member, minted with zero operator action
(`dkgnode.LoadOrCreateEncKey`, `<home>/dkg_enc_key.json`, 0600), auto-announced with an operator-bound
PoP (cycle-2), self-identity by OPERATOR (cycle-2).

**Pillar 3 — Members = bonded validators.** `TransparentMembers` derives the committee from the bonded
set: top-N by stake (`EffectiveMaxMembers`), clamped to `floor(S/8)` seats, each member's eval points
apportioned by stake. **Members carry NO account address — which is why the account-based complaint
path is unreachable (HIGH-2/3).** Rekey triggers: membership change, failed-round retry, and the opt-in
cadence/stake-drift (cycle-5, default-off).

### Determinism contract (the #1 fork risk — held through every live run, including cycle 7)
All determinism is confined to the consume half and the EndBlock DKG state machine, both pure functions
of `(committed state, entries)`. **Cycle-7 confirms this held even with DLEQ verification moved into
PreBlock** — the ingest verdict is a pure, order-independent, non-panicking function (proven by the
consensus-lens probes), and `app_hash` never diverged across 135 live heights + a genesis resync (§3).
The four HIGH findings are liveness/availability/DoS, NOT divergence.

### Dormancy / kill-switch
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` AND vote extensions are active;
the cycle-5 triggers additionally require their param `> 0`. All enabling flags default false/0.
**All four HIGH findings are on the ENABLED path — none is reachable while dormant.**

---

## 7. GO / NO-GO

### Verdict: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE**; dormant-by-default MERGE is safe.

1. **NO-GO to enable the transparent DKG** on any chain relied on for confidentiality. The targeted
   cycle-6 HIGH-1 (chaff-padding) is closed and live-proven, but the closure **introduced HIGH-A
   (halt-class, single-member) and HIGH-B (`<=1/3`-stake, re-verify-every-block)**, and cycle-6 HIGH-2/
   HIGH-3 remain open — **4 open HIGH findings**, all liveness/availability DoS (no fork, no consensus
   halt-via-divergence), all reproduced against the real consensus entry points.
2. **Merging DORMANT is safe.** With default params (`DkgEnabled = DkgTransparent = false`, drift
   triggers 0) the binary is byte-behavior-identical to `17101a12`; none of the four HIGH findings is
   reachable; both modules build green; the full regression + probe suite passes.
3. **External professional audit REQUIRED before ANY mainnet reliance**, independent of (1). **No
   external audit has been performed.**
4. **The release decision belongs to Jason** — merge timing, the cycle-8 HIGH-A/B + HIGH-2/3 fix cycle,
   VE scheduling, drift-trigger enablement, and the enable vote are his call.

### What is safe today
Merging this branch **without enabling** is safe and preserves the fix + the committed probe corpus.
What is NOT safe is turning the feature on: four HIGH liveness findings are open, two of them newly
introduced by the cycle-7 fix itself.

---

## 8. Scorecard

| Item | State |
|------|-------|
| Builds (evmd + root modules, `-tags test`) | ✅ exit 0 (root, evmd, `go vet` all clean — verified this cycle) |
| Full test + probe suite (`-tags test`) | ✅ PASS (cycle-7 keeper suite green; repro/probe tests pass by DEMONSTRATING the findings) |
| Consume-path + EndBlock determinism (unit + live) | ✅ 0 divergence, every cycle; cycle-7: **135 heights byte-identical + genesis resync reproduces every attack height** |
| Transparent experience (no daemon/account/fee/key/list) | ✅ proven live, cycles 1–7 |
| Kill-switch / dormancy | ✅ default-off; all 4 HIGH findings unreachable while dormant |
| HIGH-1/2/3/4 (cycles 1–4) + cycle-3 H-A/H-B + M/L | ✅ closed |
| **cycle-6 HIGH-1 — unverified-share count padding → forced drop** | ✅ **CLOSED (cycle-7)** — DLEQ-verify at ingest; live-proven (count held 116-not-180, defers + heals) |
| **cycle-7 HIGH-A — unbounded per-VE ingest-verify (halt-class)** | ❌ **OPEN — NEW** (introduced by the fix; one member stalls consensus every block) |
| **cycle-7 HIGH-B — re-verify-every-block chaff compute DoS** | ❌ **OPEN — NEW** (introduced by the fix; `<=1/3`-stake sustained PreBlock tax) |
| **cycle-6 HIGH-2 — Byzantine QUAL dealer bricks epoch, no recourse** | ❌ **OPEN** (out of scope for this fix; surfaces untouched) |
| **cycle-6 HIGH-3 — no complaint/justify round on transparent path** | ❌ **OPEN** (out of scope for this fix; surfaces untouched) |
| Ingest DLEQ verify — pure / deterministic / order-independent / no-panic | ✅ proven (consensus-lens probes + 135 live heights) |
| Multi-node live verdict run (cycle 7) | ✅ GREEN — chaff rejected at ingest, defers + heals, real malformed still drops, 8 nodes, 0 divergence |
| Security audit (cycle 7) | ❌ **`AUDIT_CLEAN = NO`** — 24 findings, **4 open HIGH** (2 new, 2 carried) (§4) |
| External audit | ❌ NOT DONE — **required before any mainnet reliance** regardless |
| **Enable on a real chain** | ❌ **NO-GO** — fix HIGH-A/B (cycle-7) + HIGH-2/3 (cycle-6) + re-audit first |
| **Merge DORMANT (feature off)** | ✅ safe — byte-behavior-identical to `17101a12` |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release, and
do NOT enable the transparent DKG until all four HIGH findings are closed and re-audited. The cycle-7
fix closes the chaff-padding hole (live-proven) but introduces two new DoS HIGHs — it is a checkpoint,
not a green light.*
