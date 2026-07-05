# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-05 (audit cycle 8 — bound the ingest DLEQ-verify work to O(S) + adversarial re-audit)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** `b581c17d` — *harden(encmempool/dkg): cycle-8 — bound the ingest DLEQ-verify
work to O(S), closing HIGH-A + HIGH-B*, atop `934a5d2a` (cycle-7 docs) → `e6e198c1` (cycle-7 fix) →
`b25c89dc` → `abd6457e` → `73b1dd1e` → `d8976687` → `2c2a271d` → `19d5cb6f` → `17101a12`

---

## VERDICT: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE** (dormant-by-default MERGE still safe; external audit still required regardless)

The cycle-8 fix **genuinely closes the two DoS the cycle-7 fix introduced** — the halt-class HIGH-A
(unbounded per-VE ingest-DLEQ-verify) and the `<=1/3`-stake HIGH-B (rejected chaff re-verified every
block). The block's TOTAL `O(t)` DLEQ verification is now hard-bounded to `O(S)` regardless of attacker
input, and that closure was **proven LIVE end-to-end on a fresh isolated 8-node network** (§3): a
max-spray 1500-share attacker is clamped-at-ingest and peer-rejected before any per-share verify, the
per-block DLEQ work is pinned to the attacker's *owned* eval-point budget, and block time stays flat
across hundreds of blocks. That is real, verified progress on the exact thing cycle 7 flagged.

**But the fix is NOT a net-clean win, and it is NOT ready to enable.** The cycle-8 adversarial re-audit
found that the *mechanism* that bounds the attacker — control #3, a **per-`(operator, epoch)` verify
budget equal to the operator's owned eval-point count** (`voteext.go:661-668`) — is keyed by **EPOCH,
not by CIPHERTEXT**. An honest committee member legitimately owes `owned-points` shares **per
in-flight ciphertext**, but the budget grants it only `owned-points` **total per epoch per block**. So
when more than one ciphertext of the same epoch is in flight, the whole committee piles its entire
budget onto the single oldest ciphertext and **honest decryption is throttled to ~1 ciphertext / block
/ epoch** — the rest of the honest shares are budget-**deferred every block**, and any ciphertext that
cannot be drained inside the 32-block `StrandedDecryptGrace` window **HARD-STRANDS (drops)**. This
**partially regresses the cycle-7 "defers + heals" drop-DoS fix into "defers + DROPS" under ordinary
multi-ciphertext concurrency** — no attacker required, and cheaply weaponizable by a no-stake ciphertext
flood (admission is `32768 / 2048` with **no per-block rate limit**, `types.go:387`).

This regression is **confirmed by two executable, committed probes** (§4), not merely by code reading:
with 3 matured ciphertexts of one epoch and the FULL committee serving complete valid share sets for
all three in one block, only the oldest reaches threshold — **`ct1 = 32, ct2 = 0, ct3 = 0`** stored
shares — with **no attacker** and **224 of the 256-share `O(S)` ceiling unused**.

Net inventory of OPEN HIGH findings going into any enable decision: **3**.

| # | HIGH finding | Origin | Status after cycle-8 |
|---|--------------|--------|----------------------|
| **A** | Unbounded per-VE ingest-DLEQ-verify → single member stalls consensus every block (halt-class) | cycle-7 | ✅ **CLOSED** (this fix; live-proven §3) |
| **B** | `<=1/3`-stake PreBlock compute DoS: uncapped, re-verified-every-block DLEQ of REJECTED chaff | cycle-7 | ✅ **CLOSED** (this fix; live-proven §3) |
| — | Unverified VE decryption-share COUNT PADDING → healable defer becomes hard DROP | cycle-6 HIGH-1 | ✅ CLOSED (cycle-7); preserved for the SINGLE-ciphertext case |
| **T** | **Per-`(operator, epoch)` verify budget conflates per-epoch with per-CIPHERTEXT demand → honest decryption throttled to ~1 ct/block/epoch; honest ciphertexts STRAND under multi-ciphertext load (defers+heals → defers+DROPS)** | **cycle-8 (introduced by the fix)** | ❌ **OPEN — NEW** |
| **2** | Byzantine QUAL dealer permanently bricks an epoch's decryption, no complaint recourse | cycle-6 HIGH-2 | ❌ **OPEN** (out of scope; `onchain.go`/`endblock.go` untouched) |
| **3** | Transparent VE-DKG has no complaint/justify round at all (root cause of #2) | cycle-6 HIGH-3 | ❌ **OPEN** (out of scope; untouched) |

**What this means concretely:**

- **NO-GO to ENABLE** the transparent DKG on any chain relied on for confidentiality. Two HIGHs were
  closed; **one new HIGH was opened by the closure itself** (the bound that stops the attacker also
  starves honest multi-ciphertext liveness), and two pre-existing structural HIGHs are untouched. The
  cycle-8 fix is a **lateral move** for the enable decision: it converts a *compute/halt* DoS into an
  *honest-throughput / forced-strand* DoS. The compute bound is correct and necessary; its **sizing is
  wrong** — it bounds per `(operator, epoch)` where honest demand is per `(operator, epoch, ciphertext)`.
- **The 6 crit/high audit findings converge on ONE root defect** (`voteext.go:661-668`, budget keyed by
  `opEpoch{operator, epoch}` at `:483-486`, sized `b = len(member.OwnedEvalPoints())` at `:664`). They
  are six adversarial lenses (throughput, drop-DoS, healing, strand, no-stake-flood, sizing) on the same
  mis-keyed budget → **one distinct new HIGH blocker (T)**.
- **Merging the branch DORMANT is still safe.** All three open HIGH findings live on the *enabled*
  transparent decrypt/DKG path. With `DkgEnabled = DkgTransparent = false` (the shipped default) the
  binary is byte-behavior-identical to `17101a12`; none is reachable. Landing the branch dormant
  preserves the work + the committed probe corpus and changes nothing operationally.
- **Do NOT represent the live "GREEN" run (§3) as "the branch is fixed."** The live verdict is real but
  **SCOPED**: it proves the compute bound holds, that the single-ciphertext defer+heal is intact, and
  that determinism is airtight (380+ heights + 2 from-scratch resyncs). It did **not** exercise the
  multi-ciphertext-per-epoch dimension where the new regression lives — by the run's own admission the
  naive flood landed only ~1 ciphertext/account/block and could not build the backlog that triggers the
  strand. The audit found by executable probe exactly what the live load could not surface.
- **External professional audit is STILL REQUIRED before ANY mainnet reliance**, independent of the
  three findings above. Eight internal adversarial cycles are not a substitute. We do NOT claim an
  external audit has been performed.
- **The release decision belongs to Jason.** This report states technical readiness only.

---

## 1. Cycle history — eight adversarial cycles

| Cycle | Commit(s) | Result |
|-------|-----------|--------|
| **1** | `f8615df2` | Transparent in-node DKG built (VE auto-participation, transparent enc key, members = bonded set). Live 4→5-node, 0 divergence. Audit: **NO-GO, 4 HIGHs**. |
| **2** | `a75b027f` | HIGH-1 closed (VE-coupled `veActive` guard), HIGH-2/4 closed (operator-bound PoP + operator-indexed self-id). **HIGH-3 SURVIVED — fix at wrong layer.** **NO-GO.** |
| **3** | `19d5cb6f` | HIGH-3 closed at the **crypto layer**: stake-weighted secret sharing. Audit: **NO-GO, 11 findings** — H-A (degenerate `S<n`), H-B (`t` stranded honest supermajorities AND the shortfall path **silently dropped** the ciphertext), + M/L. |
| **4** | `2c2a271d` | All 6 cycle-3 findings closed: `t = floor(2S/3) − n + 1`, `S ≥ 8n` coupling, non-silent **32-block grace deferral**. Audit: **14 findings, 0 crit/high → CLEAN**. 4-node run **GO**. |
| **5** | `73b1dd1e` | Both cycle-4 deferrals closed (stake-drift rekey; grace path live-proven heal+strand), minimal + default-off. Audit: **11 findings, 0 crit/high → CLEAN**. 4-node run **GO**. Defer-cap remained unit-test-only. |
| **6** | `abd6457e` / `b25c89dc` | Exhaustive re-audit on 6 nodes: **all 5 mission objectives proven LIVE** incl. the 128-entry defer-cap. 6-lens audit: **19 findings, 3 HIGH → `AUDIT_CLEAN = NO`** (HIGH-1 chaff-padding, HIGH-2 Byzantine QUAL dealer, HIGH-3 no complaint round). |
| **7** | `e6e198c1` / `934a5d2a` | Fix for cycle-6 HIGH-1: **DLEQ-verify decryption shares at INGEST**. **HIGH-1 CLOSED, live-proven on 8 nodes.** But the fix moved an `O(t)` verify onto PreBlock with no count bound → **2 NEW HIGH DoS (A halt-class, B `<=1/3`-stake re-verify)**. **24 findings, `AUDIT_CLEAN = NO`.** |
| **8** | `b581c17d` (**this report**) | Fix for cycle-7 HIGH-A/B: **bound the block's ingest DLEQ-verify work to `O(S)`** (4 composed controls). **HIGH-A + HIGH-B CLOSED, live-proven on 8 nodes** (§3). But the re-audit found **the bounding mechanism (per-`(operator,epoch)` budget) is mis-keyed → NEW HIGH-T: honest decryption throttled to ~1 ct/block/epoch, honest ciphertexts strand under multi-ciphertext load** (§4). cycle-6 HIGH-2/3 remain open. **19 findings, `AUDIT_CLEAN = NO`.** |

**Held across every cycle (never regressed):** the transparent experience (no daemon/account/fee/key/
list), consume-path + EndBlock determinism / zero app-hash divergence, dormancy + kill-switch, bounded
VE/dealing *bytes* (VE `<= 1 MiB`), flood/refcount invariants (any final EncTx drop goes through
`releaseEncTx`), legacy declared-DKG path byte-identical.

---

## 2. The cycle-8 fix — what it does

Cycle-7 moved `dkg.VerifyDecryptShare` (an `O(t)` elliptic-curve op) onto the PreBlock consensus path
(`ConsumeVoteExtensions` Phase 3 → `IngestDecryptShareFromVE`) with **no count cap** — bounded only by
the 1 MiB byte cap, i.e. thousands of shares → thousands of `O(t)` verifies per node per block (HIGH-A,
halt-class), and a rejected chaff share (never stored) was re-verified from scratch every block (HIGH-B).

**The fix (commit `b581c17d`)** replaces the uncapped Phase-3 loop with **`ingestDecryptSharesBounded`**
(`voteext.go:596-688`, wired at `voteext.go:327`), refactoring ingest into a cheap **`classifyDecryptShare`**
(no elliptic-curve work: in-flight-ciphertext match, membership, point-ownership, first-wins `O(1)`
`hasEncShareAt` dedup) followed by the one expensive **`verifyAndStoreDecryptShare`**. Four composed,
**pure, NO-persistent-state, deterministic** controls over the canonical (operator-sorted, deduped)
entries cap the block's TOTAL DLEQ verification at `O(S)`:

1. **Per-VE share-count cap** (`voteext.go:638`) — a single extension's shares beyond
   `VoteExtShareCap = max(256, S)` are dropped in committed order **before any per-share work**. Also
   enforced structurally in evmd `VerifyVoteExtension` (`dkg_voteext.go:283`) plus a param-only
   per-ciphertext `<= S` cap (`:274-277`), so a peer refuses a padded extension EARLY (VE stays `<= 1 MiB`).
2. **Within-block eval-point dedup** (`voteext.go:626, 654`) — each `(decryptHeight, seq, index)` slot
   is verified at most **once per block**.
3. **Per-`(operator, epoch)` verify budget** (`voteext.go:661-668`) `= len(member.OwnedEvalPoints())`.
   Summed over the committee this is exactly `S`, so it bounds the block to `O(S)`, short-circuits
   re-sent chaff (a spammer can only ever burn its owned-point budget — HIGH-B), and stops one member
   monopolizing the global budget. **← this control's per-EPOCH (not per-CIPHERTEXT) keying is the
   cycle-8 regression: see §4.**
4. **Global `O(S)` ceiling** (`voteext.go:633, 648`) `= VoteExtShareCap`: a belt for multi-epoch
   overlap; the surplus **DEFERS** (re-sent idempotently), it is **not** rejected.

**Determinism:** the accounting maps (`seen`, `spent`, `budget`, `globalSpent`) are rebuilt each block
from committed state + the canonical entries, never persisted, never ranged over — every node
accepts/rejects/defers identically (fork-safety). A **deferred** share is NOT a chaff rejection (nothing
stored, no reject event), so the cycle-7 defers-not-drops behavior is preserved **for a single
ciphertext**. The fix touches only `voteext.go`, `evmd/dkg_voteext.go`, `keeper.go` (`hasEncShareAt`
`O(1)` helper) — it does **not** touch `onchain.go` / `endblock.go` / the complaint path, which is why
cycle-6 HIGH-2/HIGH-3 are untouched.

---

## 3. Live compute-DoS proof — GREEN (but SCOPED) on a fresh isolated 8-node network

The fix was driven end-to-end on a fresh 8-node throwaway (real genesis, live delegation, live flood,
mixed fix/variant binaries), attacking the exact halt/compute gates cycle-7 opened:

1. **The compute bound HOLDS live.** An over-cap **1500-share** vote extension is **clamped at ingest**
   (consume path, `encmempool_dkg_ve_shares_clamped`) AND **peer-rejected** by `VerifyVoteExtension`
   (share-count cap) **before any per-share verify**. Per-block DLEQ work is pinned to the attacker's
   **owned eval-point budget** (`= O(S)`, often 0 for a small-stake attacker), and **block time stays
   flat** across hundreds of blocks under a max-spray attacker — even under a *simultaneous* `>128`-ct
   defer flood. This is the direct live refutation of HIGH-A (halt) and HIGH-B (re-verify-every-block).
2. **The cycle-7 drop-DoS fix is intact for the single-ciphertext case.** Chaff is still DLEQ-rejected
   at ingest (count not inflated — `have = 96`, attacker not marked present), and a matured-but-short
   ciphertext **defers + heals** to the correct plaintext within grace. Real malformed ciphertexts still
   hard-drop (AEAD failure) — the defer-routing does not launder a real fault.
3. **No cycle-1..6 regression surfaced live:** defer-cap pins at 128 and is fair; stake-drift rekey
   dampened/live/deterministic; absent-dealer `idx3` excluded from QUAL with the chain live; honest
   decrypt correct.
4. **Determinism is the strongest evidence.** **>380 contiguous heights** across every attack / defer /
   heal / rekey / absent-dealer phase agree **byte-for-byte on all 8 nodes**, and **two from-scratch
   resyncs** (including a node replaying epochs where it was itself the excluded dealer) reproduce
   identical app-hashes — the fix is a **pure function of committed state**.

**Honest caveats — recorded, and one of them is exactly why the §4 regression was NOT caught live:**

- **(a) No live unfixed A/B.** The run proved the FIXED binary HOLDS the bound; the counterfactual that
  the unfixed cycle-7 path EXPLODES rests on the code diff (its consume loop had no share-count cap) +
  the cycle-8 unit test that measures verification counts — not a side-by-side live blow-up.
- **(b) The flood landed only ~1 ciphertext/account/block** (CheckTx drops future-sequence txs), so
  building a `>128` backlog needed a sustained per-block submitter. **This is precisely the load
  limitation that prevented the live run from ever putting multiple in-flight ciphertexts of one epoch
  into the same block — the exact condition under which the §4 honest-throttle regression bites.** The
  live "GREEN" is therefore a valid proof of the compute bound and the single-ciphertext heal, and is
  SILENT on multi-ciphertext honest throughput. Auxiliary friction (a `stopnode` helper that silently
  no-op'd on a trailing-slash pattern; an ad-hoc `pkill` that self-matched the shell) was resolved via
  port-targeted kills; the affected results were re-run correctly.
- **(c) One ciphertext that crossed a rekey under an aggressive 20-block cadence stranded with
  `have = 0`** (its epoch key retired before maturity) — expected epoch-lifetime semantics, orthogonal
  to the ingest-verify bound this cycle changed.

**Net on the live run: GREEN on the compute/halt DoS — the cycle-8 bound demonstrably closes HIGH-A +
HIGH-B without breaking determinism or the single-ciphertext defer+heal.** What the live run did NOT and
could NOT surface is the honest-throughput cost of *how* the bound is sized; that is what the code audit
found next (§4).

---

## 4. Cycle-8 re-audit — **19 findings, `AUDIT_CLEAN = NO`**, ONE NEW HIGH introduced by the fix

The re-audit re-attacked the change with the same discipline as cycles 6–7, plus a dedicated
**honest-throughput lens** and **drop-DoS lens** on the new bound (committed probes below). **The two
cycle-7 HIGHs (A halt-class, B re-verify chaff) are CLOSED** — the probes and the live run agree the
per-block verify is now `O(S)`. But the *mechanism* that closes them opened one new HIGH.

### HIGH-T (NEW) — the `O(S)` verify bound is mis-sized: per-`(operator, epoch)` where honest demand is per-`(operator, epoch, ciphertext)` → honest decryption throttled to ~1 ct/block/epoch, honest ciphertexts STRAND (defers+heals → defers+DROPS)

- **Root defect (single locus):** the per-operator verify budget is keyed by
  `opEpoch{operator, epoch}` (`voteext.go:483-486`) and sized `b = len(member.OwnedEvalPoints())`
  (`voteext.go:664`), applied at `voteext.go:661-668`. This grants an operator `owned-points` verifies
  **for the whole epoch per block**. But a decryption share is **per-CIPHERTEXT** (`D = x·A`, `A` is the
  ciphertext's ephemeral), and the honest builder `buildDecryptShares` (`dkg_voteext.go:178-207`) emits
  `owned-points` shares **for every in-flight ciphertext** it serves. So honest demand is
  `owned-points × (#in-flight ciphertexts of that epoch)`; the budget covers `owned-points` — **one
  ciphertext's worth**.
- **Mechanism:** every honest operator serves the in-flight set **oldest-first** in the same
  deterministic order, so the whole committee spends its entire budget on the SAME (oldest) ciphertext.
  That one ciphertext accrues all `S` shares and heals; every OTHER in-flight ciphertext of the epoch
  gets **zero** stored shares that block (the surplus hits `spent[oe] >= b` → `continue`,
  `voteext.go:667` — a **budget defer**, not a chaff reject). Honest throughput is therefore **~1
  ciphertext / block / epoch**, independent of the `2048`/block decrypt capacity and the `256`-share
  `O(S)` ceiling.
- **Impact (liveness / availability, forced DROP):** a backlog of `K` ciphertexts of one epoch drains at
  1/block; any ciphertext that cannot be drained within the **32-block** `StrandedDecryptGrace` window
  (`abci.go:195`) **HARD-STRANDS** at `abci.go:327-336` (`encmempool_decrypt_stranded`). This **partially
  regresses the cycle-7 "defers + heals" drop-DoS fix to "defers + DROPS"** — but now under **ordinary
  multi-ciphertext concurrency with NO attacker**, and cheaply **weaponizable**: admission is
  `MaxInFlightEncTx = 32768 / MaxInFlightPerSubmitter = 2048` with **no per-block rate limit**
  (`types.go:387`), so a no-stake submitter can burst `> 32` same-epoch ciphertexts and force honest
  strands. It is the same drop-class DoS cycle-7 set out to kill, re-introduced through the throttle.
- **CONFIRMED by executable probes** (committed this cycle):
  - `audit_c8_throughput_probe_test.go :: TestC8Audit_HonestMultiCiphertextThroughput_ThrottledToOnePerBlock`
    — 3 matured ciphertexts, full committee serving all three in one block:
    **`ct1 = 32, ct2 = 0, ct3 = 0`** stored (t = 18 needed each); only 1 of 3 reaches threshold, with
    decrypt capacity `2048`/block idle.
  - `zzz_probe_c8_dropdos_lens_test.go :: TestProbeC8_MultiHonestCiphertextsPerEpoch_HonestSharesStarved`
    — 2 honest ciphertexts, same epoch, **no attacker**: honest ct2 starved to **0** stored shares
    (ct1 = 32) despite **224 / 256 spare `O(S)` ceiling** — "cycle-8 defers honest shares cycle-7 would
    have stored + healed."
- **Remediation (cycle-9):** the bound must key the verify budget per-`(operator, epoch, ciphertext)` =
  `owned-points` **per ciphertext** (so honest per-ciphertext demand is never starved), and then bound
  the **cross-ciphertext** dimension separately — because `#in-flight ciphertexts` is attacker-floodable
  (`types.go:387` has no per-block admission rate limit), simply removing the per-epoch cap re-opens
  HIGH-A/B along the ciphertext-count axis. The two must be reconciled: e.g. a **per-block
  ciphertext-maturity admission / fair per-ciphertext scheduler within the grace window** (bound `K` per
  block, drain oldest-first with a guaranteed heal-before-grace), so total work stays `O(S · K_max)` with
  `K_max` a committed bound, **without** throttling honest liveness to 1/block. The compute bound is
  correct and must stay; only its sizing axis is wrong.

### Carried-open cycle-6 HIGHs (out of scope for this fix; verified untouched from the diff)

- **HIGH-2 — Byzantine QUAL dealer permanently bricks an epoch's decryption, no complaint recourse.**
  `b581c17d` touches neither `onchain.go` nor `endblock.go`; the shape-only enc-share gate and the
  unreachable account-based complaint path are unchanged. **Still open.**
- **HIGH-3 — the transparent VE-DKG has NO complaint/justify round at all** (root cause of HIGH-2;
  `finalizeRound`'s `disq` set is only ever written from the never-reached `IterateComplaints`). The fix
  adds no complaint field/phase. **Still open.**

### Notable residuals carried from cycle-6 (medium-class, non-blocking-but-material)

- **Defer-cap fairness is per-SUBMITTER and submitter identity is free → sybil defeats it** (fair share
  holds vs 1 flooding identity, defeated by 200 sybils). Compounds HIGH-T's no-stake-flood weaponization.
- **Overflow-magnitude stake silently kills the stake-drift rekey** (recovered, no halt, but the enabled
  rekey never fires + per-block panic-event spam). Default-off, so not a live risk today.

The remaining findings are medium/low/informational — the external auditor's starting material (§5).

---

## 5. Residuals & the EXTERNAL-audit focus list

### The THREE HIGH blockers to ENABLE (must fix + re-audit before turning the feature on)

1. **HIGH-T (cycle-8, NEW) — re-size the ingest verify bound.** Budget per-`(operator, epoch,
   ciphertext)` = owned points per ciphertext; bound the attacker-floodable `#in-flight ciphertexts`
   dimension with per-block ciphertext-maturity admission / a fair grace-window scheduler, so honest
   multi-ciphertext liveness is preserved (no strand under normal concurrency) while total per-block work
   stays `O(S · K_max)`. This makes the cycle-8 compute-bound a genuine net-positive.
2. **HIGH-2 / HIGH-3 (cycle-6, carried) — add a share-validity gate AND a complaint/justify round to the
   transparent path.** (i) verify every enc-share against the dealer's Feldman commitments on consume;
   (ii) add a complaint field to `types.VoteExtension` + a complaint→justify phase to
   `ConsumeVoteExtensions` so `finalizeRound`'s `disq` set is populated on the transparent path;
   (iii) exclude a complaint-proven-bad dealer from QUAL and sum `DeriveShares` only over the healthy set.

### Required regardless of the above

3. **External professional audit REQUIRED before ANY mainnet reliance** on the encrypted mempool's
   confidentiality. Eight internal adversarial cycles are exhaustive but are **not** an external audit.
   Hand the firm §3/§4/§5, the full `audit_c6_*` / `audit_c7_*` / `audit_c8_*` / `zzz_*` probe corpus, and
   the cycle-5/6/7/8 live verdict runs. **No external audit has been performed.**
4. **Per-block admission rate-limit for maturing ciphertexts** (`types.go:387` currently `32768 / 2048`
   with no per-block cap) — needed both to bound HIGH-T's cross-ciphertext axis and as sybil-flood
   hardening; couples with the defer-cap fairness residual.
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
| `ExtendVote` | `dkgExtendVoteHandler` | Packs `{EncPubKey + PoP, Feldman dealing, DLEQ-proved per-eval-point decryption shares for EVERY in-flight ciphertext}` into the precommit's `VoteExtension`. Node-local. **(Note: this per-ciphertext honest demand is exactly what the cycle-8 per-EPOCH budget under-serves — HIGH-T.)** |
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` | Structural check + BYTE cap (`VoteExtMaxBytes = 1 MiB`) **and (cycle-8) two honest-safe SHARE-COUNT caps** — per-VE `<= VoteExtShareCap` and per-ciphertext `<= S` — so a padded extension is peer-refused early. Non-binding local filter; the authoritative bound is in PreBlock. |
| `PrepareProposal` | `wrapDkgPrepareProposal` | Prepends the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` | Self-certifies `Txs[0]` with `ValidateVoteExtensions`, strips it, delegates. Gated by `veActive`. |
| `PreBlock` | `consumeDkgVoteExtensions` → `keeper.ConsumeVoteExtensions` | Resolves consensus address → operator; deterministic canonicalizing consume. **Cycle-8: Phase-3 decryption-share ingest now runs through `ingestDecryptSharesBounded` — per-VE cap + within-block dedup + per-`(operator,epoch)` verify budget + global `O(S)` ceiling. Compute is now `O(S)`/block (closes cycle-7 HIGH-A/B), but the per-EPOCH budget throttles honest multi-ciphertext decryption (HIGH-T). No complaint phase (HIGH-3).** |

**Pillar 2 — Transparent key.** A secp256k1 ECIES key per member, minted with zero operator action
(`dkgnode.LoadOrCreateEncKey`, `<home>/dkg_enc_key.json`, 0600), auto-announced with an operator-bound
PoP (cycle-2), self-identity by OPERATOR (cycle-2).

**Pillar 3 — Members = bonded validators.** `TransparentMembers` derives the committee from the bonded
set: top-N by stake (`EffectiveMaxMembers`), clamped to `floor(S/8)` seats, each member's eval points
apportioned by stake. **Members carry NO account address — which is why the account-based complaint
path is unreachable (HIGH-2/3).** Rekey triggers: membership change, failed-round retry, and the opt-in
cadence/stake-drift (cycle-5, default-off).

### Determinism contract (the #1 fork risk — held through every live run, including cycle 8)
All determinism is confined to the consume half and the EndBlock DKG state machine, both pure functions
of `(committed state, entries)`. **Cycle-8 confirms this held with the bounded-ingest accounting maps
added to PreBlock** — the maps are rebuilt each block from committed state, never persisted, never
ranged over; the accept/reject/defer verdict is a pure, order-independent function, and `app_hash` never
diverged across >380 live heights + two genesis resyncs (§3). The three HIGH findings are
liveness/availability/DoS, NOT divergence.

### Dormancy / kill-switch
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` AND vote extensions are active;
the cycle-5 triggers additionally require their param `> 0`. All enabling flags default false/0.
**All three HIGH findings are on the ENABLED path — none is reachable while dormant.**

---

## 7. GO / NO-GO

### Verdict: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE**; dormant-by-default MERGE is safe.

1. **NO-GO to enable the transparent DKG** on any chain relied on for confidentiality. The cycle-7
   HIGH-A/HIGH-B compute/halt DoS is **closed and live-proven**, but the closure **introduced HIGH-T**
   (per-`(operator,epoch)` verify budget → honest decryption throttled to ~1 ct/block/epoch → honest
   ciphertexts strand under multi-ciphertext load), and cycle-6 HIGH-2/HIGH-3 remain open — **3 open
   HIGH findings**, all liveness/availability DoS (no fork, no consensus halt-via-divergence), all
   reproduced against the real consensus entry points (HIGH-T by two committed executable probes).
2. **Merging DORMANT is safe.** With default params (`DkgEnabled = DkgTransparent = false`, drift
   triggers 0) the binary is byte-behavior-identical to `17101a12`; none of the three HIGH findings is
   reachable; both modules build green (`-tags test`, root + evmd + `go vet` all exit 0); the full
   regression + probe suite passes.
3. **External professional audit REQUIRED before ANY mainnet reliance**, independent of (1). **No
   external audit has been performed.**
4. **The release decision belongs to Jason** — merge timing, the cycle-9 HIGH-T re-sizing + HIGH-2/3
   complaint-round fix cycle, VE scheduling, drift-trigger enablement, and the enable vote are his call.

### What is safe today
Merging this branch **without enabling** is safe and preserves the fix + the committed probe corpus.
What is NOT safe is turning the feature on: three HIGH liveness findings are open, one of them newly
introduced by the cycle-8 fix's own bounding mechanism.

---

## 8. Scorecard

| Item | State |
|------|-------|
| Builds (root + evmd, `-tags test`) | ✅ exit 0 (root, evmd, `go vet ./x/encmempool/...` all clean — verified this cycle) |
| Full test + probe suite (`-tags test`) | ✅ PASS (keeper suite green; the cycle-8 audit probes pass by DEMONSTRATING HIGH-T) |
| Consume-path + EndBlock determinism (unit + live) | ✅ 0 divergence, every cycle; cycle-8: **>380 heights byte-identical on 8 nodes + two genesis resyncs reproduce every attack height** |
| Transparent experience (no daemon/account/fee/key/list) | ✅ proven live, cycles 1–8 |
| Kill-switch / dormancy | ✅ default-off; all 3 HIGH findings unreachable while dormant |
| HIGH-1/2/3/4 (cycles 1–4) + cycle-3 H-A/H-B + M/L | ✅ closed |
| cycle-6 HIGH-1 — unverified-share count padding → forced drop | ✅ CLOSED (cycle-7); preserved for the SINGLE-ciphertext case |
| **cycle-7 HIGH-A — unbounded per-VE ingest-verify (halt-class)** | ✅ **CLOSED (cycle-8)** — block verify hard-bounded to `O(S)`; live-proven (1500-share VE clamped+rejected, block time flat) |
| **cycle-7 HIGH-B — re-verify-every-block chaff compute DoS** | ✅ **CLOSED (cycle-8)** — per-`(operator,epoch)` budget short-circuits re-sent chaff to its owned-point count; live-proven |
| **cycle-8 HIGH-T — per-`(operator,epoch)` verify budget throttles honest decrypt to ~1 ct/block/epoch → honest STRAND** | ❌ **OPEN — NEW** (introduced by the fix; confirmed by 2 committed executable probes: `ct1=32,ct2=0,ct3=0`, no attacker) |
| **cycle-6 HIGH-2 — Byzantine QUAL dealer bricks epoch, no recourse** | ❌ **OPEN** (out of scope; `onchain.go`/`endblock.go` untouched) |
| **cycle-6 HIGH-3 — no complaint/justify round on transparent path** | ❌ **OPEN** (out of scope; untouched) |
| Bounded ingest — pure / deterministic / order-independent / no-panic | ✅ proven (accounting maps rebuilt each block, never persisted; >380 live heights + 2 resyncs) |
| Multi-node live verdict run (cycle 8) | ✅ GREEN on the compute/halt DoS — 1500-share spray clamped+rejected, verify pinned to `O(S)`, block time flat, single-ct defer+heal intact, 8 nodes, 0 divergence. **SCOPED: did not exercise multi-ciphertext honest throughput (HIGH-T)** |
| Security audit (cycle 8) | ❌ **`AUDIT_CLEAN = NO`** — 19 findings, **3 open HIGH** (1 new HIGH-T from 6 lenses, 2 carried) (§4) |
| External audit | ❌ NOT DONE — **required before any mainnet reliance** regardless |
| **Enable on a real chain** | ❌ **NO-GO** — re-size HIGH-T (cycle-9) + HIGH-2/3 complaint round + re-audit first |
| **Merge DORMANT (feature off)** | ✅ safe — byte-behavior-identical to `17101a12` |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release, and
do NOT enable the transparent DKG until all three HIGH findings are closed and re-audited. The cycle-8
fix closes the cycle-7 compute/halt DoS (live-proven) but its bounding mechanism introduces a new
honest-throughput DoS (HIGH-T) — it is a checkpoint, not a green light.*
