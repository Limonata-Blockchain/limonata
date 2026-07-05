# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-05 (audit cycle 9 — re-key the ingest verify budget per-ciphertext, restoring honest
multi-ciphertext liveness; live-prove the drain + adversarially re-audit the new bound)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commits under review:** `3d396dda` — *harden(encmempool/dkg): cycle-9 — re-key ingest verify budget
per (operator,ciphertext), restoring honest liveness* + `2b533e93` — *test(encmempool/dkg): cycle-9 —
env-gated ExtendVote adversary harness for the live multi-ciphertext + compute-DoS proof*, atop
`b9ec432a` (cycle-8 docs) → `b581c17d` (cycle-8 fix) → `934a5d2a` → `e6e198c1` → `b25c89dc` →
`abd6457e` → `73b1dd1e` → `d8976687` → `2c2a271d` → `19d5cb6f` → `17101a12`

---

## VERDICT: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE** (dormant-by-default MERGE still safe; external audit still required regardless)

> ⚠️ **VERDICT CORRECTION (adversarial re-audit, post-doer 2026-07-05).** The overall `AUDIT_CLEAN = NO`
> stands, but **two specific doer claims below are WRONG and are corrected here:**
>
> 1. **"HIGH-T CLOSED" is only true for near-BALANCED committees — HIGH-T is NOT closed on Limonata's
>    real topology.** Cycle-9 re-keyed the *consumer* verify budget per-`(operator,ciphertext)` but left
>    the *supply* side untouched: `buildDecryptShares` caps a member's TOTAL emitted shares/block at
>    `shareCap = max(256,S)` (`evmd/dkg_voteext.go:171,183,198`) and dumps a member's whole owned-point
>    set on the oldest ciphertext first. A member owning `P` eval points can therefore fully serve only
>    `floor(shareCap/P)` ciphertexts/block. Eval-point allocation has **no max cap** and explicitly lets
>    a whale own `≥ t` points and "decrypt alone" (`stakeweight.go:54-57`) — and **Limonata runs a ~70%-VP
>    validator**. For such a whale `P > shareCap/2` so it is threshold-critical AND `floor(shareCap/P) ≈ 1`:
>    honest decrypt drains ~1 ciphertext/block and grace-critical honest ciphertexts STILL STRAND under a
>    multi-ciphertext backlog. All cycle-9 evidence used *balanced* committees (8 equal nodes; probe capped
>    at 30 cts to stay under its own supply ceiling), so none could surface skew. HIGH-T survives on the
>    real topology.
> 2. **HIGH-U is UNDER-SIZED and is halt-class, not "bounded / recovers / not a halt".** (a) Each verify is
>    `O(t)` EC ops (`SharePubKey` evaluates the degree-`(t-1)` commitment, `voteext.go:791`), so the true
>    per-block ceiling is `O(cap·S·t) = O(cap·S²)`, not `O(cap·S)` — ~5.3M EC ops/block at default `S=256`,
>    and **`EffectiveShareBudget` is governance-tunable up to `maxDkgShareBudget=2048`** (`types.go:578,653`),
>    where the ceiling is ~3.6e8 EC ops/block → **minutes-long `FinalizeBlock` = a practical HALT at a VALID
>    governance config.** (b) It is **sustainable / non-recovering:** there is NO per-block ciphertext
>    admission rate limit (only standing-inventory ceilings `MaxInFlightEncTx=32768` /
>    `MaxInFlightPerSubmitter=2048`, `types.go:387`), so one gas-paying submitter refills the oldest-128
>    processed window every block and pins `FinalizeBlock` at its peak (~10 s on the current small set)
>    indefinitely. The "recovery" the doer observed only happened because its harness attacker STOPPED.
>
> **Root remediation for BOTH HIGH-T-skew and HIGH-U is a DESIGN change, not another sizing/audit cycle:**
> a per-block ciphertext-admission rate limit + a fair share-SUPPLY scheduler that emits only the marginal
> points needed per ciphertext and guarantees the oldest grace-critical ciphertexts reach threshold coverage
> independent of stake skew, bounding cross-ciphertext work to a small constant. Together with the carried
> structural HIGH-2/HIGH-3 (byzantine QUAL dealer bricks an epoch; no complaint/justify round), the DKG's
> remaining work is DESIGN + implementation, which is why (Jason, 2026-07-05) we STOP the DKG audit loop
> here and pivot to designing the complaint round + admission/scheduler. Dormant merge stays safe.

The cycle-9 fix **genuinely closes HIGH-T** — the cycle-8 honest-throughput / forced-strand regression.
Cycle-8 keyed the per-operator ingest DLEQ-verify budget by **`(operator, EPOCH)`**, but a decryption
share is **per-CIPHERTEXT** (`D = x·A`, bound to the ciphertext ephemeral `A`), so with `C` in-flight
ciphertexts of one epoch the whole committee piled its entire per-epoch budget onto the single oldest
ciphertext (~1 decryptable ct/block/epoch) and **hard-DROPPED the rest past the 32-block grace**. The
cycle-9 fix re-keys the budget by **`(operator, CIPHERTEXT)`** — each member may verify up to
`owned-points` shares **for each ciphertext** — and bounds the number of DISTINCT budgeted ciphertexts
to `maxVerifyCiphertextsPerBlock == 128` via a cheap, oldest-first **processed-set** read of committed
state. Honest multi-ciphertext liveness is **RESTORED, and that restoration was proven LIVE on a fresh
isolated 8-node network** (§3): a **46-ciphertext same-epoch backlog drained fully within grace with
ZERO short-share strands** (up to **10 ciphertexts resolving in a single block**), while a `DKG_CHAFF9`
max-spray attacker stayed **clamped-at-ingest** every block and app-hashes were **byte-identical across
all 8 nodes over 353 + 231 contiguous heights, reproduced by a from-scratch resync**. The unit probes
that ASSERTED the cycle-8 regression now assert the fix: **`ct1 = 32, ct2 = 32, ct3 = 32`** stored in one
block (was `32, 0, 0`).

**But the fix is NOT a net-clean win, and it is NOT ready to enable.** The cycle-9 adversarial re-audit
(and the live run itself) found that the mechanism that restores liveness — the per-ciphertext budget —
**raises the per-block DLEQ-verify ceiling from cycle-8's `O(S)` to `O(maxVerifyCiphertextsPerBlock ×
S) = O(128 × 256) ≈ 32 768` verifications/block**. That ceiling is a **constant × S, deterministic and
NOT attacker-scalable beyond it** (so it does NOT re-open the cycle-7 *unbounded* halt-class HIGH-A —
the chain never halted, never forked, and recovered to a flat 1.16 s/block once drained). **However the
constant is large enough to measurably degrade block time under a multi-ciphertext backlog**: draining
just **46** ciphertexts inflated block time to a **transient ~5–10 s** (peak 10.3 s vs a 1.16 s
baseline, on an unloaded 56-core host — this is serial PreBlock verify compute, NOT machine
contention). Because there is **still no per-block ciphertext-maturity admission rate limit**
(`types.go:387`, cycle-8 residual #4, unchanged), an adversary can **influence** the in-flight /
processed-ciphertext count and thereby the per-block verify load toward that ceiling. So **"block time
stays flat" is FALSE under the multi-ciphertext drain** — cycle 9 converts cycle-8's *honest-strand*
into a **bounded, attacker-influenceable compute-latency cost (HIGH-U)**. The bound is correct and
necessary; its **magnitude (`cap × S`) is high** and must be reconciled with a real per-block admission
/ fair maturity scheduler before enable.

Net inventory of OPEN HIGH findings going into any enable decision: **3** (HIGH-T CLOSED; HIGH-U new;
HIGH-2/HIGH-3 carried).

| # | HIGH finding | Origin | Status after cycle-9 |
|---|--------------|--------|----------------------|
| **A** | Unbounded per-VE ingest-DLEQ-verify → single member stalls consensus every block (halt-class) | cycle-7 | ✅ CLOSED (cycle-8; live-proven) |
| **B** | `<=1/3`-stake PreBlock compute DoS: uncapped, re-verified-every-block DLEQ of REJECTED chaff | cycle-7 | ✅ CLOSED (cycle-8; live-proven) |
| — | Unverified VE decryption-share COUNT PADDING → healable defer becomes hard DROP | cycle-6 HIGH-1 | ✅ CLOSED (cycle-7) |
| **T** | Per-`(operator, EPOCH)` verify budget throttles honest decryption to ~1 ct/block/epoch → honest ciphertexts STRAND under multi-ciphertext load | cycle-8 | ✅ **CLOSED (this fix; live-proven §3 — 46-ct backlog drains, 0 strands; unit probes `32,32,32`)** |
| **U** | **Per-`(operator, CIPHERTEXT)` budget raises the per-block verify ceiling to `O(cap × S) ≈ 32 768` DLEQ ops → attacker-influenceable block-time inflation (observed ~10 s at 46 cts; bounded, recovers, NOT a halt/fork). Coupled to the still-open no-per-block-admission-rate-limit residual** | **cycle-9 (introduced by the fix)** | ❌ **OPEN — NEW** |
| **2** | Byzantine QUAL dealer permanently bricks an epoch's decryption, no complaint recourse | cycle-6 HIGH-2 | ❌ **OPEN** (out of scope; `onchain.go`/`endblock.go` untouched) |
| **3** | Transparent VE-DKG has no complaint/justify round at all (root cause of #2) | cycle-6 HIGH-3 | ❌ **OPEN** (out of scope; untouched) |

**What this means concretely:**

- **NO-GO to ENABLE** the transparent DKG on any chain relied on for confidentiality. HIGH-T is closed
  and the honest multi-ciphertext liveness it broke is **restored and live-proven**; but the fix
  **introduced HIGH-U** (a bounded but attacker-influenceable compute-latency cost from the `O(cap × S)`
  ceiling), and cycle-6 HIGH-2/HIGH-3 remain open. This is the third consecutive cycle where a
  compute-bound / liveness fix on this path is a **lateral move for the enable decision**: cycle-7 traded
  a drop-DoS for an unbounded compute halt (A/B); cycle-8 bounded the compute but starved honest liveness
  (T); cycle-9 restores liveness but at a **high, attacker-reachable compute ceiling** (U). The correct
  end-state — flagged since the cycle-8 report — is a **per-block ciphertext-maturity admission / fair
  grace-window scheduler** that keeps total work at `O(S × K_max)` with `K_max` **small enough that block
  time stays flat**, not merely bounded.
- **HIGH-T is genuinely closed — do not under-state that.** Both the executable probes (`ct1=32 ct2=32
  ct3=32` in one block; multi-ct defer+heal; burst-of-many no tail strand; order-independence) and the
  live 8-node run (46-ct same-epoch backlog, **0 short-share strands**, all resolving within grace) agree.
- **HIGH-U is genuinely open — do not over-state the live run as "flat / fixed."** The live drain
  **spiked block time to ~10 s**. The verdict remains `AUDIT_CLEAN = NO`.
- **Merging the branch DORMANT is still safe.** All open HIGH findings live on the *enabled* transparent
  decrypt/DKG path. With `DkgEnabled = DkgTransparent = false` (the shipped default) the binary is
  byte-behavior-identical to `17101a12`; none is reachable.
- **External professional audit is STILL REQUIRED before ANY mainnet reliance**, independent of the
  findings above. Nine internal adversarial cycles are not a substitute. **No external audit has been
  performed.**
- **The release decision belongs to Jason.** This report states technical readiness only.

---

## 1. Cycle history — nine adversarial cycles

| Cycle | Commit(s) | Result |
|-------|-----------|--------|
| **1** | `f8615df2` | Transparent in-node DKG built. Live 4→5-node, 0 divergence. Audit: **NO-GO, 4 HIGHs**. |
| **2** | `a75b027f` | HIGH-1 closed (`veActive` guard), HIGH-2/4 closed (operator-bound PoP + operator self-id). **HIGH-3 survived.** **NO-GO.** |
| **3** | `19d5cb6f` | HIGH-3 closed at the crypto layer (stake-weighted secret sharing). **NO-GO, 11 findings.** |
| **4** | `2c2a271d` | All 6 cycle-3 findings closed (`t = floor(2S/3) − n + 1`, `S ≥ 8n`, 32-block grace). **14 findings, 0 crit/high → CLEAN.** 4-node **GO**. |
| **5** | `73b1dd1e` | Both cycle-4 deferrals closed (stake-drift rekey; grace heal+strand). **11 findings, CLEAN.** 4-node **GO**. |
| **6** | `abd6457e` / `b25c89dc` | Exhaustive re-audit on 6 nodes; all 5 objectives proven LIVE incl. 128 defer-cap. **19 findings, 3 HIGH → NO** (chaff-padding, Byzantine QUAL dealer, no complaint round). |
| **7** | `e6e198c1` / `934a5d2a` | Fix cycle-6 HIGH-1: DLEQ-verify shares at INGEST. **HIGH-1 CLOSED, live-proven (8 nodes).** But moved an `O(t)` verify onto PreBlock with no count bound → **2 NEW HIGH DoS (A halt, B re-verify)**. **NO.** |
| **8** | `b581c17d` / `b9ec432a` | Fix cycle-7 HIGH-A/B: bound the ingest verify to `O(S)`. **HIGH-A + HIGH-B CLOSED, live-proven (8 nodes).** But the bound was keyed per-`(operator,EPOCH)` → **NEW HIGH-T: honest decryption throttled to ~1 ct/block/epoch, honest ciphertexts strand under multi-ct load**. **19 findings, NO.** |
| **9** | `3d396dda` / `2b533e93` (**this report**) | Fix cycle-8 HIGH-T: re-key the ingest verify budget per-`(operator,CIPHERTEXT)`, bound distinct budgeted ciphertexts to `cap = 128` via an oldest-first processed set. **HIGH-T CLOSED — honest multi-ct liveness RESTORED, live-proven on 8 nodes (46-ct backlog drains, 0 strands; unit probes `32,32,32`).** But the per-ct budget raises the per-block verify ceiling to `O(cap × S)` → **NEW HIGH-U: attacker-influenceable block-time inflation (~10 s observed at 46 cts; bounded, recovers, not a halt)**. cycle-6 HIGH-2/3 remain open. **`AUDIT_CLEAN = NO`.** |

**Held across every cycle (never regressed):** the transparent experience (no daemon/account/fee/key/
list), consume-path + EndBlock determinism / zero app-hash divergence, dormancy + kill-switch, bounded
VE/dealing *bytes* (VE `<= 1 MiB`), flood/refcount invariants, legacy declared-DKG path byte-identical.

---

## 2. The cycle-9 fix — what it does

Cycle-8's `ingestDecryptSharesBounded` bounded the block's total DLEQ verification to `O(S)` via four
composed controls, but **control #3 (the per-operator verify budget) was keyed by `opEpoch{operator,
epoch}` and sized `len(OwnedEvalPoints())`** — granting an operator `owned-points` verifies **for the
whole epoch per block**, where honest demand is `owned-points` **per in-flight ciphertext** (HIGH-T).

**The fix (commit `3d396dda`, `voteext.go`)** re-keys the budget and bounds the cross-ciphertext axis:

1. **Per-`(operator, CIPHERTEXT)` verify budget** (`opCiphertext{operator, decryptHeight, seq}`,
   `voteext.go:739-748`) `= len(member.OwnedEvalPoints())` **per ciphertext**. Each member may now verify
   its full owned-point share set **for every ciphertext it serves** — exactly the honest per-ciphertext
   demand. Per ciphertext the budget still sums to `<= S` over the committee.
2. **Processed-ciphertext set (control 0, NEW)** (`voteext.go:685-697`) — once per block, the
   `<= maxVerifyCiphertextsPerBlock == 128` **oldest** in-flight ciphertexts of the grace window
   (`from = h - 32`) are read from committed state in deterministic `(decryptHeight, seq)` order via
   `IterateInFlightFrom(..., 128, ...)`. A share whose ciphertext is **not** in this set — future spam,
   stranded-past-grace, or nonexistent — is dropped by an **`O(1)` map lookup BEFORE any budget/verify**
   (`voteext.go:728-729`). This caps the number of DISTINCT budgeted ciphertexts to `128`, so total work
   is `<= 128 × S`.
3. **Retained cycle-8 controls:** per-VE share-count cap (`<= VoteExtShareCap == max(256, S)`,
   `voteext.go:712-720`), within-block eval-point dedup (`seen[slot]`, `voteext.go:731-734`), and a
   **global `O(cap × S)` ceiling belt** (`voteext.go:681-684, 707-709, 722-725`, floored at `shareCap`).

**Why the attacker cannot inflate the work:** the processed set is a **committed-state read, independent
of any attacker's VE contents** — an attacker cannot add ciphertexts to it via shares. Chaff aimed at
non-processed / nonexistent ciphertexts is `O(1)`-dropped with zero verify. Chaff re-aimed at a real
processed ciphertext at an owned point burns only the attacker's **own** per-`(operator,ciphertext)`
budget (`<= owned-points`), never another operator's, and is DLEQ-rejected (not stored, count not
inflated). The within-block `seen[slot]` dedup an attacker can only set for slots **it owns**, so it can
never displace an honest operator's shares.

**Determinism:** `processed`, `seen`, `spent`, `owned`, `globalSpent` are rebuilt each block from
committed state + the canonical (operator-sorted, deduped) entries, **never persisted, never ranged
over**, and bounded (`<= cap` distinct ciphertexts × committee entries). Every node
accepts/rejects/defers identically. The fix touches only `voteext.go` (+ the cycle-8 test retargets); it
does **not** touch `onchain.go` / `endblock.go` / the complaint path — which is why cycle-6 HIGH-2/HIGH-3
are untouched.

---

## 3. Live proof — GREEN on the HIGH-T drain (but SPIKED block time — HIGH-U) on a fresh isolated 8-node network

Driven end-to-end on a fresh 8-node throwaway (single env-gated binary built from the committed HEAD;
399xx ports; scratchpad homes; `nohup`/`disown`; isolated from the live chain **and** from the
concurrent clawback net on 398xx). Topology tuned for the multi-ciphertext dimension cycle-8's live run
could not reach: **node0 = attacker** (25 % stake, ~64 of `S=256` eval points, `DKG_CHAFF9=2000
DKG_CHAFF9_FIRST=1` — max spray, chaff placed AHEAD of honest and aimed at REAL processed ciphertexts so
it reaches the per-`(operator,ciphertext)` DLEQ budget); **node1..7 = honest serve** (75 % total, a
prompt committee well above the ~54.7 % decrypt bar). Gov activated `enc + dkg + transparent`.

**The multi-ciphertext backlog was built (the cycle-8 caveat-(b) blocker overcome).** A per-round
parallel submitter fired one valid-ephemeral-`A` encrypted tx from each of the 8 funded validator
accounts, landing ~8 ciphertexts/block; **46 ciphertexts of the SAME epoch went in-flight
simultaneously** (heights 174–184). (The ~18 rejects were exactly the per-account future-sequence
CheckTx drops the cycle-8 report named — beaten here by fanning across 8 accounts.) `A` is a **valid
compressed secp256k1 point**, so the committee produces **real DLEQ shares that STORE**, letting every
in-flight ciphertext accrue shares toward threshold — the exact demand cycle-8 throttled to ~1/block.

1. **HIGH-T CLOSED live — the backlog DRAINS within grace, ZERO strands.** Over the maturity window,
   **all 46 ciphertexts accrued `>= t` valid shares and resolved** (`encmempool_decrypt_failed`, AEAD on
   the garbage body — the expected terminal once shares are sufficient), with **`encmempool_decrypt_
   stranded (short-shares) = 0`** and up to **10 ciphertexts resolving in a single block** (h=192).
   Transient within-grace `encmempool_decrypt_missed` defers (37) all **healed** into resolutions — the
   cycle-7 "defers + heals" behavior now working across **many** same-epoch ciphertexts. Under cycle-8
   this backlog would have drained at ~1/block and the tail would have stranded; here nothing stranded.
2. **The attacker is STILL clamped-at-ingest.** `DKG_CHAFF9` max spray is clamped every block it fires
   (`encmempool_dkg_ve_shares_clamped`), and the chaff that survives the per-VE clamp is DLEQ-rejected
   and **bounded to `<= 256`/block** (`encmempool_dkg_ve_share_rejected`), never stored, never inflating
   any ciphertext's share count. The compute bound holds: nonexistent-ciphertext chaff added zero work.
3. **Determinism is airtight — the strongest evidence.** **353 contiguous full-quorum heights [10..362]**
   agree **byte-for-byte on all 8 nodes** across the entire attack / flood / drain / clamp window
   (`DISAGREE = 0`). A **from-scratch resync of node7** (data wiped, block-synced from genesis, replaying
   the full attack+drain history) reproduces identical app-hashes — **231 contiguous heights [170..400]
   byte-identical including the resynced node** (`app_hash@350` matched exactly). The `O(cap × S)`
   bounded-ingest with the processed-set read is a **pure deterministic function of committed state**.
4. **BUT block time did NOT stay flat during the drain — this is HIGH-U (§4).** Baseline (idle + attacker
   spray) was **1.16–1.18 s/block**. During the 46-ciphertext drain (h≈179–195) block time rose to a
   **transient 3.6 s average, peak 10.3 s**, then **recovered to 1.16 s** once drained. The spikes track
   the serial PreBlock DLEQ-verify volume (present even in zero-chaff blocks, e.g. h=189 = 8.6 s with
   chaff = 0), and the host was **unloaded (load-avg 3.6 on 56 cores)** — so this is genuine verify
   compute, not contention. The from-scratch resync **crawled through the same h≈177–195 window** (CPU
   re-executing the same verifications) and sped up immediately past it — independent confirmation that
   the cost is compute, not divergence.

**Honest caveats:**

- **(a) No live unfixed cycle-8.** The run proves the FIXED binary DRAINS the backlog; that cycle-8 would
  have STRANDED it rests on the code diff + the retargeted cycle-8 probes (which, on the cycle-8 keying,
  asserted `ct1=32 ct2=0 ct3=0`). The unit probe is the primary evidence of the per-ct-vs-per-epoch
  granularity; the live run corroborates at the system level (0 strands under a real 46-ct backlog).
- **(b) Ciphertext bodies were garbage** (valid `A`, junk body), so ciphertexts resolved as
  `decrypt_failed` (AEAD) rather than `decrypted` — this is intentional and sufficient: the HIGH-T signal
  is **share ACCRUAL** (a ct that reaches `>= t` shares is not stranded), which garbage bodies do not
  affect. Producing fully-decryptable bodies needs client-side ECIES to the live epoch key and was out of
  scope for the drain proof.
- **(c) HIGH-U magnitude at the ceiling was extrapolated, not driven to `cap`.** The live backlog was 46
  ciphertexts (partial fill of the 128 processed-set); the `O(cap × S)` ceiling (128 cts) would be worse.
  The observed 10 s at 46 cts is the measured lower bound on the effect.

**Net on the live run: GREEN on HIGH-T (multi-ciphertext liveness restored — backlog drains, 0 strands,
determinism airtight, resync reproduces) — but block time is NOT flat under the drain, which is HIGH-U.**

---

## 4. Cycle-9 re-audit — HIGH-T CLOSED, ONE NEW HIGH introduced by the fix + self-adversarial re-read

### HIGH-T (cycle-8) — **CLOSED**

The per-`(operator, epoch)` → per-`(operator, ciphertext)` re-keying restores honest per-ciphertext
demand. **Confirmed by executable probes (committed) and the live run:**

- `audit_c8_throughput_probe_test.go :: TestC9_HonestMultiCiphertextThroughput_AllDecryptableInOneBlock`
  — 3 matured ciphertexts, full committee serving all three in one block: **`ct1 = 32, ct2 = 32, ct3 =
  32`** stored (was `32, 0, 0`). All three reach threshold in ONE block.
- `zzz_probe_c8_dropdos_lens_test.go :: TestC9_MultiHonestCiphertextsPerEpoch_BothHeal` — 2 honest
  ciphertexts, same epoch, no attacker: **both accrue their full 32 shares in one block** (was ct2 = 0),
  64 DLEQ verifies, `O(cap × S)` ceiling 4096 unused.
- `audit_c9_verify_granularity_test.go` — honest many-ct liveness, the `O(cap × S)` bound +
  non-processed-chaff pre-classification + processed-set cap mechanism, multi-ct defer/heal, and
  multi-ct order-independence.
- Live: 46-ct same-epoch backlog drained within grace, **0 short-share strands** (§3).

### HIGH-U (NEW) — the per-`(operator, ciphertext)` budget raises the per-block verify ceiling to `O(cap × S)` → attacker-influenceable block-time inflation

- **Root:** the block's total DLEQ verification is now bounded by
  `maxVerifyCiphertextsPerBlock × S = 128 × 256 ≈ 32 768` verifications (`voteext.go:681`, ceiling; and
  the per-ct budget summed over `<= 128` processed ciphertexts). This is a **constant × S, deterministic,
  NOT attacker-scalable beyond it** — so it does **not** re-open the cycle-7 *unbounded* halt-class
  HIGH-A. But the constant is **128× cycle-8's `O(S)`**, and it is **honest work an attacker can induce**.
- **Mechanism / attack surface:** the honest builder serves shares for **every** in-flight ciphertext, so
  every ciphertext the committee is serving costs each node up to `S` first-time DLEQ verifications (once
  its shares first arrive; `seen`/`hasEncShareAt` dedup prevents re-verify). Ciphertext **admission has
  no per-block rate limit** (`MaxInFlightEncTx = 32768 / MaxInFlightPerSubmitter = 2048`, `types.go:387`
  — cycle-8 residual #4, unchanged), so an adversary can keep the oldest-128 processed set full and feed
  a **stream of new ciphertexts** (≈1 ct/account/block under the CheckTx future-seq limit → a sybil fleet
  or many accounts to sustain `cap` new/block), driving per-block verify volume toward the `cap × S`
  ceiling for the duration of the grace window.
- **Impact (liveness / latency, BOUNDED):** block time degrades from ~1.16 s to **multiple seconds**
  (measured ~10 s at only 46 in-flight cts; the ceiling is higher). The chain keeps producing blocks,
  never halts, never forks, and recovers when the backlog clears — so this is a **bounded compute-latency
  degradation, milder than the cycle-7 unbounded halt**, but it is real, on the enabled path, and
  attacker-influenceable. **It is the reason "block time stays flat" cannot be claimed.**
- **Remediation (cycle-10):** exactly the fix the cycle-8 report already prescribed and cycle-9 deferred —
  a **per-block ciphertext-maturity admission / fair grace-window scheduler** so total per-block work is
  `O(S × K_max)` with `K_max` **small enough that block time stays flat** (e.g. drain the oldest few
  ciphertexts to completion per block with a guaranteed heal-before-grace), **plus** the per-block
  admission rate limit at `types.go:387`. The per-ct budget granularity is correct and must stay; the
  cross-ciphertext work per block must be bounded by a **small** constant, not `cap = 128`.

### Self-adversarial re-read of the new bound (the questions the audit asked)

- **Processed-set read cost:** `IterateInFlightFrom(..., limit = 128, ...)` is a bounded prefix scan —
  **`O(cap)` = `O(128)`** iterator steps per block, a constant. Not a DoS vector. ✅
- **Can an attacker inflate the distinct-ciphertext (processed-set) count?** **No.** The processed set is
  a committed-state read capped at `128`, **independent of any attacker's VE share contents**. Shares for
  any ciphertext outside the oldest-128 window are `O(1)`-dropped before any budget/verify. An attacker
  can only influence the set by **submitting ciphertexts** (the admission path), which HIGH-U/#4 already
  covers. ✅ (no *new* inflation channel via shares)
- **Is the oldest-first selection fair / deterministic under adversarial ordering?** **Yes.** The set is
  read in `(decryptHeight, seq)` byte order from committed state, **independent of VE ordering**; the
  budget maps are order-independent — proven by `TestC9Probe_MultiCiphertextBound_OrderIndependent` and by
  the 353 + 231 byte-identical live heights under a max-spray adversary. ✅
- **Net:** the only real new finding is **HIGH-U** — the *magnitude* of the (correct, deterministic)
  compute bound, not its determinism or fairness.

### Carried-open cycle-6 HIGHs (out of scope for this fix; verified untouched from the diff)

- **HIGH-2 — Byzantine QUAL dealer permanently bricks an epoch's decryption, no complaint recourse.**
  `3d396dda` touches neither `onchain.go` nor `endblock.go`. **Still open.**
- **HIGH-3 — the transparent VE-DKG has NO complaint/justify round at all** (root cause of HIGH-2). The
  fix adds no complaint field/phase. **Still open.**

### Notable residuals carried from cycle-6/8 (medium-class, non-blocking-but-material)

- **No per-block ciphertext admission rate limit** (`types.go:387`, `32768 / 2048`) — now **doubly
  material**: it is the axis HIGH-U rides, and the sybil-flood surface. Must be added with the HIGH-U
  scheduler.
- **Defer-cap fairness is per-SUBMITTER and submitter identity is free → sybil defeats it.** Compounds
  HIGH-U's flood reachability.
- **Overflow-magnitude stake silently kills the stake-drift rekey** (default-off, not a live risk today).

---

## 5. Residuals & the EXTERNAL-audit focus list

### The THREE HIGH blockers to ENABLE (must fix + re-audit before turning the feature on)

1. **HIGH-U (cycle-9, NEW) — bound the cross-ciphertext per-block work to a SMALL constant.** Keep the
   per-`(operator, ciphertext)` budget granularity (it fixes HIGH-T); replace the `cap = 128` distinct-
   ciphertext allowance with a **per-block ciphertext-maturity admission / fair grace-window scheduler**
   that drains the oldest few ciphertexts to completion per block (guaranteed heal-before-grace) so total
   per-block verify work is `O(S × K_max)` with `K_max` small enough that **block time stays flat**, AND
   add the per-block admission rate limit at `types.go:387`.
2. **HIGH-2 / HIGH-3 (cycle-6, carried) — add a share-validity gate AND a complaint/justify round to the
   transparent path.** (i) verify every enc-share against the dealer's Feldman commitments on consume;
   (ii) add a complaint field to `types.VoteExtension` + a complaint→justify phase to
   `ConsumeVoteExtensions` so `finalizeRound`'s `disq` set is populated on the transparent path;
   (iii) exclude a complaint-proven-bad dealer from QUAL and sum `DeriveShares` only over the healthy set.

### Required regardless of the above

3. **External professional audit REQUIRED before ANY mainnet reliance.** Hand the firm §3/§4/§5, the full
   `audit_c6_*` / `audit_c7_*` / `audit_c8_*` / `audit_c9_*` / `zzz_*` probe corpus, the env-gated
   adversary harness (`evmd/dkg_attack.go`), and the cycle-5..9 live verdict runs. **No external audit has
   been performed.**
4. **Per-block admission rate-limit for maturing ciphertexts** (`types.go:387`) — folded into HIGH-U.
5. **Sybil-vs-defer-cap-fairness** (cycle-6 residual) — price sybils or weight the defer-cap fair-share.
6. **Drift-metric overflow robustness** (cycle-6 residual).
7. **The decrypt bar is `> 2/3 − 2n/S`** (≈ 54.7 % at defaults), NOT ">2/3" — honest-statement obligation.
8. **Committee stake ≠ total bonded stake** (top-N by stake; fractions are of snapshotted committee stake).
9. Carried non-blocking deferrals from cycle 2, unchanged: injected blob occupies `Txs[0]`; lenient
   `ProcessProposal`; remote-signer/KMS nodes safely non-participate.

---

## 6. Design reference — what "transparent" means and how it is wired (stable since cycle 1)

### The goal
A bonded validator that simply **runs the binary** becomes a DKG member automatically: **no separate
daemon**, **no account/fee setup**, **no manual enc-key registration**, **no declared member list**.

### The three pillars

**Pillar 1 — In-node auto-participation via ABCI++ vote extensions** (`evmd/dkg_voteext.go`):

| Phase | Handler | What it does |
|-------|---------|--------------|
| `ExtendVote` | `dkgExtendVoteHandler` | Packs `{EncPubKey + PoP, Feldman dealing, DLEQ-proved per-eval-point decryption shares for EVERY in-flight ciphertext}` into the precommit's `VoteExtension`. Node-local. (This per-ciphertext honest demand is exactly what the cycle-9 per-`(operator,ciphertext)` budget now serves in full — HIGH-T closed.) |
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` | Structural check + BYTE cap (`1 MiB`) + two honest-safe SHARE-COUNT caps (per-VE `<= VoteExtShareCap`, per-ciphertext `<= S`). Non-binding local filter; the authoritative bound is in PreBlock. |
| `PrepareProposal` | `wrapDkgPrepareProposal` | Prepends the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` | Self-certifies `Txs[0]` with `ValidateVoteExtensions`, strips it, delegates. Gated by `veActive`. |
| `PreBlock` | `consumeDkgVoteExtensions` → `keeper.ConsumeVoteExtensions` | Resolves consensus address → operator; deterministic canonicalizing consume. **Cycle-9: Phase-3 decryption-share ingest runs through `ingestDecryptSharesBounded` — processed-set pre-classification + per-VE cap + within-block dedup + per-`(operator,CIPHERTEXT)` verify budget + global `O(cap × S)` ceiling. Compute is bounded to `O(cap × S)`/block (deterministic); honest multi-ciphertext liveness restored (HIGH-T closed), but the ceiling magnitude is high (HIGH-U). No complaint phase (HIGH-3).** |

**Env-gated adversary harness (audit builds only):** `evmd/dkg_attack.go` (`dkgAttackShares`, hooked in
`ExtendVote`) mutates ONLY this node's node-local vote-extension share list — no committed state — so a
node running it is byte-for-byte consensus-identical to the honest binary. `DKG_HOLD_FILE` withholds a
node's shares until a flag file appears (defer→heal proof); `DKG_CHAFF9`/`DKG_CHAFF9_FIRST` spray garbage
shares at real + fabricated ciphertexts (compute-DoS bound proof). Strict no-op unless the env var is set.

**Pillar 2 — Transparent key.** A secp256k1 ECIES key per member, minted with zero operator action
(`dkgnode.LoadOrCreateEncKey`, `<home>/dkg_enc_key.json`, 0600), auto-announced with an operator-bound
PoP, self-identity by OPERATOR.

**Pillar 3 — Members = bonded validators.** `TransparentMembers` derives the committee from the bonded
set: top-N by stake, clamped to `floor(S/8)` seats, each member's eval points apportioned by stake.
**Members carry NO account address — which is why the account-based complaint path is unreachable
(HIGH-2/3).**

### Determinism contract (the #1 fork risk — held through every live run, including cycle 9)
All determinism is confined to the consume half and the EndBlock DKG state machine, both pure functions
of `(committed state, entries)`. **Cycle-9 confirms this held with the processed-set read + per-ciphertext
budget maps added to PreBlock** — the maps/set are rebuilt each block from committed state, never
persisted, never ranged over, and bounded to `<= cap` distinct ciphertexts; the accept/reject/defer
verdict is a pure, order-independent function, and `app_hash` never diverged across 353 + 231 live
heights + a from-scratch genesis resync (§3). The three HIGH findings are liveness/availability/latency,
NOT divergence. (HIGH-U is a *timing* cost of the deterministic compute, not a determinism break.)

### Dormancy / kill-switch
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` AND vote extensions are active.
All enabling flags default false/0. **All three open HIGH findings are on the ENABLED path — none is
reachable while dormant.**

---

## 7. GO / NO-GO

### Verdict: `AUDIT_CLEAN = NO` — **NO-GO to ENABLE**; dormant-by-default MERGE is safe.

1. **NO-GO to enable the transparent DKG** on any chain relied on for confidentiality. HIGH-T (cycle-8
   honest-strand) is **closed and live-proven** (46-ct backlog drains, 0 strands; unit probes
   `32,32,32`), but the closure **introduced HIGH-U** (the per-ciphertext budget raises the per-block
   verify ceiling to `O(cap × S)` → attacker-influenceable block-time inflation, ~10 s observed at 46
   cts, bounded/recovering), and cycle-6 HIGH-2/HIGH-3 remain open — **3 open HIGH findings**, all
   liveness/availability/latency (no fork, no consensus halt-via-divergence).
2. **Merging DORMANT is safe.** With default params the binary is byte-behavior-identical to `17101a12`;
   none of the three HIGH findings is reachable; both modules build green (root + evmd exit 0), `gofmt` +
   `go vet` clean, and the full `-tags test ./x/encmempool/...` suite passes.
3. **External professional audit REQUIRED before ANY mainnet reliance**, independent of (1). **No
   external audit has been performed.**
4. **The release decision belongs to Jason** — merge timing, the cycle-10 HIGH-U scheduler + admission
   rate-limit, the HIGH-2/3 complaint round, and the enable vote are his call.

### What is safe today
Merging this branch **without enabling** is safe and preserves the fix + the committed probe/attack
corpus. What is NOT safe is turning the feature on: three HIGH liveness/availability findings are open,
one of them (HIGH-U) newly introduced by the cycle-9 fix's own bounding mechanism.

---

## 8. Scorecard

| Item | State |
|------|-------|
| Builds (root + evmd) | ✅ exit 0 (root `go build ./...`, evmd `go build ./...`, `go vet` both modules, `gofmt` — all clean this cycle) |
| Full test + probe suite (`-tags test ./x/encmempool/...`) | ✅ PASS (keeper suite green; cycle-9 probes assert HIGH-T CLOSED: `ct1=32 ct2=32 ct3=32`) |
| Consume-path + EndBlock determinism (unit + live) | ✅ 0 divergence, every cycle; cycle-9: **353 heights [10..362] byte-identical on 8 nodes + a from-scratch resync reproduces 231 heights [170..400] incl. the attack/drain window** |
| Transparent experience (no daemon/account/fee/key/list) | ✅ proven live, cycles 1–9 |
| Kill-switch / dormancy | ✅ default-off; all 3 open HIGH findings unreachable while dormant |
| cycle-7 HIGH-A / HIGH-B (unbounded / re-verify compute DoS) | ✅ CLOSED (cycle-8), not re-opened (HIGH-U work is BOUNDED to `O(cap × S)`, deterministic, recovers) |
| **cycle-8 HIGH-T — per-`(operator,epoch)` budget throttles honest decrypt → strand** | ✅ **CLOSED (cycle-9)** — per-ciphertext budget; live 46-ct backlog drains, 0 strands; unit probes `32,32,32` |
| **cycle-9 HIGH-U — per-`(operator,ciphertext)` budget raises per-block verify ceiling to `O(cap × S)` → attacker-influenceable block-time inflation** | ❌ **OPEN — NEW** (bounded/recovers, not a halt; ~10 s observed at 46 cts; coupled to the no-admission-rate-limit residual) |
| **cycle-6 HIGH-2 — Byzantine QUAL dealer bricks epoch, no recourse** | ❌ **OPEN** (out of scope) |
| **cycle-6 HIGH-3 — no complaint/justify round on transparent path** | ❌ **OPEN** (out of scope) |
| Bounded ingest — pure / deterministic / order-independent / no-panic | ✅ proven (processed-set + budget maps rebuilt each block, never persisted; 353 + 231 live heights + resync; order-independence probe) |
| Multi-node live verdict run (cycle 9) | ✅ GREEN on HIGH-T (multi-ct backlog drains, 0 strands, determinism airtight, resync reproduces). ⚠️ Block time **NOT flat** under the drain (~10 s peak → HIGH-U), honestly recorded |
| Security audit (cycle 9) | ❌ **`AUDIT_CLEAN = NO`** — HIGH-T closed; **3 open HIGH** (HIGH-U new + HIGH-2/3 carried) (§4) |
| External audit | ❌ NOT DONE — **required before any mainnet reliance** regardless |
| **Enable on a real chain** | ❌ **NO-GO** — bound HIGH-U (cycle-10 scheduler + admission rate-limit) + HIGH-2/3 complaint round + re-audit first |
| **Merge DORMANT (feature off)** | ✅ safe — byte-behavior-identical to `17101a12` |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release, and
do NOT enable the transparent DKG until all three HIGH findings are closed and re-audited. The cycle-9
fix closes the cycle-8 honest-strand (live-proven: a 46-ciphertext backlog drains with zero strands) but
its bounding mechanism raises the per-block verify ceiling to `O(cap × S)`, which inflates block time
under a multi-ciphertext backlog (HIGH-U) — it is a checkpoint, not a green light.*
