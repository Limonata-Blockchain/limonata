# Transparent-DKG remediation design (v2) — post adversarial critique

**Branch:** `limonata-dkg-transparent` · **Status:** design, not yet implemented.
**Produced by:** a design→critique workflow (ground 3 subsystems → design 2 fixes → adversarial
critique). The v1 designs were **rejected** by the critique; this doc is the corrected v2 that the
build follows. Decision (Jason, 2026-07-05): stop the audit loop, DESIGN then BUILD these two.

Closes the four open DKG HIGHs: **HIGH-U** (halt-class compute-DoS), **HIGH-T-skew** (whale share
starvation), **HIGH-2** (byzantine QUAL dealer bricks an epoch), **HIGH-3** (no complaint round).

---

## 0. What the adversarial critique exposed (why v1 was not shippable)

**FIX 1 (anti-halt) v1 — rejected. Sound part kept, rest redesigned:**
- ❌ The invariant "processed window `K_max = D` covers every in-grace ciphertext" is **false**: the
  in-state matured-but-short set is bounded by `MaxInFlightEncTx = 32768` (`types.go:387`), NOT by the
  per-block defer-slot cap `D`. Ciphertexts deep in the `(decryptHeight,seq)` queue get zero share-ingest
  and strand → HIGH-T reborn, 16× worse after shrinking `K_max 128→8`.
- ❌ A **global** per-block admission slot is a one-address permanent ingress DoS + a free proposer
  censorship lever.
- ❌ Precomputing `Y_1..Y_S` in a single `finalizeRound` is an epoch-boundary `S·t`-scalar-mult spike —
  HIGH-U relocated, not closed. And a pruned/cold `Y` cache silently re-opens the `O(t)` verify + strands.
- ❌ Over-claim: v1 "GUARANTEEs the oldest reaches threshold under a whale-skewed committee, regardless of
  stake skew." **False under an adversarial whale.** Limonata runs a ~70%-VP validator; if that whale is
  the adversary and withholds, honest stake < t and **nothing can decrypt — no scheduler heals it.**
- ✅ **C2 (marginal-point supply) is sound** and genuinely fixes the *honest-greedy*-whale inefficiency.

**FIX 2 (complaint) v1 — architecture sound, wiring broken:**
- ❌ Written in a `member-index == eval-point` model. The deployed transparent path is **always
  stake-weighted** (`endblock.go:235-236` → `AllocateEvalPoints`, `Weighted=true`), where a member owns a
  **contiguous block of eval-points ≠ its index** and enc-shares are keyed by eval-**point**
  (`enckey.go:166`). So v1's `findEncShare(dealing.EncShares, accuserIdx)` + `VerifyJustifiedComplaint(
  accuserIdx, ...)` are wrong on 100% of the real path → **a single member frames any honest dealer out of
  QUAL (safety break)**, and **honest complaints are rejected (HIGH-2 stays open)**.
- ❌ Framing/frivolous complaints are (correctly) not stored — but then re-charge the `O(t)` DLEQ **every
  block**, starving honest complaints out of the per-block budget → cheater survives.
- ❌ The derive-time belt detects corruption but triggers **no recovery**; an offline stake-major whale
  poisoned by a dealer bricks the epoch until the next scheduled rekey.
- ✅ **Sound and kept:** accountless VE complaints authed by **operator/consensus identity** (Pillar 3);
  the **freeze-QUAL-once-at-finalize** invariant (removing a QUAL dealer after derivation would corrupt
  the group key — forbidden; post-finalize cheaters handled by a fresh-epoch rekey); reuse of the existing
  framing-resistant `VerifyJustifiedComplaint` / `ProveDecryptShare` DLEQ primitives.

---

## FIX 1 (v2) — anti-halt: honest-scoped, per-submitter admission, chunked+pinned verify keys

### F1.1 Honest security boundary (stated up front, not buried)
Threshold decryption needs **> 2/3 of committee stake online and honest**. Under an adversarial
supermajority (e.g. the 70%-VP whale withholding), decryption is **impossible by assumption** and the
correct outcome is a **loud grace-expiry strand**, not a heal. FIX 1 guarantees heal-before-grace **only**
under honest supermajority *and* inflow ≤ heal rate `ρ`. It never claims to beat an adversarial whale.

### F1.2 The four coordinated changes
- **C2 — marginal-point, oldest-first supply (KEEP from v1, it is sound).** `buildDecryptShares`
  (`evmd/dkg_voteext.go:173-218`, node-local `ExtendVote`) emits only **not-yet-stored** owned points,
  oldest ciphertext first, and **skips threshold-complete ciphertexts**. This stops an honest-greedy whale
  from re-burning its budget on a saturated head and lets it reach grace-critical ciphertexts. Reads
  (`CollectShares`, threshold) are committed-state, so honest nodes align on the same marginal schedule.
- **C1' — bound the *in-state matured-short set*, not just a per-block constant.** The real fix for the
  false invariant: cap the concurrently-in-grace-but-short population to a **hard bound `B`**, and set the
  verify/processed window `K_max ≥ B`. Enforce `B` at maturity: when a ciphertext matures into the
  decrypt queue and the in-grace-short count already `= B`, **drop the oldest still-unhealable ciphertext
  loudly** (`releaseEncTx`, telemetry `encmempool_decrypt_backlog_evicted`) rather than silently letting
  the queue grow to 32768. This makes "the window covers the backlog" TRUE by construction. `B` is sized
  so `K_max·S` verify work stays flat (see F1.4).
- **C3' — PER-SUBMITTER admission rate limit + a sybil price, never a global slot.** Rate-limit maturing-
  ciphertext *admission per submitter account per block* (a small `r`), backed by the existing
  `MaxInFlightPerSubmitter` standing cap AND a **submission cost** (fee/bond escrow released on decrypt)
  so a sybil fleet is priced, not free. Aggregate inflow is thus bounded and no single address can
  monopolize ingress or let a proposer censor via a global slot. Determinism: a per-`(submitter,height)`
  KV counter, incremented in canonical DeliverTx order, lazily height-reset, never ranged.
- **C4' — precompute the epoch verify keys `Y_1..Y_S`, but CHUNKED across blocks + epoch-PINNED.** Spread
  the `S·t` precompute over the deal→finalize window (a bounded slice per block), store
  `ActiveShareKeyPrefix|epoch|index`, and **pin the cache for the epoch's whole in-flight lifetime**
  (ref-count against referencing EncTxs; never let `maybePruneEpoch` GC `Y` while a ciphertext of that
  epoch is in flight). `verifyDecryptShareDLEQ` looks up `Y_index` (O(1)); a **bounded** on-the-fly
  `SharePubKey` fallback covers only a cold pre-upgrade epoch and is itself rate-limited so it can't
  re-open HIGH-U.

### F1.3 Why this closes both HIGHs (honestly scoped)
- **HIGH-U:** per-block verify count `= K_max·S` with `K_max = B` small (F1.4); per-verify cost `O(t)→O(1)`
  via C4' (chunked, no epoch-boundary spike). Sustained work `= marginal decryption progress`, because C3'
  bounds inflow and C1' bounds the in-grace set — the ceiling can no longer be pinned at saturation
  indefinitely. Block time stays flat under honest load; an adversary pays per submission and still cannot
  exceed `K_max·S`.
- **HIGH-T-skew:** C2 marginal-supply + C1' bounded head means the whale always reaches every in-grace
  honest ciphertext; the oldest reaches `t` each block **when honest supermajority is online** (`Σ points
  ≥ t`). Under an adversarial whale it correctly strands (F1.1).
- **No HIGH-T regression:** control-3 per-`(operator,ciphertext)` budget is kept verbatim.

### F1.4 Sizing `B`/`K_max` and `r` (to be finalized during build with a live drain measurement)
`K_max = B` chosen so `K_max·S` O(1)-DLEQ checks fit in a small block-time slice (target < a few hundred
ms at gov-max S=2048 → `K_max` on the order of low tens, measured, not guessed). `r` (per-submitter
admissions/block) set ≤ the measured honest heal rate `ρ` so the in-grace set is drift-free; the global
throughput ceiling this implies is stated honestly as a product limit (anti-MEV mempool tx/s is bounded by
`ρ`). These two numbers are the one thing that must be tuned against a real 8-node drain during the build,
not fixed a priori (the v1 `K_max=8, R_max=2` pair was self-contradictory — `R_max` must be `≤ ρ`).

### F1.5 Files
`evmd/dkg_voteext.go` (C2 supply rewrite), `x/encmempool/keeper/abci.go` (C1' maturity-eviction + bounds),
`x/encmempool/keeper/voteext.go` (K_max, verify-key lookup), `x/encmempool/keeper/msg_server.go` +
`keeper.go` + `types/keys.go` (C3' per-submitter counter + cost), `x/encmempool/keeper/dkg.go` (C4'
chunked precompute + pin), `x/encmempool/types/types.go` (params: per-submitter rate, submission cost).

---

## FIX 2 (v2) — complaint/justify round on the WEIGHTED, accountless path

### F2.1 Load-bearing correctness (kept from v1 — the critique confirmed it)
QUAL is computed **exactly once at `finalizeRound`** with `disq` fully populated, then **immutable** for
the epoch. Removing a dealer after derivation would redefine `Pub`/`Y_p`/`X_p` and corrupt every ciphertext
already encrypted to the epoch. Post-finalize cheaters are handled by the existing **rekey** path (fresh
epoch, new dealing+complaint round). `DeriveShares` already sums over the committed `ak.Qual`, so "sum the
healthy set only" (item iii) is automatic once QUAL is clean when frozen. Ordering (already in `openRound`):
`OpenHeight < DealDeadline < ComplaintDeadline ≤ finalize`.

### F2.2 The must-fixes (weighted-path wiring — the whole point)
- **MF1/MF2 — eval-point keying (SAFETY + LIVENESS).** The wire `VoteExtComplaint` **must carry the
  disputed eval-point `p`** (not rely on member index). `IngestComplaintFromVE`:
  (a) reject unless `accuser.OwnsEvalPoint(p)` (`types.go:208`); (b) select the enc-share **by `p`**
  (`enckey.go:166` point-keyed); (c) pass **`p`** (not `accuserIdx`) as the evaluation point into
  `VerifyShare` inside `VerifyJustifiedComplaint` (`onchain.go:330`); the DLEQ stays bound to the
  accuser's `EncPubKey` and the `A` **at point `p`**. This makes framing impossible again on the weighted
  path AND makes honest complaints actually store.
- **MF3 — negative-cache so garbage can't re-charge (DoS).** A framing/frivolous complaint verified once
  and rejected must be **remembered deterministically** (a per-`(epoch,against,accuser,p)` "seen-bad"
  marker, committed) so re-sends are O(1)-dropped **before** the `O(t)` DLEQ. Honest complaints draw from
  a reserved slice of `maxComplaintVerifiesPerBlock` that spam cannot displace (verify honest-eligible
  pairs first, or give each accuser a bounded per-window verify quota).
- **MF4 — derive-belt triggers an early REKEY, not just a local skip.** When `DeriveShares`' defensive
  `VerifyShare` detects a committed-QUAL dealer that sealed a bad share to a point this node owns (the
  offline-victim residual), it must **signal an on-chain early rekey** (a deterministic vote-extension
  flag aggregated to a threshold of witnesses, or a keeper-level counter that opens a fresh epoch) so a
  stake-major offline whale poisoned by a dealer does not brick the epoch until the next scheduled rekey.

### F2.3 The rest (sound in v1, kept)
Share-validity gate = node-local detector `buildDkgComplaints` in `ExtendVote` (opens each other dealer's
enc-share to *my owned points*, runs `VerifyShare`, emits a DLEQ-proved complaint on mismatch or no-deal);
`Complaints []VoteExtComplaint` field on `VoteExtension`; **Phase 4** in `ConsumeVoteExtensions`
(window-gated `DealDeadline < h ≤ ComplaintDeadline`, verify-before-store, first-wins keyed by
`(epoch,against,accuser)`); `finalizeRound`/`FinalizePublicWeighted`/`DeriveShares` **unchanged** — they
light up once Phase 4 populates `disq`.

### F2.4 Residual limit (honest, inherent to all complaint DKGs)
A dealer that cheats **only** points owned by members offline for the **entire** complaint window escapes
DQ that epoch (only the point owner can decrypt+complain). Bounded by: the MF4 rekey trigger (once the
victim is back online), the `minQualWeight = Threshold` finalize gate, and the scheduled rekey. Widening
`DkgComplaintWindow` trades finalize latency for detection coverage.

### F2.5 Files
`x/encmempool/types/voteext.go` (`Complaints` + `VoteExtComplaint` with eval-point `p`),
`evmd/dkg_voteext.go` (`buildDkgComplaints`), `x/encmempool/keeper/voteext.go` (Phase 4,
`IngestComplaintFromVE` point-keyed, negative-cache, `maxComplaintVerifiesPerBlock` reserved slice),
`x/encmempool/keeper/dkg.go` (`GetComplaint`/seen-bad getters), `x/encmempool/dkg/onchain.go`
(`VerifyJustifiedComplaint` takes eval-point `p`), `x/encmempool/dkgnode/enckey.go` (derive-belt +
rekey signal). Tests MUST run on a **weighted** committee (member index ≠ eval point, whale owning a
point block) — v1's proposed tests would pass on an unweighted fixture and miss every finding.

---

## Build order (both fixes, on the throwaway worktree, DKG stays dormant/off)

1. **FIX 2 first** (architecture is sound, must-fixes are concrete wiring): eval-point-keyed complaint +
   negative-cache + rekey-trigger + Phase 4. Regression tests on a weighted committee. This closes
   HIGH-2/HIGH-3 and is the lower-risk of the two.
2. **FIX 1**: C2 (already sound) + C1' maturity-eviction bound + C3' per-submitter admission + C4' chunked
   pinned verify-keys. Tune `K_max`/`r` against a live 8-node drain (the one thing that needs measurement).
3. **One verifying adversarial audit** of both (not a loop): weighted-committee complaint regression,
   drain-under-skew, block-time-flat, determinism (byte-identical app-hash across nodes + a resync).
4. Build + `go vet` + `gofmt` + `-tags test ./x/encmempool/...` green; DKG remains off-by-default.
5. **External professional audit still required before enabling — regardless.**
