# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-04 (audit cycle 4 close-out)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** `2c2a271d` — *fix(encmempool/dkg): close the 6 cycle-3 findings*, atop
`19d5cb6f` (stake-weighted secret sharing) → `a75b027f` → `36b6ee82` → `17101a12`

---

## VERDICT: `AUDIT_CLEAN = YES` — **GO-to-enable readiness reached** (with the conditions below)

For the first time in four audit cycles, an independent adversarial audit of this feature
returned **zero critical and zero high findings** (14 findings total, all medium/low/informational
— triaged into the caveats and the cycle-5 focus list in §5), and an independent multi-node
verdict run returned **GO on all five mission proofs**, with every prediction matching to the
point (§4).

**What "GO-to-enable readiness" means — and does NOT mean:**

- The feature is **still gov-gated and dormant-by-default**. `DefaultParams` ships
  `DkgEnabled = DkgTransparent = false`; the default binary is byte-behavior-identical to
  `17101a12`. Nothing turns on without an explicit governance vote AND vote extensions
  scheduled in consensus params.
- **This internal audit trail is NOT a substitute for an external audit.** Four adversarial
  cycles found and closed real breaks (4 HIGHs, then a wrong-layer fix, then a config hole and
  a liveness band that shipped past cycle 3's own review). An **external professional audit is
  required before ANY mainnet reliance** on the encrypted mempool's confidentiality claims.
- **The release decision belongs to Jason.** This report states technical readiness only:
  the branch is internally clean, live-proven at its boundaries, and safe to leave dormant.
  When/whether to merge, schedule VE, and put an enable vote to governance is a product and
  risk decision, not an engineering default.

---

## 1. Cycle history — four audit cycles, every finding closed

| Cycle | Commit(s) | What happened |
|-------|-----------|---------------|
| **1** | `f8615df2` (feature), `36b6ee82` (doc) | Transparent in-node DKG built (VE auto-participation, transparent enc key, members = bonded set). Live 4→5-node proof of the transparent experience, 0 divergence. Audit: **NO-GO, 4 HIGHs** — HIGH-1 chain halt on misconfig, HIGH-2 enc-key impersonation, HIGH-3 stake-minority seat-majority capture, HIGH-4 self-identifier overload. |
| **2** | `a75b027f` (fix), `6201178d` (doc) | HIGH-1 closed (VE-coupled `veActive` + `MsgUpdateParams` guard, proven live from 3 angles), HIGH-2/4 closed (operator-bound PoP + cross-operator uniqueness + operator-indexed self-id). Both cycle-1 deferred proof cases (epoch-2 decrypt post-rekey, validator JOIN) pass live. **But HIGH-3 SURVIVED — the fix landed at the wrong layer**: `DecryptingSetMeetsStake` gated only the on-chain combine while the Shamir threshold stayed a seat COUNT, so a stake-minority seat-majority reconstructed the epoch key **off-chain** (3 probe tests proved it). **NO-GO.** |
| **3** | `19d5cb6f` (fix) | HIGH-3 closed at the **cryptographic layer**: stake-weighted secret sharing — Hamilton largest-remainder apportionment of a share budget S (`AllocateEvalPoints`), per-eval-point `EncShare`s, `FinalizePublicWeighted`, `DecryptingSetMeetsStake` demoted to defense-in-depth. Proven live on 4 nodes at default config, 0 divergence. Audit: **NO-GO, 11 findings** — the crypto was right in the intended regime but the **envelope wasn't**: (H-A) a VALID config with S < n made apportionment degenerate — decryption power tracked *operator-address order*, a 13–31% minority could reconstruct while the honest supermajority was locked out; (H-B) `t = floor(2S/3)+1` stranded honest online stake-supermajorities in a real band (66.7%→~72.9% at defaults) **inside the BFT fault model**, and the shortfall path **silently dropped** the matured ciphertext; plus M-1 (advertised ">2/3 to decrypt" bar not actually delivered), M-2 (S uncoupled from the VE share cap), L-1 (zero-weight member → eval-point collision → deterministic feature stall), L-2 (grindable operator-address tie-break). |
| **4** | `2c2a271d` (fix — **this report**) | All 6 cycle-3 findings closed (§2). Independent audit: **14 findings, 0 critical/high → `AUDIT_CLEAN = YES`**. Independent 4-node live verdict run: **GO on all five mission proofs** — threshold and coupling held at their exact numeric boundaries, the cycle-3 stranding configuration decrypts live, the H-A config hole is rejected by real governance, 602/602 identical app-hashes through an outage + catch-up + rekey (§4). |

**Held across every cycle (never regressed):** the transparent experience itself (no daemon, no
account, no fee, no manual key, no declared list), consume-path determinism / zero divergence,
dormancy + kill-switch, bounded VE/dealing size, H1/H2 flood-and-refcount invariants (any final
EncTx drop goes through `releaseEncTx`; O(cap) per-block scans only), and the legacy declared-DKG
path byte-identical.

---

## 2. Cycle-4 fix — what `2c2a271d` changed and the proven inequalities

### The threshold + coupling (H-A + H-B, the design core)

- **Threshold:** `t = floor(2S/3) − n + 1` (S = share budget, n = committee size), replacing
  `floor(2S/3)+1`. Full worst-case Hamilton-apportionment proof in `keeper/stakeweight.go`:
  for any coalition C with stake fraction f, points(C) ∈ (fS − |C|, floor(fS) + min(|C|, n−1)].
  Both inequalities are written in the code and enforced by regression sweeps:
  - **SAFETY:** f ≤ 1/3 ⇒ points ≤ floor(S/3) + n − 1 < t whenever S ≥ 6n − 1. The enforced
    S ≥ 8n coupling gives a margin ≥ (2n+1)/3 points.
  - **LIVENESS:** any ONLINE set with f > 2/3 of snapshotted committee stake has
    points > 2S/3 − n, hence points ≥ floor(2S/3) − n + 1 = t **exactly** — for ALL n up to the
    cap, ALL stake distributions, ALL offline patterns. **Zero residual liveness band** in the
    snapshot model; t is the LARGEST threshold with this guarantee, so confidentiality is
    maximized subject to guaranteed liveness. The cycle-3 66.7%→~72.9% strand band is gone;
    the auditors' search sweep now runs as a regression and finds nothing.
- **Coupling (H-A):** `Params.Validate` (shared by genesis `ValidateGenesis` AND
  `MsgUpdateParams`, mirroring the HIGH-1 config-consistency guard) enforces
  `S ≥ MinShareBudgetPerMember(=8) × effective committee cap`, so the S<n degenerate regime
  (decryption power tracking operator-address order) can neither ship in genesis nor be voted
  in. Runtime defense-in-depth where the committee actually forms: `TransparentMembers` clamps
  to `floor(S/8)` top-stake seats (loud `encmempool_dkg_committee_clamped` event, deterministic,
  never a halt) so S ≥ 8n holds at every round-open even against an unvalidated store write;
  `stakeThreshold` additionally degrades to a safety-floor threshold (loud
  `encmempool_dkg_threshold_degraded`) if S < 6n−1 ever slips through.

### The honest decrypt bar (M-1) — the ">2/3 to decrypt" claim is RETIRED

With rounding slop ±n points, ">2/3 stake to decrypt" is **not achievable together with
guaranteed >2/3 liveness**. The PROVEN bar, now stated everywhere the old claim lived:
any coalition reaching t holds **f > 2/3 − 2n/S**, which is **≥ 5/12 (~41.7%)** under the
enforced coupling, **always > 1/3** (the Byzantine bound), and **≈ 54.7% (140/256)** at the
live defaults (S=256, n≤16). The on-chain strict-majority gate (`DecryptingSetMeetsStake`)
remains as defense-in-depth for the on-chain combine only.

### Non-silent decrypt shortfall (H-B second half)

`errNotEnoughShares`/`errStakeMinority` on a matured ciphertext **no longer silently drops**:
the entry is DEFERRED (kept in state, loud `encmempool_decrypt_missed`, ref-counts intact,
vote extensions keep serving matured-but-deferred ciphertexts so late shares heal it) for a
bounded `StrandedDecryptGraceBlocks = 32`, then dropped LOUDLY via `encmempool_decrypt_stranded`
(submitter/seq/epoch/height/have/need/reason) **through `releaseEncTx`** — H2 ref-counts +
`maybePruneEpoch` preserved, O(cap) per-block scans preserved, ceiling shed still immediate
under flood pressure.

### The rest

- **M-2:** per-VE decryption-share cap coupled to S (`Params.VoteExtShareCap()` = max(256, S) —
  a member can own up to all S points of one ciphertext, so the cap must scale UP with S), and
  `maxDkgShareBudget` lowered 4096 → 2048 so the worst-case extension (dealing + S shares
  ≈ 870 KiB) provably fits `VoteExtMaxBytes` (1 MiB). 8×128 = 1024 ≤ 2048 keeps the full
  committee range configurable.
- **L-1:** zero-weight member of a weighted committee owns NOTHING — explicit
  `RoundMember.Weighted` flag (a `Weight.IsNil()` check does NOT survive the JSON store
  round-trip: sdkmath marshals nil as "0"). The collision → duplicate-enc-share → QUAL-empty →
  deterministic finalize stall is closed; a zero-token bonded validator can no longer stall the
  feature chain-wide. Legacy records (flag absent) are byte-identical.
- **L-2:** remainder-seat tie-break de-ground: (remainder desc, **stake desc**,
  **sha256(epoch ‖ operator) asc**) — byte-identical across nodes, rotates per epoch, so a
  vanity low-sorting operator address no longer captures tie-broken seats permanently.
  Allocation moved to `openRound` (epoch known there); `MembersHash` (operators only) is
  unaffected.

### Regression posture

All four cycle-3 auditor probe files are committed as flipped regressions (verified to FAIL on
`19d5cb6f` alone by temporarily reverting the threshold formula and the L-1 discriminator, PASS
with the fix), plus new property sweeps asserting BOTH inequalities for n ∈ [2..128] at boundary
distributions (adversary exactly 1/3, offline just under 1/3, whale+dust), seed-independent.
The cycle-4 auditors left a further verification-probe suite (exhaustive small-n subset
enumeration against the real `stakeThreshold`, gov-path coupling boundaries, runtime-clamp
backstop, exact-1/3 e2e non-reconstruction, worst-case VE size at S=2048, epoch-seeded tie-break
determinism) — currently untracked in `keeper/` and `types/` (`audit_c4_*`, `audit_cycle4_*`),
all green, recommended for promotion to committed regressions.
`gofmt`/`go vet` clean; `go test -tags test ./x/encmempool/... -count=1` ALL PASS (verified at
close-out with the cycle-4 probes present); evmd + root modules build.

---

## 3. Cycle-4 audit result — 14 findings, 0 critical, 0 high → `AUDIT_CLEAN = YES`

The cycle-4 adversarial audit re-attacked the full stake-capture surface: gov/genesis config
paths, the degraded runtime branches, exhaustive coalition subsets at small n, randomized sweeps
at large n, allocation determinism, VE size bounds, and the real crypto path end-to-end at the
exact 1/3 boundary. **No coalition at or below 1/3 stake reaches t at any valid config; no
online set above 2/3 falls below t; the config hole is unreachable via both validated paths and
the runtime clamp; allocation is a deterministic function of (snapshotted stake, epoch).**

The 14 findings are all medium/low/informational; none blocks enable-readiness. The substantive
residuals are captured honestly in §5 (stake-drift between rekeys, the never-live-exercised
grace path) and handed to cycle 5 / the external auditors as the focus list.

---

## 4. Multi-node live verdict run — **GO on all five mission proofs, 0 divergence**

An independent 4-node throwaway-network verdict run (fresh genesis, real governance, real
outage/recovery) confirmed every prediction **to the point**:

1. **Boundary liveness, live:** the exact stranding configuration cycle-3 reproduced in unit
   form (honest just-over-2/3 online set holding exactly 170 points vs the OLD t=171) now
   **decrypts live at maturity with zero deferral** under the new t. Boundary configs exercised
   live: n=4/S=256 and n=3/S=512.
2. **H-A config hole rejected by real governance:** a param-change proposal with S < 8×M was
   rejected with the precise validation error — the degenerate regime cannot be voted in.
3. **Consensus never wavered:** **602/602 identical app-hashes across all nodes**, through a
   node outage, its catch-up, and a rekey.
4. **Threshold + coupling held at their exact numeric boundaries** as computed on-chain —
   t = floor(2S/3) − n + 1 and S ≥ 8n matched the unit model precisely.
5. **Minority could not decrypt:** with the 86-point node offline, the remaining minority never
   produced a decrypt; recovery followed the honest supermajority exactly.

**Honest caveats on the live evidence (from the verdict run itself):**
- (a) **"Rekey on stake change" is NOT a live behavior.** `MembersHash` covers only the
  operator set (byte-identical to `19d5cb6f` — an unchanged design decision, not a regression):
  pure delegation changes only re-weight at the next membership-triggered rekey, so decryption
  power can drift from current stake between membership events. This needs a **deliberate
  product decision** (e.g. epoch-cadence rekey) before mainnet. See §5.
- (b) The live boundary exercised n=4/S=256 and n=3/S=512; full n-sweep coverage rests on the
  (green) unit property sweeps. Minority-cannot-reconstruct rests on the flipped regressions
  plus the live fact that the 86-point node was offline — **no live Byzantine reconstruction
  was staged** (that requires a malicious binary the isolation harness deliberately cannot
  produce). The authoritative negative-path evidence remains the regression suite, as in every
  prior cycle.
- (c) The deferral grace path (`StrandedDecryptGraceBlocks = 32`) **never fired** in the live
  run — the new threshold made every honest boundary case decrypt immediately. It is covered
  by unit/e2e tests only.

---

## 5. Residuals, stated honestly — and the cycle-5 / external-audit focus list

1. **Stake drift between rekeys** (§4a). The security guarantees hold against the stake
   SNAPSHOT at round-open. Between membership-triggered rekeys, delegations can move while
   eval-point allocation stays frozen. An attacker who acquires stake AFTER a snapshot gains
   nothing until the next rekey — but symmetrically, a validator that LOSES stake keeps its
   points until then. Decide deliberately: epoch-cadence rekey (bounded drift window) vs
   accepting the drift; do not let this default silently into a mainnet posture.
2. **Deferral grace path unexercised live** (§4c). Stage a live shortfall (take the committee
   below t at maturity, then heal it within 32 blocks; and separately let it expire) to observe
   `encmempool_decrypt_missed` → heal, and `encmempool_decrypt_stranded` → `releaseEncTx`.
3. **The decrypt bar is the M-1 bar** — > 2/3 − 2n/S (≈54.7% at defaults), NOT ">2/3". Anyone
   depending on the confidentiality threshold must read §2, not the retired claim.
4. **Committee stake ≠ total bonded stake.** The committee is the top-N by stake
   (`EffectiveMaxMembers`); all fractions are of SNAPSHOTTED COMMITTEE stake. Pre-existing,
   unchanged, inherent to bounding VE size.
5. Carried non-blocking deferrals from cycle 2, unchanged: injected blob occupies `Txs[0]`
   (one deterministic decode-fail slot per block); lenient `ProcessProposal` (Byzantine
   proposer can stall DKG *progress*, not fork/halt); remote-signer/KMS nodes safely
   non-participate (operator-via-flag follow-up).

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
apportioned by stake (cycle-3/4, §2); indices by operator order so `MembersHash` is a pure
function of committed state.

### Determinism contract (the #1 fork risk — held through every live run)
All determinism is confined to the consume half (`keeper.ConsumeVoteExtensions`), a pure
function of `(committed state, entries)`: stable-sorted, first-wins deduped, idempotent writes,
finalize/decrypt read only committed state, last-resort `recover` → deterministic event.
Order-independence unit-tested; every live run (cycles 1–4) byte-identical app-hashes.

### Dormancy / kill-switch
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` AND vote extensions are
active at the height. All three flags default false. Governance can disable at any time
(`MsgUpdateParams`); in-flight decrypt safety and flood/admission control proven in the
integration track and re-verified each cycle.

---

## 7. GO / NO-GO

### Verdict: **internally CLEAN — GO-to-enable readiness**, gated as follows.

1. **Still gov-gated, still dormant-by-default.** Merging this branch without enabling changes
   nothing; enabling requires VE scheduled + an explicit governance vote, and the HIGH-1 guard
   makes an inconsistent switch state unreachable.
2. **External professional audit REQUIRED before ANY mainnet reliance** on the encrypted
   mempool. The internal cycles were adversarial and independent, but they are not a
   substitute; hand the external auditors §5 (stake-drift window, grace path) plus the full
   probe suite as the starting corpus.
3. **Product decisions before mainnet:** the rekey cadence (stake-drift window, §5.1) and the
   honest public statement of the decrypt bar (§5.3).
4. **The release decision belongs to Jason** — merge timing, VE scheduling, and the enable
   vote are his call, not an engineering default.

### What is safe today
Merging this branch **without enabling** is safe: all handlers are no-ops under default params,
the binary is byte-behavior-identical to `17101a12`, both modules build green, and the full
regression suite (cycles 1–4, including every flipped auditor probe) passes.

---

## 8. Scorecard

| Item | State |
|------|-------|
| Builds (evmd + root modules) | ✅ exit 0 |
| Full test suite (`-tags test`, incl. all flipped auditor probes) | ✅ ALL PASS |
| Consume-path determinism (unit + order-independence + live) | ✅ 0 divergence, every cycle |
| Transparent experience (no daemon/account/fee/key/list) | ✅ proven live, cycles 1–4 |
| Kill-switch / dormancy | ✅ default-off, gov-disable proven |
| HIGH-1 (halt on misconfig) | ✅ closed cycle 2 — live ×3 + regression |
| HIGH-2/4 (enc-key impersonation / self-id) | ✅ closed cycle 2 — PoP + uniqueness + operator self-id |
| HIGH-3 (stake-minority capture) | ✅ closed cycle 3 at the crypto layer, envelope closed cycle 4 (H-A/H-B) |
| Cycle-3 H-A (S<n config hole) | ✅ closed — validation coupling + runtime clamp + degraded floor; gov-rejection proven live |
| Cycle-3 H-B (liveness band + silent drop) | ✅ closed — t = floor(2S/3)−n+1 (zero band, proven inequality) + loud bounded deferral |
| Cycle-3 M-1/M-2/L-1/L-2 | ✅ closed (honest bar / VE-cap coupling / zero-weight / de-grinded tie-break) |
| Multi-node verdict run (cycle 4) | ✅ GO on all 5 proofs — 602/602 app-hashes, boundary decrypt live, gov rejection live |
| Security audit (cycle 4) | ✅ `AUDIT_CLEAN = YES` — 14 findings, 0 critical, 0 high |
| External audit | ❌ NOT DONE — **required before any mainnet reliance** |
| Stake-drift rekey cadence decision | ⚠️ OPEN product decision (§5.1) |
| **Enable on a real chain** | **GO-ready** — gov-gated, dormant-by-default; decision is Jason's, after external audit for mainnet |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release.*
