# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-04
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** `f8615df2` — *feat(encmempool/dkg): TRANSPARENT in-node DKG via ABCI++ vote extensions*
**Base:** `17101a12` (full on-chain validator-DKG + governance kill-switch, dormant defaults)

## Decision: **NO-GO for enabling on a real chain.**

The transparent experience Jason envisioned **is proven end-to-end on a live 4-node p2p
network with zero consensus divergence** — a validator participates in the DKG by *running
the binary alone*, no daemon, no fee account, no enc-key setup, no declared member list. The
mechanism works. But a security review found **4 HIGH-severity findings** (14 total), so the
feature is **not safe to switch on** yet. None of the four is a redesign; each has a concrete,
scoped fix listed in the GO/NO-GO section. Ship the fixes, re-audit, then it is a GO to enable.

`clean = false` because `AUDIT_CLEAN = NO` (4 HIGH). `builds = true`. `transparent proven = true`.

---

## FIX CYCLE — 2026-07-04 (all 4 HIGH fixed, med/low triaged)

The four HIGH findings are now fixed with minimal, scoped changes; the transparent
experience, determinism/no-fork contract, and every prior HIGH fix are preserved. Each HIGH
carries a regression test that was verified to FAIL against the pre-fix source and PASS after.
`go test -tags test ./x/encmempool/... -count=1` is green; `go vet` + `gofmt` clean; the `evmd`
binary builds (exit 0).

- **HIGH-1 (halt on misconfig) — FIXED.** `veActive` (`evmd/dkg_voteext.go`) now couples to the
  consensus param: it is true only when `DkgEnabled && DkgTransparent` AND vote extensions are
  active at this height (`types.VoteExtEnabledAt(enableHeight, blockHeight)` = `enableHeight!=0 &&
  height>enableHeight`, mirroring `baseapp.ValidateVoteExtensions` exactly), so no VE handler
  ever acts — and `ProcessProposal` never self-certifies an un-validatable commit — while VE is
  inactive. `MsgUpdateParams` additionally REJECTS enabling `DkgTransparent` unless VE is
  scheduled (`vote_extensions_enable_height != 0`). Regression: `TestReg_H1_*`.
- **HIGH-2 + HIGH-4 (enc-key impersonation / no uniqueness / self-identifier overload) — FIXED.**
  `RecordEncPubKey` now requires an operator-bound PROOF-OF-POSSESSION (`dkg.SignEncKeyPoP` /
  `dkg.VerifyEncKeyPoP` — an ECDSA signature by the enc private key over the operator, so a
  replayed key+PoP fails under a different operator) and enforces CROSS-OPERATOR UNIQUENESS via a
  reverse index (`EncKeyOwnerPrefix`). The node self-identifies by OPERATOR
  (`types.MemberIndexByOperator`, resolved from its consensus address via
  `dkgnode.LoadConsAddress` + staking) instead of by an enc-key first-match. Regression:
  `TestReg_H2_*`, `TestReg_H4_*`.
- **HIGH-3 (count-majority threshold vs stake-ranked seats) — FIXED.** Each `RoundMember` carries
  its snapshotted STAKE `Weight` (NOT part of `MembersHash`, so stake drift never churns the
  committee). The decrypt path (`recoverSharedSecret`, DKG epoch>0) now requires the contributing
  set to hold a STRICT MAJORITY of committee stake (`keeper.DecryptingSetMeetsStake`,
  overflow-safe `sdkmath.Int`), so a stake-minority Sybil holding a seat-majority can no longer
  form a valid decrypting set. Legacy/unweighted rounds are unaffected (gate returns true).
  Regression: `TestReg_H3_*`.

### Med/low triage (this cycle)

FIXED / addressed inline with the HIGH work:
- PoP verification is panic-safe in the consensus consume path (parse errors → reject, no panic).
- Enc-key reverse (uniqueness) index is GC'd on key rotation, so no stale owner entries accrue.
- `RoundMember.Weight` deliberately excluded from `MembersHash` (avoids stake-drift rekey flaps).
- Stake gate is overflow-safe and a strict no-op on the legacy declared-member path.
- Idempotent re-announce short-circuits BEFORE PoP verification, so the hot path does no crypto.

DEFERRED (documented, non-blocking):
- **Injected blob is `Txs[0]`** and relies on the default tx runner's deterministic decode-fail
  (one wasted "failed tx" slot/block). Bounded + deterministic; a custom skip-runner is a higher
  halt-risk change — deferred.
- **Lenient `ProcessProposal`** (a proposer that omits the blob is accepted): a Byzantine
  proposer can stall DKG *progress* (not fork/halt). Accepted tradeoff for liveness.
- **`ValidateVoteExtensions` depends on `ctx.CometInfo()/HeaderInfo()`** being populated in
  ProcessProposal (documented SDK usage; exercised by the 4-node run). Deferred.
- **Remote-signer / KMS nodes**: self-identity is read from `<home>/config/priv_validator_key.json`;
  a node whose consensus key lives only in a remote signer (no local key file) cannot resolve its
  operator and therefore does not participate in the DKG (safe: non-participation, never a halt).
  Follow-up: allow the operator/consensus address to be supplied via config/flag.
- **Deferred proof re-runs** (harness, not code): a second full encrypt→decrypt under epoch 2
  (post-rekey) and a JOIN membership change — to be re-run on the 4-node harness before enabling.

---

## 1. Design — what "transparent" means and how it is wired

### The goal
A bonded validator that simply **runs the binary** becomes a DKG member automatically. It is
not aware the module exists. There is:
- **no separate daemon** (the old path was `evmd dkg start` submitting `MsgDkgDeal` txs);
- **no account / fee setup** (the old path needed a funded dealer account to pay tx fees);
- **no manual enc-key registration** (the old path declared each member's secp256k1 key in params);
- **no declared `DkgMembers` list** (members are now the bonded validator set itself).

### The three pillars

**Pillar 1 — In-node auto-participation via ABCI++ vote extensions.**
The node attaches its DKG contribution to its *consensus pre-commit vote*, so CometBFT signs
and tags it with the node's consensus identity — no tx, no account, no fee. The pipeline
(`evmd/dkg_voteext.go`):

| Phase | Handler | What it does |
|-------|---------|--------------|
| `ExtendVote` | `dkgExtendVoteHandler` (`:62`) | Packs `{EncPubKey announcement, Feldman dealing for the open round, DLEQ-proved decryption shares}` into a `VoteExtension` on this node's precommit. Node-local content, no cross-node obligation. |
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` (`:164`) | Lenient structural check only (size bound + decodable). All crypto/membership/dedup is enforced deterministically on-chain later. |
| `PrepareProposal` | `wrapDkgPrepareProposal` (`:186`) | **Composes around** the existing EVM-mempool handler (`NewNoCheckProposalTxVerifier`): reserves bytes, calls the inner handler, then **prepends** the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` (`:222`) | If `Txs[0]` carries the marker, **self-certifies** it with `baseapp.ValidateVoteExtensions` (every ext-sig verifies against its validator's consensus key AND the set carries ≥2/3 power), strips it, delegates the remaining txs to the inner handler. |
| `PreBlock` | `consumeDkgVoteExtensions` (`:260`) → `keeper.ConsumeVoteExtensions` | Resolves each extension's **consensus address → operator** via staking (committed read) and hands the pairs to the keeper's **deterministic canonicalizing consume** path, BEFORE module PreBlock/BeginBlock/EndBlock. This **replaces** the `MsgDkgDeal` / `MsgSubmitDecryptionShare` tx paths. |

Composition is real, not a clobber: `evmd/mempool.go:86-89` wraps the default proposal
handlers rather than replacing them.

**Pillar 2 — Transparent key.** The DKG needs a **secp256k1 ECIES key** per member (the
consensus key is ed25519 — wrong curve). Resolved with zero operator action
(`x/encmempool/dkgnode/enckey.go`):
- `LoadOrCreateEncKey` (`:44`) mints + persists the key to `<home>/dkg_enc_key.json` (0600)
  on first boot.
- The pubkey is **auto-announced idempotently** in every vote extension
  (`RecordEncPubKey` is a no-op when unchanged, so no `MembersHash` flap).
- The key **doubles as the self-identifier**: `EncKey.MyIndex` (`:96`) finds the node's own
  1-based member index by matching its enc pubkey against the recorded member set — the node
  never needs its own operator/consensus address threaded into the app.

**Pillar 3 — Members = bonded validators.** `TransparentMembers`
(`x/encmempool/keeper/voteext.go:102`) derives the committee from the bonded validator set:
every bonded validator that announced an enc key, capped to the top-N by stake
(`EffectiveMaxMembers`) to bound VE / block-data size. Committee is chosen by (power desc,
operator asc), then **indices are assigned by operator-address order** so `MembersHash` is a
pure function of committed state. A validator leaving auto-triggers a rekey.

### Determinism contract (the #1 fork risk)
Vote extensions are consensus-critical: any non-determinism in *which* extensions the proposer
includes, their *ordering*, or their *verification* = fork/halt. The design confines all
determinism to the **consume** half (`keeper.ConsumeVoteExtensions`, `voteext.go:160`), which is
a pure function of `(committed state, entries)`:
- entries are **stable-sorted by operator + first-wins deduped** before any write;
- every write is idempotent / first-wins (`RecordEncPubKey`, `IngestDealingFromVE`,
  `IngestDecryptShareFromVE`);
- dealing/share validation **mirrors the msg-server exactly** (`validateDealingShape`), so a
  malformed contribution can never enter QUAL;
- the `EndBlockDKG` finalize + `BeginBlock` decrypt paths are **unchanged** (they already read
  only committed state);
- a last-resort `recover` in `ConsumeVoteExtensions` converts any data-dependent panic into a
  deterministic event (identical committed state ⇒ identical outcome on every node).

---

## 2. What was built (file map)

| File | Role |
|------|------|
| `evmd/dkg_voteext.go` | All ABCI++ wiring: ExtendVote / VerifyVoteExtension / PrepareProposal wrap / ProcessProposal wrap / PreBlock consume. Lazy per-node enc-key load (`sync.Once`). |
| `evmd/mempool.go:86-89` | Composes the DKG wrappers around the EVM-mempool proposal handlers; registers ExtendVote/VerifyVoteExtension. |
| `evmd/app.go:230-231,443,1062-1063` | `dkgHome` + `dkgEncKeyOnce` fields; home wired at construction; `PreBlocker` calls `consumeDkgVoteExtensions` first. |
| `x/encmempool/dkgnode/enckey.go` | Node-local (non-consensus) crypto: auto key gen/persist, `MyIndex`, `BuildDealing`, `DeriveShare`, `ProveShareFor`. Reuses `x/encmempool/dkg` + `/threshold` — no new cryptography. |
| `x/encmempool/keeper/voteext.go` | Deterministic consume half: enc-key registry, `TransparentMembers`, `ConsumeVoteExtensions`, `IngestDealingFromVE`, `IngestDecryptShareFromVE`. |
| `x/encmempool/types` | `VoteExtension` / `VoteExtDealing` / `VoteExtShare` wire types + marshal; `DkgTransparent` param; `EffectiveMaxMembers`; `Validate` relaxes the declared-member checks on the transparent path (`types.go:275-304`). |
| `x/encmempool/keeper/*_test.go` | Unit tests incl. an explicit **order-independence / fork-safety** test on the consume path; `audit_transparent_probe_test.go` encodes the audit probes. |

### Dormancy / kill-switch preserved
Every handler is a **strict no-op** unless `DkgEnabled && DkgTransparent` (both gov-toggleable
via `MsgUpdateParams`) **and** CometBFT vote extensions are enabled. `DefaultParams` ships
`DkgEnabled=false`, `EncEnabled=false`, `DkgTransparent=false` — the default binary behaves
exactly as `17101a12`. All prior proven invariants are intact: H1/H2 fixes, admission control,
bounded state, in-flight decrypt safety, `MembersHash` flap-avoidance.

### Verified locally this cycle
- `go build ./...` in **both** modules (`evmd` and root/`x/encmempool/...`): **exit 0**.
- Keeper vote-extension + determinism tests (`-tags test`): **PASS**.
- `go1.26.4`, `PATH=/home/prepauto/go-sdk/bin`.

---

## 3. Multi-node transparent proof (live 4-node p2p)

**Result: worked = true, transparent = true, diverged = false.** All three pillars proven live:

- **Vote extensions carried everything** — each node's enc-key announcement, Feldman dealing,
  and DLEQ decryption shares rode its consensus precommit; the proposer injected the H-1
  `ExtendedCommitInfo`; `ProcessProposal` self-certified it (`ValidateVoteExtensions`);
  `PreBlock` deterministically consumed it.
- **Auto-key + self-identify** — nodes auto-minted+persisted their secp256k1 key on first
  participation and self-identified by matching their own pubkey against the recorded member set.
- **Members == bonded validators** — automatic; unbonding `val3` (4→3) auto-rekeyed to epoch 2.
- **Consensus safety held perfectly** — **17/17 app-hash samples byte-identical across all 4
  nodes, ZERO divergence**, including through both vote-extension DKG rounds and the rekey. The
  #1 fork risk did not materialize.
- **Kill-switch** — dormant → active via one `MsgUpdateParams`, works.
- **Encrypt → decrypt** — byte-identical plaintext on all 4 nodes, with the decryption shares
  supplied **entirely by the nodes' vote extensions** (no daemon, no share-submit tx).
- Threshold used the majority floor(n/2)+1 (`dkg_threshold=0`): t=3 for n=4, t=2 for n=3, both
  finalized with full QUAL.

### Honesty caveats on the proof (re-run these next cycle)
1. **Encrypt→decrypt was proven under epoch 1 (pre-rekey).** After the rekey the epoch-2 pub
   was verified identical on all 4 nodes and epoch 1 was GC-pruned, but a **second full
   encrypt→decrypt cycle under epoch 2 was NOT run**.
2. **Membership change tested the LEAVE direction only** (unbond 4→3). A **JOIN** exercises the
   same `TransparentMembers` path but was not separately run.
3. All friction encountered was in the *driver scripts* (gov 10s voting-period race; a base64
   AES-nonce parse bug), **never in the code under test** — the DKG/VE machinery behaved
   correctly on the first live attempt.

> Note: the single-machine hard-isolation harness could NOT exercise the live multi-node ABCI
> loop; the 4-node proof above is the authoritative end-to-end evidence. Build-/app-init
> verification and the 4-node run are the two independent confirmations.

---

## 4. Audit findings — 14 total, **4 HIGH**, `AUDIT_CLEAN = NO`

The 4 HIGH findings are the blockers. (This report itemizes the 4 critical/high provided by the
audit run; the remaining 10 are medium/low and live with the full audit output — fold them in
during the fix cycle but they do not gate the GO/NO-GO.)

### HIGH-1 — Chain HALT when `DkgTransparent` is enabled without CometBFT vote extensions active (defective activation guard)
- **Where:** `evmd/dkg_voteext.go:190` (PrepareProposal guard) + `:233-245` (ProcessProposal →
  `baseapp.ValidateVoteExtensions`). Root cause: `veActive()` (`:42-45`) keys **only** off
  module params (`DkgEnabled && DkgTransparent`) with **zero coupling** to the consensus-param
  `VoteExtensionsEnableHeight`; and `types.Validate()` (`types.go:275-304`) has no VE-height
  coupling either.
- **Why it halts:** the transparent path needs TWO independent switches on together — the
  module param `DkgTransparent` (gov `MsgUpdateParams`) **and** the consensus param
  `VoteExtensionsEnableHeight` (a separate consensus-params update). Nothing prevents flipping
  `DkgTransparent=true` while VE is not (yet) enabled at the CometBFT level, or crossing the VE
  enable-height boundary inconsistently. Once `veActive` returns true, `ProcessProposal` will
  self-certify / require a VE blob whose signatures `ValidateVoteExtensions` cannot validate
  (VE not active for that height) → every validator REJECTs → no acceptable proposal → **halt**.
- **Verified in code this cycle:** `grep` confirms `veActive` has no `GetConsensusParams()` /
  `VoteExtensionsEnableHeight` read anywhere.

### HIGH-2 — Enc-key impersonation (no per-key uniqueness) knocks a victim out of threshold decryption
- **Where:** `x/encmempool/keeper/voteext.go:55-64` (`RecordEncPubKey` — no cross-operator
  uniqueness) + `:102-131` (`TransparentMembers` — no per-key dedup) + `dkgnode/enckey.go:96-103`
  (`MyIndex` first-match) + rejection at `voteext.go:337-339`.
- **Why:** enc pubkeys are public (observed from vote extensions). `RecordEncPubKey` accepts any
  valid compressed point with **no uniqueness check and no proof-of-possession**, so a committee
  validator can announce a *victim's* key. Two operators then sit in the committee bound to the
  **same** key; `MyIndex` first-match + the `idx != s.Index` share-authorization can misroute /
  silence the honest member's shares, dropping the victim out of the threshold set.

### HIGH-3 — Threshold is a COUNT-majority but committee seats are STAKE-ranked → a stake-minority Sybil gets a decrypting majority
- **Where:** `x/encmempool/keeper/dkg.go:347-352` (`roundThreshold` = floor(n/2)+1 on member
  **count**) + `voteext.go:102-131` (`TransparentMembers` seats top-N by stake but the threshold
  is over the seated **count**).
- **Why:** an attacker who registers many low-stake validators can capture ≥ floor(n/2)+1 of the
  *seats* while holding a small fraction of *stake*, and thus a decrypting majority — breaking
  the "honest-stake-majority cannot be forced to decrypt" property the encrypted mempool relies on.

### HIGH-4 — Auto-announced key has no PoP + no uniqueness AND doubles as self-identifier → grind a lower valoper to misindex + silence an honest member
- **Where:** `voteext.go:55-64` (`RecordEncPubKey`) + `dkgnode/enckey.go:96-103` (`MyIndex`) +
  `voteext.go:337-339` (`IngestDecryptShareFromVE` idx check).
- **Why:** compounding HIGH-2/HIGH-4 — the attacker copies a victim's key (no PoP) and grinds a
  lower valoper address so operator-order index assignment puts the attacker where the honest
  member expected to be; the honest member's `MyIndex` mismatches and its shares are rejected at
  `:337-339`. The honest member is silently removed from decryption.

**Common root cause across HIGH-2/3/4:** the enc key is (a) accepted without **proof-of-possession**,
(b) not **unique per operator**, and (c) overloaded as the **self-identifier**; and the threshold
is a **count** over a **stake-ranked** committee.

---

## 5. Determinism / consensus-safety assessment (design-level)
- **Consume path** — deterministic by construction (stable-sort, first-wins, msg-server-equivalent
  validation, committed-only reads); order-independence is unit-tested; the 4-node run showed
  17/17 identical app-hashes. **Risk: LOW.**
- **ExtendVote content** — node-local, no cross-node obligation, verified via DLEQ on decrypt.
  **Risk: LOW.**
- **ProcessProposal `ValidateVoteExtensions`** — reads only consensus/committed data, so it can
  only deterministically accept/reject (a reject → new round, never a fork). It depends on
  `ctx.CometInfo()/HeaderInfo()` being populated in ProcessProposal (documented SDK usage) —
  not confirmed on a running node in the single-machine harness, but the 4-node run implicitly
  exercised it. **Risk: MEDIUM-LOW, flagged.**
- **Liveness coupling** — once VE is on, chain liveness couples to validators running a correct
  ExtendVote/Verify. This is the design's known, accepted caveat (unchanged) and is exactly what
  HIGH-1 is about guarding at the activation boundary.

### Honest implementation gaps (not security-rated, but real)
- The injected blob is `Txs[0]` and relies on the default tx runner yielding a deterministic
  **decode-failure** result (one wasted "failed tx" slot per block) rather than a custom runner
  that skips it. Works, but wasteful; consider a runner that recognizes + skips the marker.
- `ProcessProposal` is **lenient** if the transparent path is active but a proposer omits the
  blob (accepts) — trades strict must-include enforcement for liveness. A Byzantine proposer can
  stall DKG *progress* (not fork/halt). Acceptable, but note it: DKG progress is not
  proposer-censorship-resistant.

---

## 6. GO / NO-GO

### Verdict: **NO-GO to enable** (feature stays on its branch, dormant). The transparent
mechanism is proven; the security hardening is not done.

### Exact remaining fixes (all four are scoped — no redesign)

1. **HIGH-1 (activation guard) — REQUIRED, do first.**
   Couple `veActive()` to the consensus param. Read
   `app.GetConsensusParams(ctx).Abci.VoteExtensionsEnableHeight` and require it be `> 0` **and**
   `ctx.BlockHeight() > VoteExtensionsEnableHeight` before any handler acts; otherwise no-op
   (fall back to the plain EVM-mempool path). ALSO add a guard so gov cannot leave the two
   switches inconsistent — either reject `DkgTransparent=true` in `types.Validate()` /
   `MsgUpdateParams` unless VE is scheduled, or make `veActive` the single source of truth that
   requires both. Re-test the enable-height boundary on the 4-node harness.

2. **HIGH-2 + HIGH-4 (impersonation / PoP / uniqueness) — REQUIRED.**
   In `RecordEncPubKey` (a) require a **proof-of-possession** on the announced enc key (a
   signature over the operator address / a challenge, carried in the vote extension), and
   (b) enforce **cross-operator uniqueness** (reject a key already bound to a different operator).
   Stop overloading the key as the sole self-identifier — index by **operator** (which the app
   already resolves from the consensus address) rather than by enc-key first-match in `MyIndex`.

3. **HIGH-3 (stake-weighted threshold) — REQUIRED.**
   Make the decrypting threshold a function of **stake**, not seat count: either weight members
   by stake and require ≥⅔ (or a governed fraction) of committee **voting power**, or gate
   committee entry so seat-majority ⇒ stake-majority. Reconcile `roundThreshold`
   (`dkg.go:347-352`) with the stake-ranked `TransparentMembers`.

4. **Then:** fold in the 10 remaining medium/low findings, re-run the audit to `AUDIT_CLEAN=YES`,
   and re-run the two **deferred proof cases** from §3 (epoch-2 encrypt→decrypt; a JOIN membership
   change) on the 4-node harness. When audit is clean AND those two cases pass with 0 divergence,
   this flips to **GO to enable** (still gov-gated, still dormant-by-default).

### What is safe today
Merging this branch **without enabling** is safe: all handlers are no-ops under the default
params, the binary is byte-behavior-identical to `17101a12`, and both modules build green. The
NO-GO is strictly about **switching the feature on** on any real chain.

---

## 7. Scorecard

| Item | State |
|------|-------|
| Builds (evmd + root modules) | ✅ exit 0 |
| Consume-path determinism (unit + order-independence) | ✅ |
| 4-node transparent experience (no daemon/account/fee/key/list) | ✅ proven |
| App-hash consensus safety across nodes | ✅ 17/17 identical, 0 divergence |
| Kill-switch (dormant→active→disable) | ✅ |
| Encrypt→decrypt via VE-only shares (epoch 1) | ✅ |
| Encrypt→decrypt under epoch 2 (post-rekey) | ⚠️ not re-run |
| JOIN membership change | ⚠️ not run (LEAVE proven) |
| Security audit | ❌ 4 HIGH / 14 total — NOT CLEAN |
| **Enable on a real chain** | ❌ **NO-GO** until the 4 HIGH fixes land + re-audit |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release.*
