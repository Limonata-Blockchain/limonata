# Transparent in-node validator-DKG — status & readiness report

**Date:** 2026-07-04 (fix cycle 4: cycle-3 audit close-out)
**Branch:** `limonata-dkg-transparent` (feature branch — DO NOT merge into any release)
**Commit under review:** HEAD — *fix(encmempool/dkg): close the 6 cycle-3 findings*, atop
`19d5cb6f` (stake-weighted secret sharing) → `a75b027f` → `36b6ee82` → `17101a12`

---

## FIX CYCLE 4 — 2026-07-04 (all 6 cycle-3 findings closed: H-A, H-B, M-1, M-2, L-1, L-2)

The cycle-3 audit of `19d5cb6f` (stake-weighted secret sharing, proven live on 4 nodes at
default config with zero divergence) returned **NO-GO with 11 findings**. This cycle closes
all six actionable ones with minimal changes; the whole prior regression suite stays green.

### The new threshold + coupling (H-A + H-B, the design core)

- **Threshold:** `t = floor(2S/3) − n + 1` (S = share budget, n = committee size), replacing
  `floor(2S/3)+1`. Full worst-case Hamilton-apportionment proof in `keeper/stakeweight.go`:
  for any coalition with stake fraction f, points ∈ (fS − |C|, floor(fS) + min(|C|, n−1)].
  - **SAFETY:** f ≤ 1/3 ⇒ points ≤ floor(S/3) + n − 1 < t whenever S ≥ 6n − 1.
  - **LIVENESS:** f > 2/3 online ⇒ points > 2S/3 − n ⇒ points ≥ t — for ALL n, ALL stake
    distributions, ALL offline patterns whose online remainder holds > 2/3 of the
    SNAPSHOTTED committee stake. **Zero residual liveness band** (t is the largest threshold
    with this guarantee — confidentiality is maximized subject to guaranteed liveness). The
    cycle-3 66.7%→~72.9% strand band is gone; the sweep that found it now runs as a
    regression and finds nothing.
- **Coupling (H-A):** `Params.Validate` (shared by genesis `ValidateGenesis` AND
  `MsgUpdateParams`, mirroring the HIGH-1 guard) now enforces
  `S ≥ MinShareBudgetPerMember(=8) × effective committee cap`, so safety holds with a
  ≥ (2n+1)/3-point margin. Runtime defense-in-depth: `TransparentMembers` clamps the
  committee to `floor(S/8)` top-stake seats (loud event `encmempool_dkg_committee_clamped`,
  deterministic, never a halt) and `stakeThreshold` degrades to a safety-floor threshold
  (loud `encmempool_dkg_threshold_degraded`) if an unvalidated config ever slips through.
  The S<n degenerate regime (decryption power tracking operator-address order) is
  structurally unreachable.

### The honest decrypt bar (M-1) — the ">2/3 to decrypt" claim is RETIRED

With rounding slop ±n points, ">2/3 stake to decrypt" is **not achievable together with
guaranteed >2/3 liveness**. The PROVEN bar, now stated everywhere the old claim lived:
any coalition reaching t holds **f ≥ (t − n + 1)/S > 2/3 − 2n/S**, which is
**≥ 5/12 (~41.7%)** under the enforced coupling, **always > 1/3** (the Byzantine bound),
and **≈ 54.7% (140/256)** at the live defaults (S=256, n≤16). The on-chain strict-majority
gate (`DecryptingSetMeetsStake`) remains as defense-in-depth for the on-chain combine only.

### Non-silent decrypt shortfall (H-B second half)

`errNotEnoughShares`/`errStakeMinority` on a matured ciphertext **no longer silently drops**:
the entry is DEFERRED (kept in state, loud `encmempool_decrypt_missed`, ref-counts intact,
re-attempted as late shares land — vote extensions now keep serving matured-but-deferred
ciphertexts) for a bounded `StrandedDecryptGraceBlocks = 32`, then dropped LOUDLY via
`encmempool_decrypt_stranded` (submitter/seq/epoch/height/have/need/reason) **through
`releaseEncTx`** — H2 ref-counts + `maybePruneEpoch` preserved, O(cap) per-block scans
preserved, ceiling shed still immediate under flood pressure.

### The rest

- **M-2:** per-VE decryption-share cap coupled to S (`Params.VoteExtShareCap()` = max(256, S)
  — a member can own up to all S points of one ciphertext, so the cap must scale UP with S or
  a high-stake member could never serve one), and `maxDkgShareBudget` lowered 4096 → 2048 so
  the worst-case extension (dealing + S shares ≈ 870 KiB) provably fits `VoteExtMaxBytes`
  (1 MiB). 8×128 = 1024 ≤ 2048 keeps the full committee range configurable.
- **L-1:** zero-weight member of a weighted committee owns NOTHING — explicit
  `RoundMember.Weighted` flag (a `Weight.IsNil()` check does NOT survive the JSON store
  round-trip: sdkmath marshals nil as "0"). The collision → duplicate-enc-share →
  QUAL-empty → deterministic finalize stall is closed; a zero-token bonded validator can no
  longer stall the feature chain-wide. Legacy records (flag absent) are byte-identical.
- **L-2:** remainder-seat tie-break de-ground: (remainder desc, **stake desc**,
  **sha256(epoch ‖ operator) asc**) — byte-identical across nodes, rotates per epoch, so a
  vanity low-sorting operator address no longer captures tie-broken seats permanently.
  Allocation moved to `openRound` (epoch known there); `MembersHash` (operators only) is
  unaffected.

All four cycle-3 auditor probe files are flipped into regressions (they FAIL on `19d5cb6f`
alone — verified by temporarily reverting the threshold formula and the L-1 discriminator —
and PASS with the fix), plus new property sweeps asserting BOTH inequalities for n ∈ [2..128]
at the boundary distributions (adversary exactly 1/3, offline just under 1/3, whale+dust),
seed-independent. `gofmt`/`go vet` clean; `go test -tags test ./x/encmempool/... -count=1`
ALL PASS; evmd builds.

**Residual, stated honestly:** the decrypt bar is the M-1 bar above (not >2/3); the
guarantees are against the stake SNAPSHOT at round-open (drift until the next rekey is
inherent to snapshotting); the committee is the top-N by stake, so "committee stake" ≠
"total bonded stake" (pre-existing committee-selection trust assumption, unchanged).

---

## Decision (cycle 2, historical): **NO-GO for enabling on a real chain.**

The transparent experience is **re-proven end-to-end on a live 4→5-node p2p network with zero
consensus divergence**, and **both previously-deferred proof cases now pass** (epoch-2
encrypt→decrypt after a rekey, and a validator JOIN). **Three of the four HIGH findings are
genuinely closed** — HIGH-1 from three independent live angles, HIGH-2/HIGH-4 by
operator-bound proof-of-possession + cross-operator uniqueness + operator-indexed self-id.

**But the re-audit found that HIGH-3 SURVIVES this cycle's fix.** The stake-capture fix
(`DecryptingSetMeetsStake`) was placed at the wrong layer — it is an **on-chain-only** gate on
the ON-CHAIN decrypt combine, while the thing that actually leaks the mempool is **off-chain**:
the count-based Shamir threshold `t = floor(n/2)+1` means a stake-**minority** holding a
seat-**majority** (≥ t seats) holds ≥ t real secret shares and **reconstructs the epoch key by
itself, off-chain, with no chain involvement** — decrypting the encrypted mempool early. That
is the exact front-running break the feature exists to prevent. It is demonstrated by three
passing audit-probe tests (§4).

`clean = false` (1 distinct HIGH survives → `AUDIT_CLEAN = NO`).
`builds = true`. `transparent proven = true`. `deferred proof cases pass = true`.

The remaining blocker is **not a redesign of the transparent mechanism** — it is a
**cryptographic-layer** change to HIGH-3 (stake-weighted secret sharing / stake-fraction
reconstruction threshold), spelled out exactly in §6.

---

## FIX CYCLE 2 — 2026-07-04 (3 of 4 HIGH truly fixed; HIGH-3 fix landed at the wrong layer)

`go build ./...` (evmd + root/`x/encmempool`) exits 0; `go test -tags test ./x/encmempool/...`
is green (including the new HIGH regression tests AND the new audit-probe tests that *prove
HIGH-3 is still exploitable*). Each HIGH carries a regression test verified to FAIL pre-fix.

### HIGH-1 (chain HALT on misconfig) — **FIXED (confirmed live, 3 angles).**
`veActive` (`evmd/dkg_voteext.go`) now couples to the consensus param via
`types.VoteExtEnabledAt(enableHeight, blockHeight)` = `enableHeight != 0 && height > enableHeight`
— **exactly mirroring `baseapp.ValidateVoteExtensions`**. No VE handler acts, and
`ProcessProposal` never self-certifies an un-validatable commit, while VE is inactive.
`MsgUpdateParams` additionally **rejects** enabling `DkgTransparent` unless VE is scheduled
(`vote_extensions_enable_height != 0`), so gov can never leave the two switches inconsistent.
- Regression: `TestReg_H1_VoteExtEnabledAtGate`, `TestReg_H1_UpdateParamsRejectsTransparentWithoutVE`
  (both verified to FAIL pre-fix by disabling the guard).
- Live: proven from three independent angles — (a) gov activation **rejected** when VE
  unscheduled; (b) a genesis-misconfig chain with transparent forced-on but VE off **does not
  halt** (falls back to the plain EVM-mempool path); (c) the enabled path works once VE is active.

### HIGH-2 + HIGH-4 (enc-key impersonation / no uniqueness / self-id overload) — **FIXED.**
`RecordEncPubKey` now requires an operator-bound **proof-of-possession**
(`dkg.SignEncKeyPoP` / `dkg.VerifyEncKeyPoP`, `x/encmempool/dkg/pop.go` — an ECDSA signature by
the enc private key over the operator string, so a key+PoP replayed under a *different* operator
fails) **and** enforces **cross-operator uniqueness** via a reverse index
(`types.EncKeyOwnerPrefix`, `keys.go:68`; rejects a key already bound to a different operator).
The node self-identifies by **OPERATOR** (`types.MemberIndexByOperator`, resolved from its
consensus address via `dkgnode.LoadConsAddress` + staking) instead of by an enc-key first-match.
PoP verification is panic-safe on adversarial bytes (fuzzed, `TestProbe_PoP_PanicSafeOnAdversarialBytes`).
- Regression: `TestReg_H2_EncKeyPoPAndUniqueness` (verified FAIL pre-fix), `TestReg_H4_SelfIdentifyByOperator`.

### HIGH-3 (count-majority threshold vs stake-ranked seats) — **NOT FIXED (fix is at the wrong layer).**
What shipped: each `RoundMember` carries a snapshotted stake `Weight` (excluded from
`MembersHash`), and `recoverSharedSecret` (`keeper/abci.go:381`) now rejects an
**on-chain** decrypting set that does not hold a strict stake majority
(`keeper.DecryptingSetMeetsStake`, `voteext.go:193`, overflow-safe `sdkmath.Int`).
- Regression `TestReg_H3_StakeMinoritySeatMajorityCannotDecrypt` PASSES — **but it only asserts
  the on-chain gate returns `false`.** It never checks that the same seats can reconstruct the
  key. **They can.** The Shamir threshold is still a member COUNT (`roundThreshold`,
  `dkg.go:350`), and the code comment (`dkg.go:349`) concedes *"t remains a member count because
  the underlying Shamir scheme is unweighted."* A seat-majority = a share-majority = an off-chain
  reconstruction. **HIGH-3 survives.** See §4 + §6.

### Med/low triage (carried from cycle 1 + this cycle)
FIXED / addressed inline:
- PoP verification is panic-safe in the deterministic consume path (parse errors → reject, no panic).
- Enc-key reverse (uniqueness) index is GC'd on key rotation — no stale owner entries accrue.
- `RoundMember.Weight` deliberately excluded from `MembersHash` (avoids stake-drift rekey flaps).
- On-chain stake gate is overflow-safe and a strict no-op on the legacy declared-member path.
- Idempotent re-announce short-circuits BEFORE PoP verification (hot path does no crypto).

DEFERRED (documented, non-blocking for the mechanism; re-confirm at enable time):
- **Injected blob is `Txs[0]`**, relying on the default runner's deterministic decode-fail (one
  wasted "failed tx" slot/block). Bounded + deterministic; a skip-runner is a higher halt-risk change.
- **Lenient `ProcessProposal`** (a proposer omitting the blob is accepted): a Byzantine proposer
  can stall DKG *progress* (not fork/halt). Accepted liveness tradeoff.
- **Remote-signer / KMS nodes**: self-identity is read from `config/priv_validator_key.json`; a
  node whose consensus key lives only in a remote signer cannot resolve its operator and simply
  does not participate (safe non-participation, never a halt). Follow-up: supply operator via flag.

---

## 1. Design — what "transparent" means and how it is wired

### The goal
A bonded validator that simply **runs the binary** becomes a DKG member automatically: **no
separate daemon**, **no account/fee setup**, **no manual enc-key registration**, **no declared
member list** (members are the bonded validator set itself).

### The three pillars

**Pillar 1 — In-node auto-participation via ABCI++ vote extensions.** The node attaches its DKG
contribution to its consensus pre-commit vote, so CometBFT signs and tags it with the node's
consensus identity — no tx, no account, no fee (`evmd/dkg_voteext.go`):

| Phase | Handler | What it does |
|-------|---------|--------------|
| `ExtendVote` | `dkgExtendVoteHandler` | Packs `{EncPubKey announcement + PoP, Feldman dealing, DLEQ-proved decryption shares}` into the precommit's `VoteExtension`. Node-local. |
| `VerifyVoteExtension` | `dkgVerifyVoteExtensionHandler` | Lenient structural check only; all crypto/membership/dedup is enforced deterministically on-chain later. |
| `PrepareProposal` | `wrapDkgPrepareProposal` | **Composes around** the EVM-mempool handler: reserves bytes, calls the inner handler, **prepends** the H-1 `ExtendedCommitInfo` as `Txs[0]` behind an inject marker. |
| `ProcessProposal` | `wrapDkgProcessProposal` | If `Txs[0]` carries the marker, self-certifies it with `baseapp.ValidateVoteExtensions` (every ext-sig verifies against its validator's consensus key AND the set carries ≥2/3 power), strips it, delegates the rest. **Gated by `veActive` (HIGH-1 fix).** |
| `PreBlock` | `consumeDkgVoteExtensions` → `keeper.ConsumeVoteExtensions` | Resolves each extension's consensus address → operator via staking and hands the pairs to the keeper's deterministic canonicalizing consume path. Replaces the `MsgDkgDeal` / `MsgSubmitDecryptionShare` tx paths. |

**Pillar 2 — Transparent key.** A secp256k1 ECIES key per member (consensus key is ed25519 —
wrong curve), minted with zero operator action (`x/encmempool/dkgnode/enckey.go`):
`LoadOrCreateEncKey` mints+persists to `<home>/dkg_enc_key.json` (0600) on first boot; the pubkey
is auto-announced idempotently **with an operator-bound PoP** (HIGH-2 fix). **Self-identity is
now by OPERATOR** (`LoadConsAddress` → staking → `MemberIndexByOperator`), no longer an enc-key
first-match (HIGH-4 fix).

**Pillar 3 — Members = bonded validators.** `TransparentMembers` derives the committee from the
bonded set: every bonded validator that announced a valid, unique enc key, capped to the top-N by
stake (`EffectiveMaxMembers`) to bound VE/block-data size. Chosen by (power desc, operator asc);
indices assigned by operator-address order so `MembersHash` is a pure function of committed state.

### Determinism contract (the #1 fork risk)
All determinism is confined to the **consume** half (`keeper.ConsumeVoteExtensions`), a pure
function of `(committed state, entries)`: entries stable-sorted by operator + first-wins deduped;
every write idempotent/first-wins; dealing/share validation mirrors the msg-server exactly; the
finalize + decrypt paths read only committed state; a last-resort `recover` converts any
data-dependent panic into a deterministic event. Order-independence is unit-tested; the live run
showed byte-identical app-hashes across all nodes.

---

## 2. What was built / changed this cycle (file map)

| File | Change this cycle |
|------|-------------------|
| `evmd/dkg_voteext.go` (+74) | `veActive` couples to `types.VoteExtEnabledAt` (HIGH-1); self-id resolved by operator. |
| `evmd/app.go` (+7) | Wiring for operator-resolved self-identity. |
| `x/encmempool/dkg/pop.go` (NEW, +76) | `SignEncKeyPoP` / `VerifyEncKeyPoP` — operator-bound, non-replayable enc-key proof-of-possession (HIGH-2). |
| `x/encmempool/dkgnode/enckey.go` (+39) | `LoadConsAddress`; `DeriveShare` unchanged. Self-id by operator, not enc-key match (HIGH-4). |
| `x/encmempool/keeper/voteext.go` (+101) | PoP verify + `EncKeyOwnerPrefix` uniqueness in `RecordEncPubKey`; `DecryptingSetMeetsStake` (HIGH-3 *on-chain gate — insufficient*). |
| `x/encmempool/keeper/abci.go` (+19) | `recoverSharedSecret` applies `DecryptingSetMeetsStake`; `errStakeMinority` (HIGH-3 on-chain gate). |
| `x/encmempool/keeper/dkg.go` (+7) | `RoundMember.Weight` snapshot; `roundThreshold` comment concedes count-based Shamir. |
| `x/encmempool/keeper/msg_server.go` (+16) | `MsgUpdateParams` rejects `DkgTransparent=true` unless VE scheduled (HIGH-1). |
| `x/encmempool/types/{keys,types,voteext}.go` | `EncKeyOwnerPrefix`, `MemberIndexByOperator`, `VoteExtEnabledAt`, `RoundMember.Weight`. |
| `x/encmempool/keeper/audit_transparent_h1_test.go` (NEW) | HIGH-1 regression. |
| `x/encmempool/keeper/audit_transparent_probe_test.go` (NEW) | HIGH regression suite + PoP fuzz + stake-gate determinism. |
| `x/encmempool/keeper/audit_h3_offchain_probe_test.go` (NEW, this report) | **Proves HIGH-3 survives** (off-chain reconstruction). |
| `x/encmempool/keeper/zz_audit_probe_test.go` (NEW, this report) | **Proves HIGH-3 survives** end-to-end via `dkgnode.DeriveShare` on real committed dealings. |

### Dormancy / kill-switch preserved
Every handler is a strict no-op unless `DkgEnabled && DkgTransparent` **and** CometBFT vote
extensions are active at this height. `DefaultParams` ships all three flags false; the default
binary is byte-behavior-identical to `17101a12`. All prior proven invariants intact (H1/H2
on-chain-DKG fixes, admission control, flood control, bounded state, in-flight decrypt safety,
`MembersHash` flap-avoidance).

---

## 3. Multi-node transparent re-proof (live 4→5-node p2p) — **worked, transparent, 0 divergence**

**Result: worked = true, transparent = true, diverged = false, both deferred cases pass.**

- **Transparent experience re-proved** — a validator participates by running the binary alone:
  vote extensions carried every node's enc-key+PoP announcement, Feldman dealing, and DLEQ
  decryption shares on its consensus precommit; the proposer injected the H-1 `ExtendedCommitInfo`;
  `ProcessProposal` self-certified it; `PreBlock` deterministically consumed it. No daemon, no
  account, no fee, no manual key, no declared list.
- **Consensus safety held perfectly** — app-hash samples **byte-identical across all nodes, ZERO
  divergence**, through both VE-DKG rounds, the rekey, and the JOIN. The #1 fork risk did not
  materialize.
- **HIGH-1 confirmed live from three angles** (see §fix-cycle): gov-activation rejected when VE
  unscheduled; genesis-misconfig (transparent forced-on + VE off) does **not** halt; enabled path
  works when VE active. This is the strongest of the four confirmations.
- **DEFERRED CASE 1 — epoch-2 encrypt→decrypt (post-rekey) — NOW PASSES.** After a rekey to
  epoch 2, a full encrypt→decrypt cycle produced byte-identical plaintext on all nodes, with
  decryption shares supplied entirely by vote extensions.
- **DEFERRED CASE 2 — validator JOIN — NOW PASSES.** A bonding validator (4→5) auto-joined the
  committee via the same `TransparentMembers` path and rekeyed with 0 divergence. (Cycle 1 had
  proven only the LEAVE direction, 4→3.)

### Honesty caveat on the live evidence (why the live run is NOT sufficient on its own)
The live 4→5 run is an **honest-path** proof: all nodes ran the honest release binary, registered
operator-bound unique keys, and the stake-weighted on-chain decrypt gate ran green. It confirms
the fixes **don't break the honest path** and that PoP/uniqueness/stake-weight are actually
populated and enforced in committed state. It does **not** exercise the adversarial negative
paths — a Byzantine node broadcasting a spoofed enc-key VE, or a Sybil coalition
**reconstructing off-chain** — because those require a patched/malicious binary the throwaway
isolation harness cannot produce with the honest binary. The authoritative negative-path evidence
is the regression + audit-probe test suite (§4). **For HIGH-3, that suite is exactly what exposes
the surviving break: the live run's green stake-gate is not evidence of safety.**

---

## 4. Re-audit — 11 findings; **HIGH-3 SURVIVES** → `AUDIT_CLEAN = NO`

The re-audit reproduced **one distinct HIGH (HIGH-3)** from three independent angles (3 of the 11
findings), plus the carried medium/low set consistent with cycle 1's triage. HIGH-1, HIGH-2, and
HIGH-4 are confirmed CLOSED (regression tests FAIL pre-fix, PASS now; HIGH-1 also live).

### HIGH-3 (survives) — stake-minority seat-majority reconstructs the epoch key OFF-CHAIN; the stake gate is at the wrong layer
- **Where:** `x/encmempool/keeper/dkg.go:350` (`roundThreshold` = `floor(n/2)+1`, still a member
  COUNT) + `x/encmempool/keeper/voteext.go:193` (`DecryptingSetMeetsStake` — an **on-chain-only**
  gate) + `x/encmempool/keeper/abci.go:381` (gate applied only inside `recoverSharedSecret`, the
  on-chain combine) + `x/encmempool/dkgnode/enckey.go:165` (`DeriveShare` hands each seat its real
  secret share Xᵢ).
- **Why the fix does not close it:** committee seats are stake-ranked top-N, but the *Shamir
  reconstruction threshold* is a seat **count**. A coalition holding ≥ t seats holds ≥ t real
  shares Xᵢ. Those shares are sufficient — **by the mathematics of the scheme** — to reconstruct
  the epoch secret and decrypt any ciphertext, **entirely off-chain**, before the chain reveals
  anything. The on-chain `DecryptingSetMeetsStake` gate only rejects the on-chain *combine*; it is
  irrelevant to an attacker who computes the plaintext on its own machines. So a stake-**minority**
  (e.g. 3/103, or 1800/4800) that is a seat-**majority** front-runs the encrypted mempool — the
  precise property the module exists to defend.
- **Proven exploitable (tests PASS):**
  - `TestProbe_H3_OffChainReconstructionBypassesStakeGate` — n=4, t=3 (the DEFAULT threshold used
    by the proven live run): 1 whale (100) + 3 dust (1 each); the 3 dust seats decrypt off-chain
    while the on-chain gate rejects them.
  - `TestProbe_H3_MirrorsShippedRegressionCommittee` — the **exact committee the shipped HIGH-3
    regression declares "fixed"** (n=12, t=7, 9 attacker seats @200 vs 3 whales @1000): the 9
    attacker shares reconstruct the key off-chain. The regression only checks
    `DecryptingSetMeetsStake==false`; it never checks reconstructability.
  - `TestProbe_H3_StakeMinorityOffChainCapture` — full keeper/DKG e2e: opens epoch 1 over a real
    transparent committee, finalizes with full QUAL, then a stake-minority seat-majority uses
    `dkgnode.DeriveShare` on the committed dealings + `dkg.RecoverVerified` to decrypt off-chain
    while `DecryptingSetMeetsStake` rejects the same set on-chain.

### Findings NOT reproduced (confirmed closed this cycle)
- HIGH-1 (halt on misconfig) — CLOSED (VE-coupled `veActive` + `MsgUpdateParams` guard; live ×3).
- HIGH-2 (enc-key impersonation / uniqueness) — CLOSED (operator-bound PoP + reverse-index uniqueness).
- HIGH-4 (self-identifier overload) — CLOSED (operator-indexed self-id).

---

## 5. Determinism / consensus-safety assessment (unchanged, still LOW risk)
- **Consume path** — deterministic by construction; order-independence unit-tested; live run 0
  divergence. **Risk: LOW.**
- **ExtendVote content** — node-local, DLEQ-verified on decrypt. **Risk: LOW.**
- **ProcessProposal `ValidateVoteExtensions`** — reads only consensus/committed data; a reject →
  new round, never a fork. Exercised by the live run. **Risk: LOW.**
- The HIGH-3 break is a **confidentiality / front-running** failure, **not** a
  liveness/consensus-safety failure — the chain stays live and deterministic; it just fails to
  keep the mempool sealed against a stake-minority seat-majority.

---

## 6. GO / NO-GO

### Verdict: **NO-GO to enable** (feature stays on its branch, dormant). One blocker remains: HIGH-3.

### THE EXACT REMAINING BLOCKER + FIX (next cycle)

**Blocker:** HIGH-3 stake-capture. The stake requirement is enforced as an **on-chain policy
gate** (`DecryptingSetMeetsStake`) while the actual capability to reconstruct the secret is
governed by the **cryptographic threshold**, which is still an unweighted seat COUNT
(`roundThreshold = floor(n/2)+1`, `dkg.go:350`). Off-chain reconstruction by a stake-minority
seat-majority bypasses the gate entirely (proven by the three `TestProbe_H3_*` tests).

**Root-cause fix — bake stake into the cryptography, not into an on-chain check:**
1. **Stake-weighted secret sharing.** Allocate each committee member a number of Shamir
   shares/evaluation points **proportional to its bonded stake** (with a bounded total-share
   budget S to keep VE/block-data size bounded), and set the reconstruction threshold **t as a
   stake-fraction of S** (a strict majority `> S/2`, or `> 2S/3` for a BFT bar). Then *any*
   coalition able to assemble t shares necessarily controls a stake-majority — so off-chain
   reconstruction requires stake-majority, and the on-chain gate and the off-chain capability
   finally agree. This touches `roundThreshold` (`dkg.go:350`), the dealing/share derivation
   (`dkgnode.DeriveShare`, `enckey.go:165`), the round-member share assignment, and
   `recoverSharedSecret`'s `need`. It is a change to the DKG's share layer — **not** to the
   transparent VE mechanism, which is proven and stays as-is.
   - *Alternative (weaker, brittler under Sybil):* gate committee ADMISSION so that a seat-majority
     always implies a stake-majority (e.g. equal-weight seats requiring equal bonded stake, or a
     high per-seat minimum-stake floor + a low `EffectiveMaxMembers`). This avoids weighted crypto
     but concentrates trust and is harder to reason about; prefer the weighted-sharing fix.
2. **Delete or demote `DecryptingSetMeetsStake` to defense-in-depth.** Once the threshold is
   stake-weighted, the on-chain gate is redundant; keep it only as a belt-and-suspenders check,
   not as the primary control. Update the misleading `dkg.go:349` comment and the HIGH-3
   regression to assert **off-chain non-reconstructability** (the `TestProbe_H3_*` probes must
   FLIP to failing-to-decrypt), not just the on-chain gate return value.
3. **Then:** fold in the carried medium/low findings, re-run the audit to `AUDIT_CLEAN = YES`, and
   re-run the 4→5-node harness (the deferred cases already pass this cycle). When the
   `TestProbe_H3_*` off-chain-capture tests can no longer decrypt AND the audit is clean, this
   flips to **GO to enable** (still gov-gated, still dormant-by-default).

### What is safe today
Merging this branch **without enabling** is safe: all handlers are no-ops under the default
params, the binary is byte-behavior-identical to `17101a12`, and both modules build green. The
NO-GO is strictly about **switching the feature on** on a real chain — and specifically about the
one surviving confidentiality break (HIGH-3).

---

## 7. Scorecard

| Item | State |
|------|-------|
| Builds (evmd + root modules) | ✅ exit 0 |
| Consume-path determinism (unit + order-independence) | ✅ |
| 4→5-node transparent experience (no daemon/account/fee/key/list) | ✅ re-proven |
| App-hash consensus safety across nodes | ✅ 0 divergence |
| Kill-switch (dormant→active→disable) | ✅ |
| HIGH-1 (halt on misconfig) | ✅ FIXED — live ×3 + regression |
| HIGH-2 (enc-key impersonation / uniqueness) | ✅ FIXED — PoP + reverse-index uniqueness |
| HIGH-4 (self-identifier overload) | ✅ FIXED — operator-indexed self-id |
| Deferred case 1: epoch-2 encrypt→decrypt (post-rekey) | ✅ PASSES |
| Deferred case 2: validator JOIN | ✅ PASSES |
| **HIGH-3 (stake-minority seat-majority capture)** | ❌ **SURVIVES** — off-chain reconstruction bypasses the on-chain-only gate (3 probe tests PASS) |
| Security audit | ❌ `AUDIT_CLEAN = NO` — 1 distinct HIGH (HIGH-3), 11 total |
| **Enable on a real chain** | ❌ **NO-GO** until HIGH-3 is fixed at the crypto layer (stake-weighted sharing) + re-audit clean |

*Author: Limonata. This branch is a large standalone consensus change; do not merge into a release.*
