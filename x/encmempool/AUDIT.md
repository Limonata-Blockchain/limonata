# x/encmempool — Internal Security Audit

**Module:** `x/encmempool` (anti-MEV: commit-reveal + opt-in threshold encryption)
**Branch:** `limonata-encmempool-audit`
**Type:** INTERNAL, adversarial, probe-driven ("reproduce or it doesn't count")
**Scope of code that GOES LIVE:** the **commit-reveal** mechanism activates on the
live testnet at **block 766558** and is the mainnet-launch anti-MEV path. The
**threshold** mechanism is **opt-in and OFF by default** (`EncEnabled=false`), inert
until a governance action turns it on.

> **BOTTOM LINE FOR THE 766558 ACTIVATION:** the commit-reveal path that ships at
> block 766558 has **no confirmed critical or high finding**. Every critical/high in
> this report lives **only** on the opt-in threshold path (gated by `EncEnabled`,
> which is `false`), and the one confirmed **critical** (a nonce-length chain halt)
> has been **fixed** in this branch. The commit-reveal path does carry medium/low
> **design limitations** (documented below) — most importantly, commit-reveal is a
> *delay/ordering* primitive, **not** front-running-proof encryption.

---

## 1. Scope

In scope (the code that ships / can be activated):

| Area | Files |
| --- | --- |
| Commit-reveal | `keeper/msg_server.go` (CommitTx/RevealTx), `keeper/abci.go` (BeginBlock execute + GC) |
| Threshold path | `keeper/msg_server.go` (SubmitEncrypted/SubmitDecryptionShare), `keeper/abci.go` (decryptMatured) |
| Threshold ElGamal primitive | `threshold/threshold.go` (Setup/Encrypt/ComputeShare/Recover/Decrypt, secp256k1 + AES-256-GCM) |
| Params / validation / genesis | `types/types.go`, `keeper/keeper.go`, `keeper/genesis.go` |

**Out of scope:** the `x/encmempool/dkg` package (audited separately — see
`dkg/AUDIT.md`). This report references its `RecoverVerified`/DLEQ primitive because
the threshold decrypt path *should* consume it but currently does not.

## 2. Threat model

Actors: (a) an ordinary account submitting commits/reveals/ciphertexts; (b) a
searcher/MEV bot observing mempool + block events; (c) a governance-authorized
**keyper** (only relevant once `EncEnabled=true`); (d) a block proposer. Trust
assumptions: the SDK ante (`(cosmos.msg.v1.signer)`) authenticates message signers;
validators run identical binaries; keypers (if enabled) are trusted for
availability but **not** for honesty of individual decryption shares.

**Primary security goals audited:**
1. **Consensus safety (paramount):** no path in BeginBlock/msg_server may produce a
   different result on different validators (map-iteration order, non-canonical
   decode, or a panic on one node) — any such path is a **chain-halt/fork = critical**.
2. **Anti-MEV efficacy:** ordering is fixed before intent is readable; a single
   party cannot front-run or censor at will.
3. **State soundness:** bounded state; no orphan/leak; no double-execution.

## 3. Method — six adversarial passes, every finding reproduced

Six focused passes, each writing Go probes against the module's keeper test harness
(`keeper/threshold_e2e_test.go`) or the threshold package, attempting the attack and
observing the real result:

1. **commit-reveal** — binding, salt, replay, ordering, window edges
2. **thresholdshare** — the `Recover` vs `RecoverVerified` gap (the KNOWN SUSPECT)
3. **consensus** — BeginBlock determinism & panic-safety (the central deliverable)
4. **mev** — front-running / free-option / ordering fairness
5. **threshold ElGamal primitive** — point validation, infinity, KDF, canonicality
6. **dos** — floods, unbounded loops, state leaks, size bounds

The consensus-safety lens ("can this fork or halt?") was applied to every finding.
The scratch probes were removed after verification; the surviving **regression
tests** (`*/audit_regression_test.go`) lock in each fix and were confirmed to FAIL
against the pre-fix source.

## 4. Findings

Severity is the post-verification severity. **Path** says whether the finding can
affect the **commit-reveal** launch (block 766558 + mainnet) or **only** the opt-in
**threshold** path. **Status:** `FIXED` in this branch, or `DOCUMENTED` (accepted
risk / design limitation with a stated remediation-before-enablement).

### 4.1 Threshold path — critical/high (all latent behind `EncEnabled=false`)

| # | Sev | Finding | Location | Path | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | **CRITICAL** | GCM nonce length != 12 makes `gcm.Open` PANIC in BeginBlock over deterministic state → **uniform chain halt** (incl. empty nonce; ingress unvalidated) | `threshold/threshold.go` Decrypt; `keeper/abci.go:94`; `keeper/msg_server.go` SubmitEncrypted | threshold-only | **FIXED** |
| T2 | MEDIUM (was high) | `Recover` is an **unauthenticated** Lagrange combine (no DLEQ, no `D_i==x_i*A` check). One authorized keyper's on-curve-but-wrong `D` in the sorted first-`t` prefix **deterministically censors** a targeted ciphertext despite an honest quorum, un-attributably (EncTx GC'd on failure). Deterministic ⇒ **censorship/liveness, NOT a halt**. | `threshold/threshold.go:167-194`; `keeper/abci.go:88-94,114-116`; `keeper/msg_server.go:127` | threshold-only | **DOCUMENTED** (blocker before enablement) |
| T3 | LOW (was medium) | Under-quorum EncTx is GC'd at its decrypt height and permanently dropped (no park/retry) | `keeper/abci.go:109-116` | threshold-only | **DOCUMENTED** (design tradeoff) |
| T4 | LOW | Last-write-wins on shares: a keyper can overwrite its own good share with garbage at T-1 to flip a ciphertext to censored | `keeper/msg_server.go:131`, `keeper/keeper.go:126-128` | threshold-only | **DOCUMENTED** (subsumed by the T2 DLEQ fix) |
| T5 | LOW (was medium) | Threshold params entirely unvalidated: `EncEnabled=true` with `DecryptDelay=0` **or** `Threshold=0` ⇒ permanent, per-user, unbounded EncTx state leak on enablement | `types/types.go` Validate; `keeper/abci.go:68`; `keeper/keeper.go:112-120` | threshold-only (validation surface) | **FIXED** |

### 4.2 Commit-reveal path (LIVE at 766558) — medium/low/info

| # | Sev | Finding | Location | Path | Status |
| --- | --- | --- | --- | --- | --- |
| C1 | MEDIUM | Commit flood → **ungated O(N) BeginBlock GC re-scan every block** (amplification up to `MaxRevealWindow`); no per-sender/per-block cap, no fee (keeper has no bank/fee keeper). Deterministic ⇒ uniform slowdown, **not a fork/halt**; state stays bounded. On this block-time-sensitive chain, sustained flooding is a real liveness-degradation griefing vector. | `keeper/abci.go:52-63`; `keeper/msg_server.go:27-45` | **commit-reveal (LIVE)** | **DOCUMENTED** (needs a param/product decision — see §6) |
| C2 | MEDIUM | **Commit-reveal gives NO front-running resistance for `reveal_tx`**: the plaintext is public a full block before its ordering event. This is the module's own documented caveat (`abci.go:20-24`), but it is load-bearing for any integration that executes `reveal_tx`. | `keeper/msg_server.go:73`; `keeper/abci.go:35-49` | **commit-reveal (LIVE)** | **DOCUMENTED** (by-design limitation) |
| C3 | MEDIUM | Bond-less **free option**: commit-many/reveal-one and withhold-after-observe let an attacker reserve priority slots and abandon them for free (no bond/fee/penalty on commit). | `keeper/msg_server.go:27-45`; `keeper/abci.go:52-63` | **commit-reveal (LIVE)** | **DOCUMENTED** (by-design limitation) |
| C4 | LOW | Commitment is non-binding under byte-shifting: `sha256(reveal_tx‖salt)` has no length delimiter, so a different `(reveal_tx,salt)` split matches. No on-chain impact today (execute emits events only); matters for any executor of `reveal_tx`. | `keeper/msg_server.go:68` | commit-reveal | **DOCUMENTED** |
| C5 | LOW | No minimum salt entropy: empty/low-entropy salt makes the public commit hash brute-forceable before reveal. | `keeper/msg_server.go:51` | commit-reveal | **DOCUMENTED** |
| C6 | LOW | Commit-copy / payload replay: attacker duplicates a victim's commit hash and re-reveals the victim's payload under its own identity after the victim reveals. | `keeper/msg_server.go:51` | commit-reveal | **DOCUMENTED** |
| C7 | LOW | Same-height execution ordering is **address-lexicographic (grindable)**, not FIFO submission order — a vanity low-sorting address wins ties. Deterministic (proposer cannot reorder). | `keeper/keeper.go:206`; `keeper/abci.go:29-49` | commit-reveal | **DOCUMENTED** |
| C8 | INFO | `Validate` permits `MaxRevealWindow == RevealDelay` (a one-block reveal window); a single censored/missed block forces a recommit. Not triggered by launch defaults (delay=1, window=100). | `types/types.go` | commit-reveal | **DOCUMENTED** |
| C9 | INFO | Maturity-gate uint64 addition (`CommitHeight+RevealDelay`) has no overflow guard; only reachable via a pathological governance `RevealDelay`. Deterministic on every node ⇒ no fork; never panics. | `keeper/abci.go:36,55` | commit-reveal | **DOCUMENTED** |

> **The only confirmed finding that touches the 766558 launch and is above LOW is
> C1 (commit-flood liveness griefing, MEDIUM) — a bounded, deterministic slowdown,
> not a halt/fork.** C2/C3 are anti-MEV *efficacy* limitations of a delay/ordering
> primitive (by design; the threshold path is what actually hides intent).

## 5. Fixes applied in this branch

Minimal, targeted changes to audited source (67 lines across 3 files); each has a
regression test that fails pre-fix and passes post-fix.

### 5.1 CRITICAL T1 — nonce-length chain halt (FIXED)

Two-layer fix (ingress + primitive backstop):

- **`threshold/threshold.go`** — added `const NonceSize = 12` and a guard at the top
  of `Decrypt`: a nonce of any other length returns a normal `error` instead of
  reaching `gcm.Open` (which panics on len != 12). `decryptMatured` already treats a
  returned error as a graceful `encmempool_decrypt_failed`, so the halt becomes a
  no-op non-event. This backstop protects **any** caller.
- **`keeper/msg_server.go`** — `SubmitEncrypted` now rejects `len(Nonce) != NonceSize`
  at ingress, so a malformed ciphertext never even enters state.

Regressions: `keeper/audit_regression_test.go::TestRegression_NonceLengthNoHalt`
(drives BeginBlock with nonce lengths {0,1,11,13,16,24} + an honest quorum — no
panic, `decrypt_failed` emitted) and `::TestRegression_SubmitEncryptedRejectsBadNonce`
(ingress rejects, valid 12-byte nonce accepted); plus
`threshold/audit_regression_test.go::TestRegression_DecryptNonceLengthNoPanic`.

### 5.2 T5 — threshold-param validation gap (FIXED)

- **`types/types.go`** — moved validation into `Params.Validate()` (called by
  `GenesisState.Validate()` and thus by `ValidateGenesis`). When `EncEnabled=true` it
  now requires `DecryptDelay >= 1`, `Threshold >= 1`, `Threshold <= len(Keypers)`,
  a non-empty `ThresholdPub`, and distinct non-empty keyper addresses. When
  `EncEnabled=false` (the launch/default config) the threshold checks are a no-op.
  This makes the genesis/upgrade that flips the switch reject the exact configs that
  cause the permanent EncTx leak.

Regression: `types/audit_regression_test.go::TestRegression_ValidateRejectsBrokenThresholdParams`.

### 5.3 Not changed (deliberate) — see residual risk §6

- **T2 (RecoverVerified/DLEQ enforcement)** is **not** wired in this branch. The
  correct fix is a *feature*, not a patch: keypers must submit a DLEQ proof with each
  share (a new proto field), the keeper must store the DKG public commitments, and
  the decrypt path must call `dkg.RecoverVerified` with good-share selection. That is
  out of scope for a minimal bug-fix and is **not reachable at launch** (threshold
  path off). It is recorded as a hard blocker before `EncEnabled` is ever set true.
- **No blanket `recover()` in BeginBlock.** The audit exhaustively proved the nonce
  length was the *only* panic vector in the decrypt path (Recover/Decrypt are
  panic-safe on off-curve, nil, duplicate-index, and point-at-infinity inputs). Fixing
  the root cause at the panic site is preferred over a broad `recover()`, which in
  consensus code can mask future non-determinism (turning a clean halt into a fork).
- **C1 commit-flood cap** is a param/product decision (cap value or fee/bond), not an
  arbitrary constant to bake into a consensus binary two days before activation — see §6.

## 6. Residual-risk register

| Risk | Path | Live at 766558? | Recommendation |
| --- | --- | --- | --- |
| **C1** commit-flood liveness griefing (unmetered O(backlog) GC/block) | commit-reveal | **YES** | Add a per-sender and/or per-block commit cap, or a small commit fee/bond (also mitigates C3), or amortize/meter the GC scan. Pick the cap with product input; deterministic and bounded today, so not a blocker, but the highest-value live hardening. |
| **T2** unauthenticated threshold combine (censorship) | threshold | No (off) | **Before `EncEnabled=true`:** route decrypt through `dkg.RecoverVerified` with per-share DLEQ + good-share selection; do not GC the EncTx on a *combine* failure. Also add on-curve `D` validation at ingress (msg_server). |
| **T3/T4** under-quorum drop / share retract | threshold | No (off) | Fixed largely by T2's DLEQ (bad shares rejected at ingress; good shares selected). Consider append-only shares and a bounded re-attempt window. |
| **C2/C3** commit-reveal is not front-running-proof; free option | commit-reveal | **YES** | Do **not** advertise commit-reveal as MEV-*proof*. It is a delay/ordering primitive. Real hiding requires the threshold path (≥ t independent keypers). Optionally add a commit bond to blunt the free option. |
| **C4–C9** binding/salt/replay/ordering/window/overflow edges | commit-reveal | YES | Length-prefix the commit hash, enforce a min-salt at reveal, order by `(height, global-seq)` if FIFO is intended, require `window >= delay + margin`, saturating maturity arithmetic. All low/info; safe to schedule. |

## 7. Verified-sound properties (do NOT regress these)

**Consensus safety (the central deliverable):**
- BeginBlock reveal execution is deterministic: pending reveals are collected into a
  slice via a **sorted store iterator** (big-endian `commitHeight‖sender‖seq`), then
  executed collect-then-mutate — **no Go-map iteration anywhere in `abci.go`**.
  Insertion/proposer order cannot change the result.
- The threshold decrypt path is deterministic: `CollectShares` is a sorted store
  iterator (not a map), `shares[:t]` is the sorted-key prefix, `threshold.Recover`
  output is byte-identical across runs, and GC is unconditional. This **refutes the
  "or worse ⇒ CONSENSUS HALT"** half of the KNOWN SUSPECT: the `Recover` gap is
  **censorship/liveness, deterministic, NOT a fork/halt**.
- No BeginBlocker `recover()` in the SDK path — which is *why* the nonce panic was a
  genuine halt (now fixed) rather than a caught error.

**Cryptographic primitive:**
- AES-256-GCM **fails closed**: a corrupted recovered key yields an auth error, never
  a forged/attacker-chosen plaintext. A malicious keyper can DENY decryption but
  cannot make the chain decrypt to a value of its choosing.
- `Recover`/`Decrypt` are **panic-safe** on malformed input: off-curve/nil/short `D`
  ⇒ `ParsePubKey` error; duplicate index ⇒ skipped (no zero-inverse); point at
  infinity (crafted or direct `Z=0`) ⇒ deterministic garbage key ⇒ GCM auth error.
- Shamir/Lagrange are correct and 1-indexed; every `t`-subset reconstructs `f(0)`,
  no `t-1` subset does. KDF uses a fresh ephemeral per Encrypt (no GCM nonce reuse).
- `ParseShare` canonicality fix verified: rejects `xi >= q`, `xi == 0`, wrong length,
  `index < 1`.

**Commit-reveal mechanism:**
- Reveal-delay gate is exact (`cur >= commitHeight + delay`, no off-by-one).
- No stale/past-window commit executes once GC'd; double-reveal is idempotent and
  executes **exactly once** (commit+pending deleted on execute).
- `seq` is a single global monotonic counter the caller cannot choose or collide;
  `(height,sender,seq)` keys are collision-free.
- A non-committer cannot reveal a victim's commit (`GetCommit` is keyed by sender;
  the real cross-sender guarantee is the SDK signer binding).
- Malformed commits (hash length != 32) are rejected before storage.

**Ingress authorization (threshold):** `SubmitDecryptionShare` rejects non-keypers
and index mismatches, so no non-keyper share and no duplicate-index share can reach
`Recover` via the message path.

## 8. Limitations of this audit (READ THIS)

- This is an **INTERNAL** audit by the project's own tooling. It **does NOT replace an
  external cryptography and consensus audit**, and **does not by itself clear the
  module for mainnet.**
- Reproductions are Go tests against an in-memory keeper harness, not a live
  multi-validator network under adversarial load. Determinism claims are established
  by construction + repeated in-process runs, **not** by cross-client differential
  testing.
- The threshold ElGamal scheme is a **prototype** with a **trusted Shamir setup**
  (the DKG package is a separate, also-internally-audited experiment). Even with T2
  fixed, the confidentiality/liveness guarantees of the threshold path depend on the
  keyper set and have not been externally reviewed.
- The commit-reveal path is a **delay/ordering primitive, not encryption**; its
  anti-MEV strength is limited by C2/C3 above and by whatever executor (if any) is
  later wired to `reveal_tx`. In this branch "execute" only emits an ordering event.
- No economic/game-theoretic analysis of the free-option (C3) or ordering-grinding
  (C7) incentives beyond reproducing the mechanism.

## 9. What ships at block 766558

- **Active:** commit-reveal (`CommitTx`/`RevealTx` + BeginBlock execute/GC).
- **Inert:** threshold path (`EncEnabled=false` in `DefaultParams`; both threshold
  msg handlers reject; `decryptMatured` is skipped).
- **Confirmed critical/high on the active path:** **none.** The nonce-length halt
  (T1, fixed) and the `Recover` censorship gap (T2, documented) are threshold-only.
- **Live residual to weigh:** C1 (commit-flood liveness griefing, medium, bounded &
  deterministic) and the C2/C3 anti-MEV *efficacy* limits inherent to a
  delay/ordering primitive.

_Regression tests: `x/encmempool/{keeper,threshold,types}/audit_regression_test.go`._
