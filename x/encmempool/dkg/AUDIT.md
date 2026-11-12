# Internal Cryptographic Audit — `x/encmempool/dkg`

> **STATUS: INTERNAL audit of an EXPERIMENTAL prototype. This report DOES NOT
> replace an independent third-party cryptography audit and MUST NOT, on its own,
> gate any mainnet deployment. See §7 (Limitations).**

- **Target:** `x/encmempool/dkg` (branch `limonata-dkg-poc`) — a joint-Feldman VSS
  Distributed Key Generation with a Chaum–Pedersen DLEQ for partial-decryption
  verification, producing a threshold key that is a drop-in for the trusted
  `x/encmempool/threshold` (`threshold.Setup`) → secp256k1 threshold ElGamal →
  AES-256-GCM.
- **Files audited:** `dkg.go`, `proof.go`, `dkg_test.go`, `cmd/dkgdemo/main.go`,
  and the `threshold.go` dependency it drops into.
- **Method:** adversarial audit — every suspected issue was turned into an executable
  probe ("reproduce or it doesn't count"), then a second pass adversarially
  re-verified each finding (severity, reachability, false-positive check).

---

## 1. Scope & threat model

The key produced here is used for **one** purpose: a threshold-ElGamal **decryption**
key for the anti-MEV encrypted mempool. The security goals in scope:

1. **Secrecy / threshold.** `msk = Σ_{i∈QUAL} s_i` is never assembled as a scalar
   anywhere; no party and no coalition of `< t` parties can decrypt; `≥ t` can.
2. **Robustness.** A dealer that deals a share inconsistent with its Feldman
   commitments is disqualified; an honest dealer cannot be framed; the run completes
   iff `|QUAL| ≥ t`.
3. **Verifiable decryption.** A keyper's partial `D_m = x_m·A` is checkable against
   the public `Y_m = x_m·G` (DLEQ) before it can poison a Lagrange combine.
4. **Drop-in correctness.** DKG output is byte-compatible with `threshold.Setup`.

**Explicitly out of scope** (and *documented as such* in README §3 / SECURITY.md — the
audit re-validated that these characterizations are accurate, not that they are fixed):

- **Key biasability** of plain single-round joint-Feldman (a rushing adversary steers
  `pub`). Claimed **benign for encryption, FATAL for signing** — re-validated below.
- **Constant-time.** All secret-scalar ops use variable-time `*NonConst` variants.
- **Networking / DoS / complaint-round game theory / message authentication.** Parties
  are in-memory structs; there is no transport, no equivocation model.
- **Enforcement wiring.** The live keeper (`keeper/abci.go`) still calls raw
  `threshold.Recover`, not `RecoverVerified`.

---

## 2. Methodology

Five auditors worked in parallel, one per axis — **secrecy**, **biasing / rogue-key /
complaint manipulation**, **proofs (DLEQ / Fiat–Shamir)**, **inputs (validation / DoS /
panics / encoding)**, and **math (Lagrange / scalar arithmetic / drop-in)** — plus a
**test-adequacy** pass that checked whether the committed regression tests actually
guard the properties they claim. Every candidate issue was reproduced with a Go probe
run as `go test ./x/encmempool/dkg/... -run <Probe> -v`. A separate adversarial pass
then re-derived each confirmed finding from an *independent* probe and challenged its
severity and reachability. Findings that survived are in §3; everything that was probed
and held is in §5.

---

## 3. Findings & dispositions

Two genuine correctness/security bugs and three defensive-hardening gaps were confirmed
and **FIXED** in this change; each has a non-vacuous regression test (verified to FAIL on
the pre-fix tree). Documented-acceptable caveats are **ACCEPTED** with a note.

| # | Severity | Title | Root cause | Status |
|---|----------|-------|------------|--------|
| F1 | Medium | Out-of-range complaint index frames a provably-honest dealer (liveness DoS) | `dkg.go` complaint loop never bounds `c.By` to the party set | **FIXED** |
| F2 | Medium | Replay of one partial under a `+2^32`-colliding index defeats `RecoverVerified`'s distinct-index invariant → silent wrong secret | Fiat–Shamir challenge omitted the keyper index **and** `RecoverVerified` deduped the full `uint64` while `scalarFromUint` reduces mod 2^32 | **FIXED** |
| F3 | Low | `t = 0` panics in the dealing round (`evalPoly` indexes `coeffs[-1]`) | DKG entry points did not validate `t ≥ 1` | **FIXED** |
| F4 | Low | `SharePubKey` panics on an empty commitment slice (`commitments[-1]`) | exported API had no length guard | **FIXED** |
| F5 | Low | `threshold.ParseShare` silently reduces a non-canonical (`≥ q`) / zero share | `SetBytes` overflow flag discarded | **FIXED** |
| F6 | Low/Info | Test-adequacy gaps (dup-index guard tested only for literal dups; no-msk check is structural; `|QUAL|<t` & no-framing untested) | committed tests narrower than the claimed properties | **ADDRESSED** (new regression tests) |
| A1 | Info | Key biasability documented only for `pub`; the whole coefficient vector (incl. top coeff → degree collapse) is adversary-influenced, blocked *only* by ECDLP | plain joint-Feldman | **ACCEPTED / doc note** |
| A2 | Info | `Result.Shares` bundles every keyper's secret share in one struct | non-networked PoC | **ACCEPTED** (integration footgun) |
| A3 | Info | Structural gate checks commitment-vector *length* but not *degree* (identity-topped poly slips into QUAL) | benign under ≥1 honest dealer | **ACCEPTED** |
| C1 | — | Key biasability is benign for encryption, FATAL for signing | documented | **ACCEPTED** (re-validated accurate) |
| C2 | — | Variable-time `*NonConst` ops leak via timing | documented | **ACCEPTED** |
| C3 | — | Networking / DoS / complaint game theory / msg-auth not modeled | documented | **ACCEPTED** |
| C4 | — | Enforcement wiring: keeper uses raw `threshold.Recover` | documented (README gap #4) | **ACCEPTED** (integration must route through `RecoverVerified`) |

### F1 — Complaint framing (MEDIUM, fixed)

`Finalize` validated a complaint with `VerifyShare(d.Commitments, c.By, d.Shares[c.By])`
and never bounded `c.By` to `[1,n]`. For an out-of-range `By`, `d.Shares[c.By]` is a
nil-map miss and `VerifyShare` returns false on the nil share, so `Finalize` conflated
"the dealer never dealt to `By`" with "the dealer dealt `By` a bad share" and
disqualified a **provably-honest** dealer. A single forged `Complaint{By: <out of range>,
Against: <honest dealer>}` evicts any honest dealer; enough of them drive `|QUAL| < t`
and abort the run — falsifying the documented *"an accuser cannot frame an honest
dealer"* guarantee (README §1 Round 3). Impact is liveness/integrity only (no secret
leak). **Fix:** bound `c.By` to the real party set (`isParty[c.By]`) before treating the
complaint as a fault proof; a bare `By ≥ 1` check is insufficient (`By = n+1` still
frames). **Regression:** `TestAuditFix_OutOfRangeComplaintCannotFrameHonestDealer`
(By ∈ {0,6,99,2^32,2^32+1,2^40} all ignored; escalation does not shrink QUAL) and
`TestAuditFix_LegitimateComplaintStillDisqualifies` (a genuine bad share is still
disqualified — the fix does not neuter the mechanism).

### F2 — Index-truncation replay defeats `RecoverVerified` (MEDIUM, fixed)

`scalarFromUint` reduces an index via `SetInt(uint32(v))`, so an index `i` and
`i + 2^32` map to the **same** evaluation point: `SharePubKey(V, i)` and
`SharePubKey(V, i + 2^32)` are byte-identical, and the old Fiat–Shamir challenge
`H(ctx, A, D, Y, T1, T2)` omitted the index — so **one** honest DLEQ proof verified at
**both** indices. `RecoverVerified` deduped on the full `uint64` index, so a replay of a
single honest partial under `{i, i + 2^32}` was counted as two distinct partials. The
degenerate Lagrange node (`InverseNonConst(0) = 0`) then silently zeroed terms and
`RecoverVerified` returned a **wrong** shared secret **with no error** — the exact silent,
unattributed DoS the function was written to prevent (README §1: *"rejects duplicate
indices"*, *"one malicious keyper can no longer silently corrupt a recovery"*). It is
**not** a confidentiality break: the recovered secret is wrong, so `< t` genuine keypers
still cannot decrypt (independently re-confirmed). **Fix (defense in depth):** (a) bind
the full `uint64` keyper index into the DLEQ challenge transcript, so a proof issued at
`i` no longer verifies at `i + 2^32`; and (b) reject any ingest index outside
`[1, 2^32)` in `RecoverVerified`, making the surviving index domain injective under the
mod-2^32 reduction (so the `seen[]` dedup on the full `uint64` again agrees with the
crypto). **Regression:** `TestAuditFix_TruncationReplayRejected` asserts the collision
still exists at the eval layer, that the honest proof is now rejected at the colliding
index, and that `RecoverVerified` errors (never silently decrypts) on
`{orig, replay@+2^32, other}` while an honest quorum still decrypts.

### F3 / F4 / F5 — panic & canonicality hardening (LOW, fixed)

- **F3:** `DealerRound`/`Finalize` now reject `t < 1` with a clean error (was a
  `coeffs[-1]` panic — a chain-halt class fault if `t` is mis-wired). Regression:
  `TestAuditFix_ThresholdZeroRejected`.
- **F4:** `SharePubKey` returns `nil` on an empty commitment slice instead of indexing
  `commitments[-1]`. Regression: `TestAuditFix_SharePubKeyEmptyNoPanic`.
- **F5:** `threshold.ParseShare` now honours the `SetBytes` overflow flag and rejects a
  zero scalar, so a stored share `≥ q` (or `= q`, which reduced to a zero share) is
  rejected as non-canonical rather than silently reduced. This only ever rejects a
  corrupt/non-canonical file; a real share always round-trips. Regression:
  `TestAuditFix_ParseShareRejectsNonCanonical`.

### F6 — test-adequacy (addressed)

The committed suite's duplicate-index guard (test `h`) was asserted only for literal
duplicates and did **not** catch the `+2^32` collision; the "no master secret" check
(test `c`) is a structural type-shape check, not a runtime behavioral assertion; and the
`|QUAL| < t` failure path and the no-framing property had no test. The new regression
tests cover the `+2^32` collision (F2), the framing property and its negative control
(F1), and the `t = 0`/empty-input/non-canonical paths (F3–F5). The structural
no-msk check is left as-is (the invariant genuinely holds in `Finalize`, which sums
commitment **points**; only the test's *coverage* was narrow) and is noted here.

---

## 4. What changed (fix summary)

| File | Change |
|------|--------|
| `dkg.go` | F1: `isParty[c.By]` guard in the complaint loop. F3: `t ≥ 1` guard in `DealerRound` and `Finalize`. F4: empty-slice guard in `SharePubKey`. |
| `proof.go` | F2: keyper index bound into `dleqChallenge` (prove + verify); `RecoverVerified` rejects indices outside `[1, 2^32)`. |
| `threshold.go` | F5: `ParseShare` honours the `SetBytes` overflow flag and rejects a zero share. |
| `audit_regression_test.go` | 6 new regression tests (one per fix + a legitimate-complaint control), all verified to FAIL on the pre-fix tree. |

No change touches the on-wire `DecryptShare` encoding, the 1-based evaluation domain, or
the compressed-point/KDF conventions — the drop-in compatibility with `threshold.Setup`
is preserved (`TestCompatibilityDropIn` and the `dkgdemo` transcript still pass).

---

## 5. Properties independently verified SOUND

Reproduced by probe and left unchanged:

- **Threshold secrecy.** `t-1` partials cannot decrypt (naive Lagrange yields the wrong
  shared secret; AES-GCM `Open` fails); `t` succeed. `msk` is information-theoretically
  hidden from `t-1` final shares (multiple degree-`t-1` polynomials fit the observed
  shares with different constant terms → different `pub`).
- **Observer + `t-1` valid partials still cannot decrypt.** The missing partial is a CDH
  gap on `(Y_j, A)` that public point ops do not bridge.
- **No master secret assembled.** `pub = Σ C_{i,0}` is summed from commitment **points**;
  the scalar `msk` is never formed; every share is consistent with the public commitments.
- **DLEQ soundness & non-malleability.** 20 000 simulated `(C,Z)` pairs against a wrong
  `D' ≠ x·A` were all rejected; reusing a proof against a wrong `D`, or negating `C`/`Z`,
  are rejected; the transcript binds `A`, `D`, `Y` (now also the index).
- **Deterministic-nonce fix is complete.** `deriveDLEQNonce` is deterministic and distinct
  across ciphertexts **and** across shares; the classic `(z1−z2)/(c1−c2)` extraction
  recovers the wrong scalar. The prior HIGH nonce-reuse bug is genuinely closed.
- **Feldman relation is binding.** For a fixed `(commitments, index)` exactly one scalar
  satisfies the check; no forged share, and an honest dealer cannot be framed by a bad
  share against its own commitments.
- **Rogue-key / key-cancellation is infeasible.** Publishing a cancelling commitment
  fails all honest Feldman checks (the discrete log of the cancelling term is unknown), so
  the rogue dealer is disqualified.
- **Biasability is benign for encryption.** A real rushing adversary can steer a byte of
  `pub`, but the biased key is still a sound `(t,n)` threshold key; the adversary's known
  `s_adv` is not `msk`; biasing reveals only the point `honestC0` (ECDLP), never the
  scalar, and does not help decrypt anyone else's ciphertext. Degree-collapse (the only
  sub-threshold path) requires the honest **scalar** sum, of which only the point is
  public — blocked by the same ECDLP barrier.
- **Drop-in math is correct.** `pub = (Σ_{i∈QUAL} s_i)·G`; shares are a genuine Shamir
  sharing of `msk` on the 1-indexed domain; independent big.Int Lagrange reconstructs
  `msk` for every ≥`t` subset (incl. non-contiguous QUAL); every `t`-subset decrypts and
  every `(t-1)`-subset fails; `ModNScalar` invariants (`Negate(0)=0`, `(N-1)+1=0`,
  `InverseNonConst(0)=0`, overflow flag) are as the code assumes.
- **No panic on malformed input** to `Finalize`, `VerifyDecryptShare`, `RecoverVerified`
  (nil / empty / short / over-long / bad-encoding points), and edge thresholds
  `(1,1),(3,1),(3,3),(5,5)` round-trip; `t>n` returns a clean `|QUAL|<t` error.

---

## 6. Residual risk register

The fixes above harden the primitives; the following remain and are what an **external**
audit and a production integration must still address:

| ID | Risk | Owner / mitigation |
|----|------|--------------------|
| R1 | **Key biasability** (rushing adversary steers `pub`) | ENCRYPTION-ONLY rule enforced by policy. **Never sign** with this key. A signing deployment MUST add the Pedersen (GJKR) commit-then-reveal round. |
| R2 | **Constant-time / side-channels** — `*NonConst` ops leak `share.Xi` via timing | Production keyper needs constant-time scalar mul / inversion. |
| R3 | **Networking / DoS / equivocation / message authentication** not modeled | Transport layer must sign complaints (bind `By` to the authenticated sender ∈ `[1,n]` — which also independently closes F1), handle timeouts/liveness, and prevent private-channel equivocation. |
| R4 | **Enforcement wiring** — the live keeper (`keeper/abci.go`) calls raw `threshold.Recover` without per-share DLEQ | Integration MUST route decryption through `RecoverVerified` carrying each partial's proof. |
| R5 | **Share distribution** — `Result.Shares` centralises all shares in the PoC (A2) | Production `Finalize` must be distributed so each node derives only its own `X_m`. |
| R6 | **Trusted secret storage** — `ParseShare` now rejects non-canonical shares but the storage path is still trusted | Keyper key management out of scope here. |

---

## 7. Limitations of this audit (read this)

- This is an **INTERNAL** review performed by the **same author-tooling that wrote the
  code**. It shares the author's blind spots and its threat model was self-selected. It is
  **not** an independent assessment.
- It does **not** replace an **independent third-party cryptography audit**, and it
  **must not, on its own, gate any mainnet deployment.**
- It covers the **prototype crypto in this package only.** It does **not** cover: the
  networking/consensus integration, the live keeper decrypt path, key management, the
  biasability boundary for any non-encryption use, or constant-time behaviour.
- Reproductions establish the *presence* of the behaviours reported; the *absence* of
  further issues is **not** proven. No formal verification, no machine-checked proofs, no
  hostile-network simulation was performed.

---

## 8. Verdict

For its **stated, narrow purpose — a threshold-ElGamal DECRYPTION key at the
proof-of-concept level — the core crypto is sound.** Secrecy, the threshold property,
Feldman binding, DLEQ soundness, the deterministic-nonce fix, and drop-in correctness all
hold under adversarial probing. The two genuine bugs found (complaint framing F1;
index-truncation replay F2) were **availability/integrity** defects, not confidentiality
breaks, and are now **fixed with non-vacuous regression tests**; three low-severity
panic/canonicality gaps are also fixed. The documented caveats (biasability,
constant-time, networking) were re-validated as **accurately characterized** and remain
**accepted, not fixed**, by design.

**This does not clear the package for mainnet.** Before any production use, an external
cryptographic audit must still cover R1–R6 above — in particular the biasability boundary
(a Pedersen round if signing is ever contemplated), constant-time hardening, the
networking/complaint adversary with authenticated transport, and the enforcement wiring
into the live keeper.
