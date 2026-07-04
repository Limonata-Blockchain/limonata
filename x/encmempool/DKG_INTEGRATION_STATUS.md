# x/encmempool on-chain validator DKG — integration status

**Date:** 2026-07-03
**Branch:** `limonata-dkg-integration` (HEAD `1456bd52`)
**Target:** conditional merge into `limonata-v030-release`
**Decision:** **NO-GO. Not merged into v0.3.0.**
**Evidence gate:** **NOT PASSED** (2 unresolved HIGH audit findings; multi-node deploy verdict is conditional, not unconditional).

This document is the honest, evidence-based record of the hardening pass, the real
multi-node proof, the re-audit, and the merge decision. It supersedes the informal
single-node PoC result.

---

## TL;DR

The DKG integration is **genuinely good engineering that is not yet safe to ship to 14
independent validators.** The determinism held perfectly across independent nodes, the
self-healing auto-retry works, and the real-time daemon fixed the original deal-window
race. But an adversarial re-audit found **two HIGH-severity defects that are reachable by
a single Byzantine validator**, and the multi-node test did **not** cleanly prove the one
scenario that 14 equal-power validators will actually exercise (a rekey concurrent with a
>2/3 validator-set rotation). Both HIGH findings are reproduced by passing probe tests in
the tree. Shipping this into v0.3.0 now would put a validator-triggerable liveness DoS
into a release.

**Merge is gated on fixing the two HIGH findings and re-running the equal-power rekey
proof — not on more caution.**

---

## What was hardened (and it works)

Committed on `limonata-dkg-integration` as `Limonata <noreply@limonata.xyz>`
(commit `1456bd52`, no Claude attribution). `go build ./cmd/evmd` => exit 0;
`go vet` clean; all module tests pass.

1. **Self-healing auto-retry (PRIORITY 1).** `keeper/endblock.go` `EndBlockDKG` now marks
   a round that finalizes with `|QUAL| < t` (or times out with too few deals) as `Failed`
   and automatically opens a fresh round (new epoch, reset deadlines, incremented
   `Attempt`) after a bounded backoff (`DkgRetryBackoff`, >= 1 block enforced). A single
   timing hiccup or transient member outage can no longer wedge the feature permanently.
   Membership change takes priority over retry. Tests: `TestOnChainDKG_AutoRetryOnFailedRound`,
   `TestOnChainDKG_RetryPurgesStaleDeals`.

2. **Real-time daemon + realistic windows (PRIORITY 2).** The dkg daemon
   (`evmd/cmd/evmd/cmd/dkg.go`) was refactored from a poll-lookback per-block scan (which
   fell behind the deal window in the single-node PoC — original gap #1) to a websocket
   `NewBlock` subscription that reacts the instant a round opens, with a periodic ticker as
   a self-healing fallback. Default windows resized for a ~2s-block p2p net:
   `DkgDealWindow` 5->20, `DkgComplaintWindow` 3->10, `DkgRetryBackoff`=5, `DkgMaxAttempts`=8
   (all governance-tunable).

3. **Determinism audited + locked (PRIORITY 3).** EndBlock finalize + BeginBlock decrypt
   are byte-identical across nodes: sorted store-key iteration, Go maps used only for
   lookup/dedup, QUAL built in sorted order, no wall-clock, no randomness. Test:
   `TestOnChainDKG_FinalizeDeterministic` (two keepers, reversed insertion order, identical
   Pub / PublicCommitments / QUAL / Threshold).

4. **Ingress + BeginBlock consensus-safety hardening** folded in: reject wrong-length GCM
   nonce at submit; recover-guard the decrypt path so a malformed permissionless ciphertext
   cannot halt consensus.

---

## Multi-node proof (real p2p, independent nodes)

**Result: worked, rough, no divergence — but deploy is CONDITIONAL.**

Genuinely proven on a real 4-node p2p network (independent nodes, independent daemons on
independent RPCs/websockets):

- All 4 nodes independently computed **byte-identical `ThresholdPub`s and byte-identical
  app hashes** through a first round, two rekeys, and two forced round failures — **never a
  fork or divergence.**
- The real-time daemon landed all 4 deals inside the deal window, so **epoch 1 finalized on
  the FIRST attempt** — the original gap #1 failure did not recur.
- The self-healing auto-retry **recovered a sub-threshold round with no manual
  intervention** (epochs reopened attempt 1->2->3 until the crashed daemon returned and it
  converged).
- Encrypt->decrypt round-tripped the exact plaintext identically on every node via the
  DLEQ-verified path.

**Three reasons it is NOT unconditionally production-ready for 14 equal validators:**

1. **Rekey touches base-layer accounting and CAN halt the chain if misconfigured.** A
   deterministic all-node halt was hit from `x/distribution` when `unbonding_time` was
   pathologically short. It is not the DKG code and won't occur with a normal
   `unbonding_time`, but it proves member-set changes must be validated against
   distribution/slashing behavior for exiting validators before mainnet.
2. **The clean rekey proof used a DOMINANT node0 (>2/3 power)** to sidestep the small-set
   quorum knife-edge. Equal-power 4-way block production was demonstrated separately, but a
   rekey **under equal power with the member-change round running concurrently with a real
   >2/3 validator-set transition** — exactly what 14 equal validators do — was **not**
   cleanly demonstrated. This must be re-run before trusting it at 14 nodes.
3. Gaps #4 (EVM re-injection) and #5 (enc-key derivation) are untouched by design — see
   below.

---

## Re-audit findings

13 findings total. **2 HIGH, 0 CRITICAL.** Both HIGH findings are reproduced by passing
probe tests in `x/encmempool/keeper/` (`dkg_probe_test.go`, `dkg_probe2_test.go`,
`dkg_soundness_probe_test.go`) — i.e. they are demonstrated, not hypothetical.

### HIGH-1 — Malformed enc-share `A` is accepted at ingress and is structurally uncomplainable (validator-triggerable keyless-liveness DoS)

- **Where:** `keeper/msg_server.go:267` (DkgDeal enc-share validation only checks
  `len(A)!=0`, never that `A` parses as a compressed secp256k1 point) →
  `dkg/onchain.go:235` / `dkg/proof.go:82` (`VerifyJustifiedComplaint` →
  `VerifyDecryptShare` calls `parsePoint(A)` FIRST and returns false on a malformed point)
  → `dkg/onchain.go:87` (`FinalizePublic` keeps the dealer in QUAL — it only checks
  commitments) → `keeper/endblock.go:85` (no retry once the round is Active).
- **Attack:** one Byzantine validator publishes VALID Feldman commitments (passes the QUAL
  gate) but seals every other member an enc-share whose `A` is a non-empty but invalid
  point. Victims cannot derive their share (ComputeShare parses `A`) **and cannot complain**
  (the complaint-verification path parses `A` first and rejects the complaint as a framing
  attempt). The dealer stays in QUAL, poisoning every honest member's final share, while the
  round finalizes Active with no auto-retry. **One malicious member => permanent keyless
  liveness DoS for the epoch, with no on-chain recovery** until an unrelated member-set
  change.
- **Probe:** `TestProbe_MalformedEncShareA_Uncomplainable`,
  `TestProbe_MalformedEncShareA_BreaksDecryption`,
  `TestProbe_MalformedEncShareA_CryptoRootCause` (all passing = defect present).
- **Fix direction:** validate `A` (and every enc-share field) as a well-formed compressed
  point at DkgDeal ingress, so a malformed dealing is rejected before it can enter QUAL;
  OR make the complaint path able to justify-disqualify a structurally-unopenable share.

### HIGH-2 — Unbounded `DkgRound` state growth under a sustained sub-quorum

- **Where:** `keeper/endblock.go:85-107` (retry branch never hard-stops — past
  `DkgMaxAttempts` it emits `encmempool_dkg_stalled` but KEEPS reopening a new epoch) +
  `keeper/dkg.go:31,89-108` (`purgeRoundData` deletes deal/complaint keys but
  **deliberately retains the per-epoch `DkgRound` record** "for history/telemetry").
- **Consequence:** while fewer than `t` members are live, the EndBlocker opens a new epoch
  every `DkgRetryBackoff` blocks forever, and each leaves a permanent `DkgRound` record
  (which carries the full member list + enc keys). At 2s blocks / backoff 5 that is one
  retained record every ~10s of outage — unbounded, griefable state bloat.
- **Fix direction:** cap retained history (ring buffer of the last N failed rounds) or GC
  the `DkgRound` record on retry, and/or apply a real backoff ceiling.

### The other 11 (medium/low)

Not merge-blocking on their own but should be triaged alongside the HIGH fixes before the
feature is enabled in production.

---

## Deferred gaps (documented, not regressions)

- **Gap #4 — EVM re-injection.** Decrypted plaintext is still emitted as an EVENT, not
  re-injected into x/vm execution. Documented in `keeper/abci.go`. This is a
  threshold-decryption / anti-MEV delay primitive, not yet end-to-end encrypted EVM
  execution.
- **Gap #5 — member enc-key derivation.** Member enc keys are genesis-declared, not derived
  from validator keys. Consensus keys are ed25519 (wrong curve for the secp256k1 ECIES);
  derivation needs the operator account's eth_secp256k1 pubkey + an AccountKeeper wiring.
  Documented in `types/types.go`.

---

## Build / test evidence

- `cd evmd && go build -o <scratch> ./cmd/evmd` => **exit 0**
- `go test ./x/encmempool/dkg/` => **ok**
- `go test ./x/encmempool/threshold/` => **ok**
- `go test ./x/encmempool/keeper/` => **ok** (includes the auto-retry/determinism tests and
  the HIGH-finding probe tests)
- Live chain (pre-existing, pid on 26657/8545) never touched, still advancing during this
  work (711790+). No throwaway chain started; no new listeners created.

---

## Safe-default note

`DefaultParams` ships `DkgEnabled: false` (`types/types.go:179`). Even if the integration
source were present in a binary, the DKG state machine, daemon message handlers, and the new
EndBlocker are all gated behind `DkgEnabled` and are inert until governance flips it on with
a declared `DkgMembers` set. That is the correct posture — but it is not a substitute for
fixing HIGH-1 before the feature is ever enabled on a chain with untrusted validators.

---

## Go / No-Go

**NO-GO for v0.3.0 right now.** The gate did not pass: two HIGH findings reachable by a
single Byzantine validator, and the one multi-node scenario that matches the 14-equal-
validator production config was not cleanly proven.

### Merge checklist (what must be true to flip this to GO)

1. Fix **HIGH-1** (validate enc-share `A`/fields as well-formed points at DkgDeal ingress,
   or make a structurally-unopenable share justify-disqualifiable) — and keep the probe test
   as a passing regression that now asserts the dealing is rejected / the dealer is dropped.
2. Fix **HIGH-2** (bound retained `DkgRound` history / GC on retry / backoff ceiling).
3. Re-run the multi-node suite with **EQUAL validator power** and **normal `unbonding_time`**
   to confirm no halt when a member-change coincides with a >2/3 validator-set rotation.
4. Add a targeted guard/review for base-layer lookups of exiting validators during a rekey.
5. Then either close gaps #4/#5 or ship them explicitly documented as deferred, with
   `DkgEnabled=false` at genesis and a documented governance-enable procedure.

Only after 1–4 should the DKG source be merged into `limonata-v030-release` and the release
tar regenerated.
