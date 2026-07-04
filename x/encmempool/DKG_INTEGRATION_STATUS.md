# x/encmempool on-chain validator DKG — integration status

**Date:** 2026-07-04
**Branch:** `limonata-dkg-integration` (HEAD `d9e12408` — HIGH-1/HIGH-2 fix pass)
**Target:** conditional merge into `limonata-v030-release`
**Decision:** **NO-GO. Not merged into v0.3.0.**
**Evidence gate:** **NOT PASSED** — one HIGH audit finding SURVIVES the fix pass (an
unbounded-state HIGH-2 *variant* via the member-change / ActiveThresholdKey path).

This document supersedes the `1456bd52` NO-GO record. It records the fix pass, the real
4-node re-proof, the re-audit, and the (still) NO-GO merge decision.

---

## TL;DR

The fix pass is strong and moved the needle: **HIGH-1 is fixed**, the **originally-filed
HIGH-2 (failed-round retry path) is fixed**, and a real 4-node equal-power re-proof passed
all five PROVE properties with zero app-hash divergence and both original HIGHs confirmed
dead live. **But the re-audit found that HIGH-2 was only half-closed.** The same
unbounded-state class survives through the *other* state-growth path — legitimate/induced
**member changes** — which retain the superseded epoch's `DkgRound` record AND leak a
never-deleted `ActiveThresholdKey`, and additionally reset the retry backoff. There is no
delete of an `ActiveThresholdKey` **anywhere** in the module. That is a surviving
validator-inducible unbounded-state HIGH, so the gate does **not** pass and the DKG is
**not** merged into v0.3.0. The v0.3.0 release dir was **not touched**.

---

## Fix pass — what got fixed (verified)

Committed on `limonata-dkg-integration` as `Limonata <noreply@limonata.xyz>` (commit
`d9e12408`, no Claude attribution). `go build ./cmd/evmd` => exit 0; `go vet` + `gofmt`
clean; `go test ./x/encmempool/...` passes.

- **HIGH-1 (FIXED).** `DkgDeal` now validates EVERY enc-share field at ingress and rejects
  the whole dealing if any is malformed: each Feldman commitment must parse as a compressed
  on-curve secp256k1 point (`dkg.ParseCommitmentPoints`), each enc-share `A` must be a valid
  compressed point (`dkg.ValidCompressedPoint`), each nonce must be exactly
  `threshold.NonceSize`, body non-empty — so a bad dealing can never enter QUAL.
  Defense-in-depth: `VerifyJustifiedComplaint` now treats a structurally-unopenable
  enc-share as a public, unframeable, justify-disqualifiable fault (`cheated=true,
  proofValid=true`). Regression probes in `dkg_soundness_probe_test.go`
  (`RejectedAtIngress`, `JustifyDisqualifiable` unit+e2e, `LivenessPreserved`) verified to
  FAIL pre-fix. **Re-audit: closed. Confirmed dead live on 4 nodes (malformed A / nonce /
  commitment deals rejected at ingress, code 18; finalized key correct on all nodes).**

- **HIGH-2, failed-round path (FIXED).** `purgeRoundData` split into `purgeDealings`
  (deal/complaint bulk only) and `purgeFailedRound` (also deletes the `DkgRound` record);
  the auto-retry branch now calls `purgeFailedRound`, bounding retained failed-round state
  to O(1) under a sustained sub-quorum. Capped geometric backoff (`retryBackoff`, ceiling
  `dkgBackoffCeilingBlocks=1000`) added; `CountDkgRounds` added.
  `TestOnChainDKG_SustainedSubQuorumBoundedAndRecovers` asserts record count stays <=2
  across ~16 retries then recovers; verified to FAIL pre-fix (peak=16). **Re-audit: this
  specific (failed-round) path is closed and confirmed bounded live (failed epochs 9–11
  purged on retry).**

- **Triage (cheap/adjacent, FIXED):** member_change purges the superseded epoch's dealing
  bulk; complaint window floored >=1 (`max64`); saturating deadline arithmetic (`addSat`)
  guards overflow; `EndBlockDKG` wrapped in a deterministic panic-guard (recover -> event,
  no chain halt); `decryptMatured` bounds crypto work at `maxDecryptAttemptsPerBlock=2048`,
  GCing overflow with an event.

---

## Multi-node re-proof (real 4-node p2p, equal power)

**Result: worked, no divergence, both ORIGINAL highs dead — verdict GO for those two.**

Re-proof succeeded on a realistic 4-node equal-power (100 each) p2p network with normal
unbonding (`1814400s`). All 5 PROVE properties passed with raw evidence: (1) identical
app-hash network formed; (2) DKG finalized to the SAME pub on all 4, no master secret on
chain; (3) encrypt->decrypt identical on all 4; (4) member-change rekey produced a NEW
independent key identical across nodes, and a 2-of-4 rotation under normal unbonding caused
NO `x/distribution` halt; (5) auto-retry recovered a forced sub-quorum failure with state
that stayed strictly bounded. App-hash identical across all 4 nodes at 16 heights spanning
the run — zero divergence, zero halts.

Residual note the re-proof itself flagged **by design**: *superseded ACTIVE-epoch
`DkgRound` records are retained and grow with member changes.* The re-proof treated this as
acceptable ("grows only with legitimate member changes"). **The re-audit disagrees** — see
the surviving HIGH below.

---

## Re-audit — 14 findings, **one SURVIVING HIGH (merge-blocker)**, 0 critical

### SURVIVING HIGH — HIGH-2 variant: member-change / ActiveThresholdKey unbounded state (+ backoff reset)

- **Where (verified in tree, HEAD `d9e12408`):**
  - `keeper/endblock.go:108-114` — the `member_change` branch calls `purgeDealings(cur)`
    (drops dealing/complaint bulk but **KEEPS** the `DkgRound` record) then
    `openRound(..., attempt=1, "member_change")`.
  - `keeper/dkg.go:83-110` — `purgeDealings` **deliberately retains** the `DkgRound`
    record. The only path that deletes a record is `purgeFailedRound` (`dkg.go:123-126`),
    which is called **only** from the retry branch (`endblock.go:139`). No ACTIVE-epoch
    record is ever GC'd.
  - **No `ActiveThresholdKey` delete exists anywhere in the module.** Grep of
    `x/encmempool/**` for any delete/prune of `ActiveThresholdKey` returns nothing; only
    `SetActiveKey` (`dkg.go:160`) and `GetActiveKey` (`dkg.go:164`) exist. Every successful
    rekey writes a new `ActiveThresholdKey` at the new epoch and none is ever reclaimed.
- **Why it is a HIGH, not "by design":**
  1. **Monotonic unbounded growth with no prune-on-mature.** ACTIVE-epoch records are only
     needed to authorize decryption shares for in-flight ciphertexts stamped with that
     epoch. Those ciphertexts have a bounded reveal horizon and are consumed by BeginBlock
     `decryptMatured`. Once an old epoch has zero pending ciphertexts, its `DkgRound` record
     **and** its `ActiveThresholdKey` are dead weight — but nothing reference-counts or
     prunes them. State grows O(total successful rekeys over chain lifetime), forever.
  2. **Inducible, not merely "legitimate."** `ActiveMembers` (`dkg.go:206`) is
     `IterateBondedValidatorsByPower` ∩ `p.DkgMembers`, and the re-key trigger is a change
     in `MembersHash`. A declared member flapping its bonded status (bond/unbond, or
     crossing the bonded-set boundary) induces a member_change **each time** — so the growth
     is griefable, not bounded by honest churn.
  3. **Backoff reset.** `member_change` opens `attempt=1`, resetting the HIGH-2 geometric
     backoff. An attacker who flaps membership both bloats state and defeats the retry
     backoff ceiling that HIGH-2 added for the failed path.
- **Net:** the fix closed the *failed-round* unbounded-state path but left the
  *active-epoch/member-change* unbounded-state path (plus a never-deleted `ActiveThresholdKey`
  and a griefable backoff reset) open. Same HIGH-2 class, different door. **Merge-blocking.**

### The other 13 (medium/low)

Not merge-blocking on their own; several cheap ones were fixed in this pass (see Triage).
The remainder (infinity-aggregate stuck key from 2 colluding dealers; Gap #4 EVM
re-injection; Gap #5 enc-key derivation; base-layer exiting-validator lookup review) are
documented as deferred, out of the minimal fix scope.

---

## Remaining fix to flip the gate to GO

1. **Prune superseded ACTIVE-epoch state.** Add reference-counted / prune-on-mature GC:
   track pending EncTx/EncShare count per epoch (or scan at maturation) and, once a
   superseded epoch has **zero** pending ciphertexts, delete BOTH `dkgRoundKey(epoch)` AND
   its `ActiveThresholdKey(epoch)`. Add the missing `DeleteActiveKey`. Alternatively
   ring-buffer the last N ACTIVE epochs and refuse to prune any epoch still referenced by a
   pending ciphertext (safe — reveal horizon is bounded). Must preserve in-flight-ciphertext
   share authorization for any epoch that still has pending ciphertexts.
2. **Do not let an induced member-change flap reset the backoff or force unbounded fresh
   rounds.** Carry/dampen the backoff across member-change churn, or rate-limit re-genesis so
   membership flapping cannot reset the backoff and cannot mint unbounded retained rounds —
   while still rekeying promptly on a genuine, settled member change (preserve liveness).
3. **Extend the HIGH-2 bounded-state probe to the MEMBER_CHANGE path:** many induced rekeys
   => retained `DkgRound` record count AND `ActiveThresholdKey` count must stay
   O(pending-epochs), not O(total rekeys). Verify it FAILS pre-fix.
4. Then a **fresh 4-node re-proof + re-audit**. Only if that audit returns no surviving
   critical/high does the gate pass.

---

## Build / test evidence

- `go build ./cmd/evmd` => **exit 0**; `go vet` + `gofmt` clean.
- `go test ./x/encmempool/...` => **ok** (auto-retry, determinism, soundness, and
  bounded-state probes). NOTE: the passing suite does **not** yet cover the surviving
  member-change unbounded-state path — that probe is item 3 above and does not exist yet.
- Live chain never touched; no throwaway listeners left; v0.3.0 release dir NOT touched.

---

## Safe-default note (informational — NOT a substitute for the fix)

`DefaultParams` ships `DkgEnabled: false`. The DKG state machine, daemon handlers, and the
new EndBlocker are inert until governance flips it on with a declared `DkgMembers` set. That
is the correct ship posture, and it is why the surviving HIGH is not an *active* risk to a
v0.3.0 that ships it dormant. It is **not**, however, grounds to merge with a known
unbounded-state HIGH still open: the gate rule is "no surviving critical/high," and one
survives. Merge only after the fix + fresh re-proof + clean re-audit.

---

## Go / No-Go

**NO-GO for v0.3.0.** Gate NOT PASSED: one surviving HIGH (member-change /
`ActiveThresholdKey` unbounded state + backoff reset). HIGH-1 and the failed-round HIGH-2
are genuinely fixed and the 4-node re-proof is clean, but the code's verdict is that the
unbounded-state class is not fully closed. Fix item 1–3 above, re-prove on 4 equal-power
nodes, re-audit; merge into `limonata-v030-release` (with `DkgEnabled=false` at genesis)
only when the re-audit shows no surviving critical/high.
