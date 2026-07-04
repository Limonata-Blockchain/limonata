# x/encmempool on-chain validator DKG — integration status

**Date:** 2026-07-04
**Branch:** `limonata-dkg-integration` (HEAD `a6db7233` — HIGH-2-variant + 2-medium fix pass)
**Target:** conditional merge into `limonata-v030-release`
**Decision:** **NO-GO. Not merged into v0.3.0.**
**Evidence gate:** **NOT PASSED** — a NEW HIGH was introduced by this cycle's DROP→DEFER
medium fix. The decrypt cap now DEFERS (instead of DROPping) the per-block overflow, which
reintroduced **unbounded EncTx state + an O(backlog) per-block scan + starvation of honest
ciphertexts (anti-MEV liveness break)**. Reproduced by the re-audit; confirmed by reading
the tree.

This document supersedes the `d9e12408` NO-GO record. It records this cycle's fixes (the
HIGH-2 variant IS genuinely closed and re-proved live), the re-audit, and the (still)
NO-GO merge decision — now blocked by a *different* HIGH than last cycle.

---

## TL;DR

The HIGH-2 variant (member-change / `ActiveThresholdKey` unbounded state) is **genuinely
and well closed** this cycle — prune-on-mature GC with a per-epoch in-flight ref-count, the
missing `DeleteActiveKey` added, a flap dampener, `ValidateDkgWindows` param bounds — and a
fresh 4-node re-proof confirmed retained DKG state stays **bounded (peak 2, steady 1)**
across 10 real member-change rekeys with byte-identical app-hash and in-flight decrypt
surviving 2 intervening rekeys. **But the re-audit caught a self-inflicted regression:** the
*other* medium fix — changing the per-block decrypt cap from **DROP** to **DEFER** — removed
the only mechanism that bounded EncTx accumulation under flood, and did so in a way that (a)
lets state grow without bound, (b) forces every block to materialize the entire matured
backlog before doing any work, and (c) lets one flooder indefinitely starve honest
ciphertexts out of decryption — a direct defeat of the module's anti-MEV timed-decryption
property. Any user can trigger it permissionlessly (submission is only gas-gated; there is
no admission cap). That is a fresh, exploitable HIGH in the code proposed for merge, so the
gate does **not** pass and the DKG is **not** merged into v0.3.0. The v0.3.0 release dir was
**not touched**.

---

## This cycle — what got fixed (verified in tree, HEAD `a6db7233`)

`go build ./x/encmempool/...` => **exit 0**; `go test ./x/encmempool/...` => **ok**
(keeper suite ~14.7s). Committed as `Limonata <noreply@limonata.xyz>` (no Claude
attribution).

- **HIGH-2 variant — member-change / ACTIVE-epoch unbounded state (CLOSED, verified good).**
  - New per-epoch ref-count of in-flight (un-matured) EncTx: `EpochEncCountPrefix` (`0x16`,
    `types/keys.go:36`); `incEpochEncCount` on submit (`keeper.go:131`), `decEpochEncCount`
    at maturity (`abci.go:178`).
  - The missing delete now exists: `DeleteActiveKey` (`dkg.go:193`).
  - `maybePruneEpoch` (`dkg.go:243`) deletes BOTH the superseded `DkgRound` record AND its
    `ActiveThresholdKey` — but only when the epoch is **neither** the serving `ActiveEpoch`
    **nor** the in-flight `CurrentEpoch` **AND** its ref-count is 0. So an epoch pinned by
    any un-matured EncTx is never pruned early: `SubmitDecryptionShare` still reads
    `GetDkgRound(epoch)` and recovery still reads `GetActiveKey(epoch)` for in-flight
    ciphertexts. Prune fires at `finalizeRound` for the just-superseded `prevActive`
    (`dkg.go:394`) if already drained, else the instant its last stamped ciphertext matures
    (`abci.go:179`). Retained state is now **O(pending epochs)**, not O(total rekeys).
  - **Re-audit: closed. Re-proved live** — bounded (peak 2 / steady 1) across 10 real
    member-change rekeys on 4 p2p nodes; a ciphertext pinned to epoch E survived 2
    intervening rekeys and decrypted correctly on all 4 at maturity, then E was reclaimed
    exactly at maturity; app-hash byte-identical at every sampled height, zero panics/halts.

- **Flap dampener (CLOSED).** `LastRekeyHeightKey` (`0x17`); `DkgMinRekeyGap` (default 30,
  `types.go:193`). `endblock.go:116` holds a member-change arriving within `DkgMinRekeyGap`
  of the last rekey, while a genuine settled change (preceded by stability) rekeys
  immediately. A superseded FAILED round's record is now fully GC'd on member change (was
  leaking one record per churn); an Active superseded round is kept (pinned) and pruned by
  the GC above. Unit-covered by `TestOnChainDKG_MemberChangeFlapDampened`.

- **Medium (b) — param bounds (CLOSED).** `Params.ValidateDkgWindows` (`types.go:250`)
  wired into `GenesisState.Validate` (`types.go:228`) — the only governance/genesis param
  entry point (encmempool exposes no `MsgUpdateParams`). Deal/complaint/backoff windows must
  be in `[1, 10_000_000]`; `DkgMinRekeyGap`/`DkgMaxAttempts` upper-capped; `DkgMaxAttempts=0`
  still allowed (never-alert). Nonsensical values rejected at ingress instead of silently
  clamped.

---

## Medium (a) — DROP→DEFER — is where this cycle broke: the surviving HIGH

### SURVIVING HIGH — DROP→DEFER reintroduced unbounded EncTx state + O(backlog) per-block scan + honest-ciphertext starvation (anti-MEV liveness break)

- **Where (verified in tree, HEAD `a6db7233`):**
  - `keeper/abci.go:106-107` — `decryptMatured` now materializes the WHOLE matured backlog:
    `k.IterateEncTxUpTo(ctx, cur, func(e) { matured = append(matured, e) })`.
  - `keeper/abci.go:118-123` — at `attempts >= maxDecryptAttemptsPerBlock (2048)` the loop
    `break`s and leaves the surplus in state. **The break caps only the crypto loop — the
    O(backlog) materialization at line 107 already ran.**
  - `keeper/keeper.go:178-198` — `IterateEncTxUpTo` range-scans `[EncTxPrefix, be(h+1))`,
    i.e. every EncTx with `decryptHeight <= cur` (the cumulative backlog), not just this
    height's arrivals.
  - `keeper/msg_server.go:93-119` — `SubmitEncrypted` has **no admission cap**: the only
    ingress checks are `EncEnabled`, non-empty `A`/`Body`, and nonce length. Nothing bounds
    the number of in-flight / pending EncTx. Submission is permissionless, gas-gated only.

- **Why it is a HIGH:**
  1. **Unbounded EncTx state.** Pre-fix, the cap DELETED (dropped) the per-block overflow, so
     EncTx state was bounded — that was the *entire stated purpose* of the cap ("so no flood
     of ciphertexts can stall block production", `abci.go:96-99`). DEFER removed that
     enforcement. With no admission cap and a drain fixed at 2048/block, any arrival rate
     above 2048/block — reachable with cheap minimal-body submits under a normal EVM block
     gas limit — accumulates in state without bound. The prune/ref-count fix bounded
     *active-epoch* state; this fix un-bounded *ciphertext* state through a different door.
  2. **O(backlog) per-block scan.** Line 107 walks + JSON-unmarshals + appends the ENTIRE
     matured backlog into `matured` every block, regardless of the 2048 cap (the cap gates
     the loop *after* materialization). Per-block cost is O(total backlog) — and by (1) the
     backlog is itself unbounded — so block processing time grows with the flood: a
     slowdown/OOM/halt DoS.
  3. **Starvation / anti-MEV liveness break.** `matured` is in `(decryptHeight, seq)` order
     and the loop DEFERS the SUFFIX. An attacker who floods the OLDEST maturing height with
     >2048 ciphertexts occupies the entire per-block decrypt budget every block; every honest
     ciphertext behind them in key order is deferred indefinitely and never decrypts. Since
     timed decryption *is* the anti-MEV mechanism, an attacker can thereby indefinitely
     delay/censor honest reveals and choose when they surface — defeating the module's core
     property. **Secondary:** a permanently-deferred ciphertext keeps `getEpochEncCount > 0`,
     so `maybePruneEpoch` can never reclaim its epoch — the starvation quietly re-opens the
     very unbounded active-epoch state the HIGH-2-variant fix just closed.

- **Net:** the medium (a) fix traded a MEDIUM ("silently drops overflow work") for a HIGH
  ("unbounded state + O(backlog) scan + honest-ciphertext starvation"). **Merge-blocking.**

### The rest of the 17 findings (medium/low)

Not merge-blocking on their own. The two mediums this cycle set out to fix — param bounds
(b) and the decrypt-cap behavior (a) — are respectively CLOSED and the source of the HIGH
above. Remaining lows/mediums (infinity-aggregate stuck key from 2 colluding dealers; Gap #4
EVM re-injection; Gap #5 enc-key derivation; base-layer exiting-validator lookup review) are
documented as deferred, out of the minimal fix scope. Triage those in the same cycle that
closes the HIGH.

---

## Remaining fix to flip the gate to GO

The DEFER intent (don't silently lose share-carrying work) is right; the implementation must
be **bounded** in all three dimensions:

1. **Bounded scan.** Stop materializing the whole backlog. Cap the iterator at
   `maxDecryptAttemptsPerBlock` — add a limited variant (or `break` inside the
   `IterateEncTxUpTo` callback after collecting `cap` items) so per-block cost is O(cap), not
   O(backlog).
2. **Bounded state (admission control + hard ceiling).** Cap in-flight / pending EncTx at
   `SubmitEncrypted` ingress — globally and/or per-submitter and/or per decrypt-height — and
   reject new submissions when full, so the DEFER backlog is hard-bounded. Keep an absolute
   state ceiling with a LOUD, deterministic DROP (event) as the last resort, so both "no
   silent loss under normal load" AND "bounded state under flood" hold. **Any DROP path MUST
   call `decEpochEncCount` + `maybePruneEpoch`** for the dropped ciphertext — otherwise the
   drop re-leaks its epoch and regresses the HIGH-2-variant fix.
3. **Anti-starvation fairness.** Fair-share the per-block decrypt budget across submitters
   (per-submitter cap per block, or round-robin over submitters) so one flooder cannot
   monopolize the front of the ordered queue and starve honest ciphertexts — preserving the
   anti-MEV liveness property. Must stay deterministic (ordered store + a deterministic
   fair-share rule so every node selects the identical set).
4. **Regression probe.** A sustained >2048/block flood must keep EncTx state AND per-block
   scan cost bounded, and honest ciphertexts must still decrypt at/near their scheduled
   height (no indefinite starvation). Verify it FAILS pre-fix (today: unbounded `matured`,
   no `encmempool_decrypt_deferred` fairness, epoch never reclaimed).
5. Then a **fresh 4-node re-proof + re-audit**. Gate passes only if that audit returns no
   surviving critical/high. The HIGH-2-variant closure and flap dampener from this cycle
   carry forward (re-proved good) and do not need re-litigating unless the fix touches them.

---

## Build / test evidence (this cycle)

- `go build ./x/encmempool/...` => **exit 0**.
- `go test ./x/encmempool/...` => **ok** (keeper ~14.7s; dkg/threshold cached). Includes the
  cycle's new probes: `TestOnChainDKG_ActiveEpochBoundedUnderRekeys`,
  `TestOnChainDKG_InFlightCiphertextSurvivesRekey`, `TestOnChainDKG_MemberChangeFlapDampened`,
  `TestDecryptCapDefersNotDrops`. **NOTE:** `TestDecryptCapDefersNotDrops` asserts nothing is
  dropped — it does NOT assert bounded state, bounded scan, or fairness, which is exactly the
  gap the surviving HIGH lives in. The remaining-fix probe (item 4) does not exist yet.
- Multi-node re-proof: GO on the HIGH-2 variant (bounded active-epoch state, in-flight
  decrypt survives rekeys, byte-identical app-hash, zero halts). The re-proof did NOT stress
  a >2048/block decrypt flood at live scale, so it did not exercise the surviving HIGH.
- Live chain never touched (26657 advancing, height ~714163 during this review); no throwaway
  listeners left; **v0.3.0 release dir NOT touched.**

---

## Safe-default note (informational — NOT a substitute for the fix)

`DefaultParams` ships BOTH `EncEnabled: false` and `DkgEnabled: false`
(`types.go:181-192`) — the entire encrypt/decrypt/DKG path is dormant at genesis until
governance flips it on. That is the correct ship posture and is why the surviving HIGH is not
an *active* risk to a v0.3.0 that ships it dormant. It is **not**, however, grounds to merge
with a known unbounded-state / liveness HIGH still in the code: the gate rule is "no
surviving critical/high," and one survives, and it activates the moment governance enables
`EncEnabled`. Merge only after the fix + fresh re-proof + clean re-audit.

---

## Go / No-Go

**NO-GO for v0.3.0.** Gate NOT PASSED: one surviving HIGH (DROP→DEFER reintroduced unbounded
EncTx state + O(backlog) per-block scan + honest-ciphertext starvation / anti-MEV liveness
break). The HIGH-2 variant (member-change / `ActiveThresholdKey` unbounded state) is
genuinely closed and re-proved bounded live, the flap dampener and param bounds are in, and
the build + suite are green — but the code's verdict is that this cycle's decrypt-cap medium
fix opened a new HIGH of the same unbounded-state / liveness class. Apply remaining-fix items
1–4 above (bounded scan + admission control with a hard-ceiling drop + fair-share drain +
regression probe), re-prove on 4 equal-power nodes under a decrypt flood, re-audit; merge
into `limonata-v030-release` (with `DkgEnabled=false` and `EncEnabled=false` at genesis) only
when the re-audit shows no surviving critical/high.
