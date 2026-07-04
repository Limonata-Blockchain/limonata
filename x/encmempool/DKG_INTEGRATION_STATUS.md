# x/encmempool on-chain validator DKG — integration status

**Date:** 2026-07-04
**Source branch:** `limonata-dkg-integration` (HEAD `53e1eb76` — bounded-defer + admission + fairness)
**Merged into:** `limonata-v030-release`
**Follow-on merge:** `limonata-killswitch` → `limonata-v030-release` — the governance
**KILL-SWITCH** (`MsgUpdateParams`) that makes activating the dormant DKG **reversible by a
vote** (see the dedicated section below).
**Decision:** **GO — merged into v0.3.0, present-but-DORMANT, now with a reversible gov toggle.**
**Evidence gate:** **PASSED** — the self-inflicted DROP→DEFER HIGH is closed; build green;
encmempool + all touched modules test-green; genesis validates in both modes; the DKG ships
`DkgEnabled=false` **and** `EncEnabled=false` in `DefaultParams` (dormant). The kill-switch was
**proven on a 4-node p2p network**: dormant→activate→disable→re-enable, app-hash identical
across all 4 nodes at every one of 454 sampled heights, clean disable (in-flight EncTx drained,
not stranded), no halt, authority + full validation enforced.

This supersedes the prior `a6db7233` NO-GO record. The regression that blocked the last
cycle (changing the per-block decrypt cap from DROP to an *unbounded* DEFER, which
reintroduced unbounded EncTx state + an O(backlog) per-block re-scan + honest-ciphertext
starvation) has been fixed with **bounded-defer + admission control + fairness**, all
deterministic and preserving the HIGH-2 GC and in-flight-decryption safety.

---

## Governance KILL-SWITCH — `MsgUpdateParams` (this follow-on merge)

**Why it exists.** Before this merge x/encmempool had **no params-mutation path** — `Params`
(including `DkgEnabled` / `EncEnabled`) were settable **only at genesis or a coordinated
chain upgrade**. Activating the dormant DKG on a live chain was therefore a **one-way door**:
a bad activation could not be undone without *another* coordinated upgrade. The kill-switch
closes that door by adding a gov-gated `MsgUpdateParams` so activation is **reversible by a
single vote**.

**Wiring (minimal blast radius).** A new `UpdateParams` rpc + `MsgUpdateParams{authority,
params}` was added to `proto/.../encmempool/v1/tx.proto` (only `tx.proto` + its `tx.pb.go`
regenerated), registered in `types/codec.go`. Because module params are stored as
**JSON-in-store** (not proto), `MsgUpdateParams.params` carries the **JSON encoding of
`types.Params`**; the handler decodes it opaquely. No `app.go` / keeper-constructor change.

**Three safety gates, in order (`keeper/msg_server.go: UpdateParams`):**
1. **Authority-gated.** `msg.Authority` must equal the x/gov module account
   (`authtypes.NewModuleAddress(govtypes.ModuleName)`, computed at runtime — mirrors
   `x/valgrant`; `x/gassponsor`/`x/squeeze` have no `UpdateParams`). Any other signer →
   `ErrUnauthorized`, no mutation.
2. **Fully validated.** The decoded params must pass the **same `Params.Validate` /
   `ValidateDkgWindows` used at genesis** — bounding `RevealDelay`/`DecryptDelay`/thresholds/
   DKG windows/in-flight ceilings and requiring a well-formed member set (`DkgEnabled`) or
   keyper + `ThresholdPub` set (`EncEnabled`). Malformed JSON and every invalid config are
   rejected **before** `SetParams`; the stored params are left untouched. An update can
   therefore **never** install a config that would strand EncTx state or panic
   BeginBlock/EndBlock.
3. **Applied atomically** with a loud `encmempool_params_updated` event
   (`enc_enabled` / `dkg_enabled`).

### Safe-DISABLE semantics (the whole point)

Turning the path **off** (`EncEnabled=false`, or `DkgEnabled=false` with no legacy trusted
key) stops new-round opening (`EndBlockDKG` returns on `!DkgEnabled`) and new-ciphertext
admission (`SubmitEncrypted` requires `EncEnabled`). The **strand risk** it must avoid:
`decryptMatured` is the *only* remover of an `EncTx` and is gated on the path being live, so a
naïve disable would leave already-submitted `EncTx` **never decrypted AND never GC'd** —
leaking `EncTx` state, the global/per-submitter ref-counts, and the pinned per-epoch
`DkgRound` + `ActiveThresholdKey` forever.

**Fix (`keeper/abci.go`).** `BeginBlock` now branches:
- **Path live** (`EncEnabled && (Threshold>0 || DkgEnabled)`) → `decryptMatured` as before.
  A *partial* disable (e.g. `DkgEnabled=false` but a valid legacy `Threshold>0`) still
  **decrypts** DKG-epoch ciphertexts via `GetActiveKey`.
- **Path off but `GetGlobalEncCount>0`** → the new **`drainDisabledEncTx`** GC's matured
  in-flight ciphertexts through the **existing `releaseEncTx` path** (delete EncTx + shares,
  dec every ref-count, `maybePruneEpoch`), using the **same bounded scan**
  (`CollectMaturedUpTo(maxDecryptScanPerBlock)`). Result: **no strand, no halt, bounded
  O(cap)/block work, deterministic**, and the `O(1)` count guard makes it **zero-overhead in
  the default/dormant config**.
- **Path off and no in-flight state** (the dormant default) → the `O(1)` `GetGlobalEncCount`
  guard short-circuits; nothing runs.

GC (drop-with-event `encmempool_enc_drained_disabled`), not decrypt, is the correct
kill-switch semantics: the module is being turned OFF and the PoC never re-injects decrypted
bodies into the EVM, so shedding the finite in-flight set cleanly is the non-stranding
outcome. Because no new EncTx are admitted while disabled and `DecryptDelay` is bounded, the
in-flight set fully drains within a bounded number of blocks. **Re-enabling** opens a fresh
DKG round via the unchanged `EndBlock` state machine and restores encrypt/decrypt. No existing
HIGH-fix (admission control, bounded scan, H2 GC / epoch ref-count, ingress validation) is
weakened.

### Tests

`keeper/updateparams_test.go` + `keeper/killswitch_probe_test.go` (all green under
`go test -tags test`): authority-only (non-gov rejected + no mutation; gov applies); invalid
params rejected across `reveal_delay=0` / enc-without-keypath / dkg-without-members /
dkg-zero-window / malformed-JSON with **state unchanged**; enable→disable→re-enable cycle;
disable **drains** an in-flight legacy epoch-0 ciphertext with **no strand** (EncTx gone,
global + submitter counts 0, no decrypt, no BeginBlock error); disable drains a **superseded
DKG epoch** and prunes its `DkgRound` + `ActiveThresholdKey` via the ref-count path; plus 19
adversarial probes (DKG↔legacy transitions, epoch ref-count integrity, determinism,
authority edges).

### Recommended MAINNET hardening (governance-process, not code)

The kill-switch is a **double-edged** primitive: the same `MsgUpdateParams` that lets a good
gov *disable* a bad activation also lets a **captured** gov *strip the anti-MEV protection*
(flip `EncEnabled=false`) to enable front-running. Mitigate at the governance-process layer,
**not** by removing the toggle (an irreversible activation is strictly worse):
- **Timelock the disable.** Route `MsgUpdateParams` that *reduce* protection (any
  `EncEnabled true→false` or `DkgEnabled true→false`) through a longer voting + **execution
  delay** than ordinary params, so the network can react to a capture attempt before anti-MEV
  drops. (An *enable* or a pure safety-tightening can keep the normal timeline.)
- **High quorum / super-majority** for protection-reducing updates.
- **Guardian veto.** A time-boxed security-council / guardian able to **veto** (not enact) a
  protection-reducing update, expiring after audit maturity — veto-only keeps it from becoming
  a second capture surface.
- **On-chain alerting.** The `encmempool_params_updated` event should page an off-chain
  monitor on any `enc_enabled`/`dkg_enabled` transition.

These are deployment/gov-config choices (gov `params`, a custom ante/decorator, or an
authz/group policy in front of gov) and are intentionally **not** baked into the module, which
keeps the authority a single well-known account (`x/gov`) and the blast radius minimal.

---

## TL;DR

- The self-inflicted flood/starvation **HIGH is CLOSED**. Per-block decrypt work is now
  O(cap) (bounded scan), in-flight EncTx is hard-bounded at ingress (admission ceilings)
  with an always-on absolute backstop, and one flooder can no longer starve honest
  ciphertexts (deterministic fair-share). Every removal path (mature *and* ceiling-drop)
  routes through a single `releaseEncTx` helper, so no drop can re-leak the per-epoch
  ref-count — the HIGH-2 fix stays intact.
- **Merged into `limonata-v030-release` DORMANT.** `DefaultParams` ship
  `DkgEnabled=false` **and** `EncEnabled=false`. The DKG code, the `dkg` CLI, the keyper
  daemon, and the bounded/admission/fairness logic are all present but the DKG path is off
  until governance turns it on.
- Build is green; `go build ./...` produces a working `limonatad`
  (`keyper` + `dkg` subcommands present). The full `x/encmempool` suite is green, as is
  every other `x/...` module touched by the merge.

---

## This cycle — what got fixed (verified in the merged tree)

All symbols below were confirmed present in non-test source and exercised by passing tests.

1. **Bounded scan.** `keeper.CollectMaturedUpTo` materializes at most
   `maxDecryptScanPerBlock` (= `2*cap` = 4096) matured EncTx per block and returns a
   `truncated` flag, so `decryptMatured`'s per-block cost is **O(cap), not O(backlog)**.
   The old materialize-the-whole-backlog iterator is gone.

2. **Admission control at ingress.** `SubmitEncrypted` rejects when either the global
   (`Params.MaxInFlightEncTx`) or per-submitter (`Params.MaxInFlightPerSubmitter`) in-flight
   ceiling is reached, using O(1) maintained ref-counts (`GetGlobalEncCount` /
   `GetSubmitterEncCount`, both deleted at zero so live counters stay
   O(submitters-with-pending-ct)). A ceiling of `0` disables that check.

3. **Absolute ceiling (always-on).** A constant `absMaxInFlightEncTx` (1<<20, or the param
   when lower) is the unconditional "bounded state under flood" backstop: if in-flight
   exceeds it, `decryptMatured` sheds the **newest** scanned entries (keeping the
   oldest/most-overdue) with a loud deterministic `encmempool_enc_dropped_ceiling` event,
   bounded to `maxCeilingDropsPerBlock`/block. This holds even if admission is bypassed
   (genesis import / a lowered ceiling).

4. **H2-safe drop rule.** Both the drop path and the mature path go through the single
   `releaseEncTx` helper (`keeper.go`), which does
   `DeleteEncTx + DeleteSharesFor + decGlobalEncCount + decSubmitterEncCount` and, for
   `Epoch > 0`, `decEpochEncCount + maybePruneEpoch`. No removal can re-leak the epoch
   ref-count. Regressed-by: `TestCeilingDropReleasesEpochRefcount_HIGH2Safe` (a superseded
   epoch drained entirely via drops is still pruned).

5. **Fairness.** `selectFairDecrypts` fair-shares the per-block decrypt budget across
   submitters via a deterministic first-appearance round-robin, then processes the selected
   subset in original `(decryptHeight, seq)` order (execution ordering unchanged). When the
   matured set fits the budget, every entry is selected — no reorder or loss under normal
   load.

### Folded-in mediums / lows

- **`DecryptDelay` bounded** in param validation (`Params.Validate`, ≤ 10,000,000 blocks) —
  it drives the key-retention window. The two admission ceilings are validated too
  (each ≤ 1<<40; per-submitter must be ≤ global).
- **BeginBlock panic-guard.** A top-level recover in `BeginBlock` (symmetry with
  `EndBlockDKG`) turns any unforeseen panic in the reveal/GC/decrypt scans into a contained,
  deterministic `encmempool_beginblock_panic` event returning `nil` instead of a fatal
  BeginBlock error.
- **Flap-dampener fix.** The member-change-dampened arm of `EndBlockDKG` no longer freezes a
  FAILED round's auto-retry: `retryFailedRound` retries against the OLD member set (stable
  `MembersHash`, so it follows the backoff-gated retry path with `attempt++`, never a
  member-change re-genesis), while a genuine settled member change is still applied once the
  min-rekey gap elapses.

### Merged-in audit fixes from v0.3.0 (preserved, not lost)

The `limonata-v030-release` security-audit fixes to `x/encmempool` were preserved through
the merge and coexist with the DKG work:

- **`threshold.Decrypt` nonce-length guard** + `const NonceSize = 12` (dedup'd across the two
  branches) — an out-of-spec AES-GCM nonce is rejected as a normal error instead of
  panicking `gcm.Open` on the consensus decrypt path.
- **`SubmitEncrypted` ingress nonce guard** (rejects a non-12-byte nonce before it enters
  state).
- **`ParseShare` canonicality** — honours the `SetBytes` overflow flag and rejects a zero
  scalar.
- **`Params.Validate`** now merges *both* branches' checks: the v0.3.0 trusted-setup checks
  (threshold ≥ 1, threshold ≤ keypers, `threshold_pub` set, keyper de-dup — gated behind
  `EncEnabled && !DkgEnabled`, since the DKG supplies its own active key) **and** the DKG
  cycle's checks (DecryptDelay bound, admission-ceiling bounds, and the `DkgEnabled` member/
  window validation).

---

## Multi-node re-proof (flood / fairness / H2)

The 4-node p2p re-proof (prior-cycle harness, unchanged binary logic) established, and the
merged tree reproduces at the code + unit-test level:

- Ingress admission hard-bounds in-flight EncTx (a per-submitter attacker pinned at its
  ceiling under thousands of attempts; late txs rejected at ingress with the exact
  "in-flight ceiling" error).
- Per-block work stays bounded with **zero app-hash divergence** across all flood windows.
- Drops/matures route through `releaseEncTx`, so the epoch ref-count never re-leaks
  (HIGH-2 preserved: retained DKG state peaked at 2 across 8 rekeys, in-flight ciphertext
  survived and decrypted).
- Honest ciphertexts submitted during a flood decrypt on schedule identically on all nodes.

**Honest caveats (orthogonal to the on-chain fix):**
1. The per-block fairness round-robin (`>budget` branch) and the absolute-ceiling drop path
   (1<<20) are not reachable under live admission + block-gas limits; they are exercised only
   by the unit tests `TestDecryptFloodBoundedAndFair` and
   `TestCeilingDropReleasesEpochRefcount_HIGH2Safe` (both pass).
2. The keyper **daemon** (client, not the consensus fix) is fragile under a share-flood
   (account-sequence mismatch) — a client-robustness follow-up, not a defect in the chain
   fix.

---

## Audit

- Critical/High findings on the merged code: **none**.
- Total findings this cycle: 14, all triaged; the HIGH is closed and the mediums/lows folded
  in (above).

---

## Build / test / genesis verification (this merge, on `limonata-v030-release`)

- **Build:** `make build` → `build/evmd` green (CGO on, release ldflags). `keyper` and `dkg`
  subcommands present.
- **Tests:** `go test -tags test ./x/encmempool/...` green (keeper, dkg, threshold, types).
  The load-bearing tests pass: `TestSubmitEncrypted_AdmissionCeilings`,
  `TestCeilingDropReleasesEpochRefcount_HIGH2Safe`, `TestDecryptFloodBoundedAndFair`,
  `TestRegression_NonceLengthNoHalt`.
- **Genesis (both modes)** via `limonata-genesis.sh` with the merged binary:
  - `MODE=testnet` → `GENESIS_OK`, supply = 1,000,000,000 LIMO, `bond_denom=aLIMO`,
    `extended_denom=aLIMO` (`app_state.evm.params.extended_denom_options.extended_denom`).
  - `MODE=mainnet` → `GENESIS_OK` (real 12-mo cliff + 36-mo linear vesting, no faucet,
    reserve retained), same supply/denoms. (Run with `KEYRING=test` in CI; the mainnet
    default `KEYRING=os` needs an interactive system keyring, unavailable headless — a
    key-custody concern orthogonal to genesis validity.)
  - **`dkg_enabled` is absent from genesis in both modes ⇒ unmarshals to `false`
    (DKG DORMANT).**

### Known pre-existing (NOT caused by this merge)

`go test ./x/vm/...` has two build-failed test packages (`x/vm/keeper`, `x/vm/wrappers`)
because v0.3.0's own `x/vm/keeper/fees.go` added `SendCoinsFromModuleToModule` to the
`types.BankKeeper` interface without regenerating the mocks
(`x/vm/types/mocks/BankKeeper.go`, `x/vm/wrappers/testutil` `MockBankWrapper`). This
reproduces identically on a **pristine `limonata-v030-release`** checkout (proven via a
detached worktree) — it is pre-existing v0.3.0 test-only debt, is unrelated to the DKG
(which never touches `x/vm`), and does **not** affect the shipped binary (it builds and runs
fine). Follow-up: regenerate the two `x/vm` bank mocks (mockery) and add the missing
test expectations.

Also note: this repo's tests must be run with `-tags test` — without it, `x/vm/types`
`ResetTestConfig` intentionally panics.

---

## Shipped DORMANT — how to enable later (governance)

The v0.3.0 binary now **contains** the full validator-DKG, the keyper daemon, and the
bounded/admission/fairness decrypt path, but ships them **off**:

- `DefaultParams`: `DkgEnabled=false`, `EncEnabled=false`,
  `MaxInFlightEncTx=32768`, `MaxInFlightPerSubmitter=2048`.

**To enable the DKG path**, a `MsgUpdateParams` (governance — the kill-switch added by this
merge; see the section above) sets `DkgEnabled=true` with a valid `DkgMembers` set (33-byte
compressed enc-pubkeys, unique operator/account addrs), `DkgThreshold` ≤ members, and sane
`DkgDealWindow` / `DkgComplaintWindow` / `DkgRetryBackoff` (all validated by `Params.Validate`
/ `ValidateDkgWindows`). When the DKG is on, the trusted-setup `ThresholdPub`/`Threshold`/
`Keypers` become the epoch-0 fallback and need not be populated. Crucially, because
`MsgUpdateParams` now exists, this activation is **REVERSIBLE**: if the activation misbehaves,
a second `MsgUpdateParams` flips `DkgEnabled`/`EncEnabled` back to `false` and the in-flight
EncTx drain cleanly (no strand, no halt) — no coordinated chain upgrade required.

### Genesis-script note (enc_enabled vs the dormant default)

`DefaultParams` ship `EncEnabled=false`, but `limonata-genesis.sh` **explicitly bakes
`enc_enabled=true`** — the pre-existing v0.3.0 trusted-setup 2-of-3 encrypted mempool that is
already part of the live testnet genesis. This merge **deliberately did not turn that off**:
disabling a live, already-audited feature is out of scope for a "merge the DKG dormant" task
and would be a product regression, not a safety win. The genesis it produces sets
`enc_enabled=true` **and** `dkg_enabled=false` (DKG dormant, which is the actual safety
requirement).

> If the intended posture is a **fully dormant** encrypted mempool at genesis
> (`enc_enabled=false` too, enabled later purely by governance), that is a one-line change to
> `limonata-genesis.sh` (line ~305) — flip `enc_enabled:true` → `false` and drop the keyper
> setup block. It was left as an explicit operator decision for Jason, not made silently here.
> Note the merged binary is strictly *safer* than the current v0.3.0 for the `enc_enabled=true`
> path anyway (it adds the bounded scan + absolute ceiling; admission ceilings are opt-in via
> the same governance path).
