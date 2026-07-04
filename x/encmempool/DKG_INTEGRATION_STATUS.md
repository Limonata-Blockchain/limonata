# x/encmempool on-chain validator DKG — integration status

**Date:** 2026-07-04
**Source branch:** `limonata-dkg-integration` (HEAD `53e1eb76` — bounded-defer + admission + fairness)
**Merged into:** `limonata-v030-release`
**Decision:** **GO — merged into v0.3.0, present-but-DORMANT.**
**Evidence gate:** **PASSED** — the self-inflicted DROP→DEFER HIGH is closed; build green;
encmempool + all touched modules test-green; genesis validates in both modes; the DKG ships
`DkgEnabled=false` (dormant).

This supersedes the prior `a6db7233` NO-GO record. The regression that blocked the last
cycle (changing the per-block decrypt cap from DROP to an *unbounded* DEFER, which
reintroduced unbounded EncTx state + an O(backlog) per-block re-scan + honest-ciphertext
starvation) has been fixed with **bounded-defer + admission control + fairness**, all
deterministic and preserving the HIGH-2 GC and in-flight-decryption safety.

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

**To enable the DKG path**, a `MsgUpdateParams` (governance) sets `DkgEnabled=true` with a
valid `DkgMembers` set (33-byte compressed enc-pubkeys, unique operator/account addrs),
`DkgThreshold` ≤ members, and sane `DkgDealWindow` / `DkgComplaintWindow` /
`DkgRetryBackoff` (all validated by `Params.Validate` / `ValidateDkgWindows`). When the DKG
is on, the trusted-setup `ThresholdPub`/`Threshold`/`Keypers` become the epoch-0 fallback and
need not be populated.

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
