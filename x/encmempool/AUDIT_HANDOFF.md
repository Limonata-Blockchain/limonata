<!--
SPDX-License-Identifier: BUSL-1.1
Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1.
-->

# Limonata encrypted-mempool / transparent-DKG — External Audit Handoff

Last updated: 2026-07-08. Branch `limonata-dkg-transparent`. This document is the single
source of truth for an external firm: scope, current state, what is already fixed, and the
KNOWN OPEN items that deserve audit budget. Read it before diving into the code.

---

## 1. Scope & licensing

**In scope (the novel work):**
- `x/encmempool/` — the encrypted mempool + transparent validator DKG (threshold decryption,
  vote-extension DKG, admission control, decrypt→execute re-injection).
- `evmd/dkg_voteext.go`, `evmd/mempool.go` — the ABCI++ vote-extension wiring (ExtendVote,
  VerifyVoteExtension, PrepareProposal/ProcessProposal injection, PreBlock consume).

**Licensing:** every file under `x/encmempool/dkg/`, `x/encmempool/dkgnode/`, and the DKG-
specific files carry an **SPDX BUSL-1.1** header — they are **source-available, NOT Apache-2.0**.
`LICENSE.dkg` (repo root) + `x/encmempool/dkg/LICENSE` hold the terms. The base cosmos/evm and
the already-public commit-reveal base (`keeper/abci.go`, `keeper/genesis.go`, `threshold/`,
protos) stay Apache-2.0. Do not relicense.

**Out of scope:** the base cosmos/evm modules (x/vm, ante, feemarket, etc.), except where the
re-injection path calls into x/vm (see §4).

---

## 2. Current deployment state (IMPORTANT)

Nothing in this track is live on mainnet. On the testnet (chain 10777) the transparent DKG and
threshold decryption are **dormant** (`DkgEnabled`/`DkgTransparent`/`EncEnabled` default false).
Three governance gates, all default OFF:

| Param | Default | Turns on |
|---|---|---|
| `EncEnabled` | false | threshold encryption (submit + decrypt) |
| `DkgEnabled` + `DkgTransparent` | false | the in-node validator DKG (else legacy trusted setup) |
| `EncExecEnabled` | false | decrypt→**EXECUTE** re-injection of the decrypted EVM tx |

**Do NOT enable any of these on a live chain until this audit signs off.** In particular
`EncExecEnabled` executes attacker-controlled EVM transactions inside BeginBlock (halt/fork
surface) and has one KNOWN residual (§5, precompile sub-calls).

---

## 3. Trust model & the topology precondition (READ THIS FIRST)

The anti-MEV guarantee is **threshold cryptography over the validator set**: the committee is
auto-derived from bonded validators (each announces an ECIES key via a vote extension), and
eval-points are **stake-weighted**. Confidentiality holds iff no single operator (nor a colluding
coalition) owns ≥ the reconstruction threshold `t = floor(2S/3) - n + 1` of eval-points.

**This is a precondition on the stake distribution, not a code property.** With the default
params a single operator holding more than ~54.7% of stake can reconstruct the key ALONE and
decrypt every ciphertext locally the moment it sees the ciphertext's `A` (even from the mempool).
The auditor should treat "the validator set is sufficiently decentralized (no operator/coalition
near the threshold, and operators are Sybil-distinct)" as an **explicit assumption**, and note
that the feature provides NO confidentiality on a concentrated set. (Limonata's own testnet is
currently stake-concentrated; mainnet decentralization is the resolution, not a patch.)

---

## 4. Architecture pointers

- Threshold scheme: `x/encmempool/threshold/threshold.go` (hash-DH / threshold-ElGamal over
  secp256k1). Key = `KDF(x·A)`; shares `d_i = x_i·A`; DLEQ proofs in `x/encmempool/dkg/proof.go`.
- Ciphertext ingress: `x/encmempool/keeper/msg_server.go` `SubmitEncrypted` (validates A is a
  point, nonce length, body size, admission caps, and a submitter-bound **PoK of r** — the same-A
  replay binding).
- DKG round machine: `x/encmempool/keeper/dkg.go` + `endblock.go` (open/finalize/rekey).
- Vote-extension DKG: `evmd/dkg_voteext.go` (ExtendVote builds dealings/complaints/shares;
  VerifyVoteExtension bounds them; PrepareProposal injects the H-1 extended commit;
  ProcessProposal self-certifies ≥2/3; PreBlock `ConsumeVoteExtensions` ingests deterministically).
- Decrypt: `keeper/abci.go` `decryptMatured` (BeginBlock; bounded scan + fair-share + grace defer).
- **Decrypt→execute re-injection** (EncExecEnabled): `keeper/evm_exec.go` `executeDecryptedTx` — a
  "mini-ante" that replicates the EVM ante's fee-buy + nonce + balance checks that
  `evmkeeper.ApplyTransaction` bypasses, runs per-tx on a cache context with a cumulative block-gas
  ceiling, and NEVER emits plaintext. See `DESIGN_EVM_REINJECTION.md`.

---

## 5. KNOWN OPEN residuals — where to spend audit budget

These are already-identified and (where noted) deliberately deferred. Please VERIFY the reasoning
and assess severity; do not re-report them as new without engaging the rationale.

1. **Topology / whale (see §3) — fundamental; now FAIL-CLOSED.** A stake-dominant operator decrypts
   alone; no code can create confidentiality against a legitimately key-holding whale (math, not a
   bug). What is now enforced: `SubmitEncrypted` FAILS CLOSED (`CommitteeConcentrationBreached`) when
   a committee member owns >= the reconstruction threshold of eval-points, refusing to accept a
   "confidential" submission a whale would read rather than lie. Actual confidentiality still requires
   stake decentralization. Auditor: verify the concentration test + that the fail-closed is honest.

2. **Offline-victim dealer poisoning — DETECTED + attributed; auto-rekey scoped.** The in-window
   complaint channel misses a dealer that poisons a validator OFFLINE for the whole complaint window.
   Now: `dkgnode.DetectPoisonedDealers` runs the Feldman check POST-finalization at derive time, so a
   returning victim attributes the poison to the specific dealer (logged for operator action); the
   DLEQ backstop prevents corruption and the health rekey (16 strands) recovers liveness
   automatically. REMAINING (scoped, not built): the AUTOMATIC post-final exclusion->rekey — tractable
   and Byzantine-safe by reusing the existing framing-resistant justified complaint (a false complaint
   fails the on-chain VerifyShare), but a consensus-gating + rekey change that needs its own review
   cycle (the class that regressed the HIGH-2 repro before). Refs: `dkgnode/enckey.go`
   DetectPoisonedDealers, `evmd/dkg_voteext.go` buildDkgComplaints.

3. **Sybil encrypted-submit spam — now PRICED (bond + partial burn).** Admission stays per-submitter
   (a global cap re-introduces one-address censorship). The cost is a bond (`EncSubmitBond`/
   `EncSubmitBondDenom`, gov param, default 0) that `SubmitEncrypted` escrows and `releaseEncTx`
   returns - PLUS a burn fraction `EncSubmitBondBurnBps` (0..10000): on release the module BURNS
   `bond*bps/10000` and refunds the rest, so every submit costs a real, non-refundable amount a
   funded swarm cannot recover (a pure refundable bond is only a capital-lockup bar). Amounts are
   stamped on the EncTx (immune to a param change). Auditor: verify escrow is all-or-nothing, every
   release path burns+refunds, and the burn cannot exceed the bond. Refs: `keeper/msg_server.go`,
   `keeper/keeper.go` refundBond.

4. **Proposer can omit DKG vote-extension injection — ABCI++ dilemma (DESIGN, unresolved).** A
   proposer may inject nothing on its own blocks. A non-proposer in ProcessProposal does NOT have
   H-1's extended commit (only the proposer does, via PrepareProposal's LocalLastCommit), so it
   CANNOT independently tell a censoring proposer from one that genuinely had no extensions -
   requiring injection would false-reject legitimately-empty blocks and risk a HALT. Mitigation:
   DKG progresses on any NON-censored proposer's blocks and the deal/complaint windows + auto-retry
   tolerate censored slots, so a minority of censoring proposers delays but does not stall DKG. A
   hard fix needs a protocol change (persisted extended-commit view or a slashing signal). Refs:
   `evmd/dkg_voteext.go` wrapDkgProcessProposal.

7. **Node-local secret-scalar ops use variable-time (NonConst) EC mul — side-channel (LOW).** Share
   proving / decryption (`threshold/threshold.go`, `dkg/proof.go`) use `ScalarMultNonConst` /
   `ScalarBaseMultNonConst` with SECRET scalars. Not a remote/consensus break, but a validator
   key/share timing side-channel on a shared or observable host. The decred secp256k1 lib exposes
   only NonConst variants, so a true constant-time fix needs a different EC backend - scoped as a
   library-level change, not a local patch. Operator mitigation: run validators on dedicated hosts.

8. **`EncExecEnabled=false` user submits — now REFUSED (round-10 #4).** SubmitEncrypted rejects a
   user submission while execution is off (a matured ciphertext would be decrypted + consumed
   without executing = silent user-tx loss). The keeper decrypt path still runs inert for bring-up
   via direct SubmitEncTx. Refs: `keeper/msg_server.go`.

5. **Genesis DKG-state serialization — DONE (was §6).** ExportGenesis/InitGenesis now round-trip
   the full DKG/threshold state (EncSeq, EncTx, shares, DkgRounds, dealings, ActiveKeys, epochs,
   enc-key registrations); the ref-counts are RECOMPUTED from the imported EncTx set (never
   carried) so they are always consistent. The export panic is removed. Verify the round-trip +
   ref-count consistency in `keeper/genesis.go` + `keeper/audit_genesis_roundtrip_test.go`.
   (Ephemeral state - caches, streaks, submit-rate, complaints, rotation cooldowns - is
   intentionally not carried; it self-rebuilds after import.)

6. **Decrypt→execute: precompile isolation + ante-bypass — CLOSED (round-11 #1 deep fix).** The
   re-injection now runs the decrypted tx under `WithBlockedPrecompiles`, so a new EVM call hook
   (`GetPrecompileBlockingCallHook`) rejects a call whose recipient is a precompile at ANY depth
   (the hook fires on every Call/CallCode/Delegate/Static frame before the precompile is installed) -
   a sub-call via a contract/constructor is blocked exactly like a top-level `To`. It also applies
   the net-seller cap (`NetCapChecker`) to a decrypted native value transfer, matching the
   `NetCapEVMDecorator` the BeginBlock path bypasses. Verify: `x/vm/keeper` GetPrecompileBlockingCallHook
   + TestGetPrecompileBlockingCallHook, `keeper/evm_exec.go`, e2e `precompile_call_blocked`. (EncExec
   remains a large surface - executing attacker EVM in BeginBlock - and still needs the external firm
   before enable, but the specific isolation/bypass HIGH is closed.)

**Already fixed (do not re-report; verify if you wish):** DLEQ nonce/index binding (key-extraction),
same-A replay via PoK-of-r, early decrypt-share exposure (maturity gate), VE-decode DoS,
share/deal write-once (first-wins), admission-cap-disable, stale-stake rekey defaults, committee×
share-budget→MaxTxBytes coupling, cache-context panic rollback, the re-injection fee/nonce/gas
correctness (fee-collector conservation, reverted-create nonce bump, per-tx + block gas caps,
TxIndex isolation, blob-tx reject), genesis DKG-state round-tripping with recomputed ref-counts,
vote-extension shape caps enforced on the AUTHORITATIVE consume path (not only gossip-time
VerifyVoteExtension), the ExtendVote adversary moved behind the `dkgattack` build tag (production
binary gets a no-op), PoK chain-id domain separation (cross-chain/fork replay), the fail-closed
whale guard on submits, the refundable anti-sybil submit bond, ingest-verified-share DLEQ de-dup,
derive-time offline-victim poison detection + attribution, exec-off submit refusal (no silent
user-tx loss), the decrypted-exec cumulative-gas de-overshoot (deferred, no tx loss), the submit-
bond partial burn (real anti-sybil cost), the genesis Verified-trust hole (imported shares are
never trusted as pre-verified; recovery re-verifies), PoK verification ordered LAST among the
CheckTx rejection gates (cheap gates reject doomed spam before the EC verify), and rejection of a
zero-scalar enc key.

**Operator note (spam defaults + MaxTxBytes):** the encrypted path is off by default. When enabling
it: (a) set a non-zero `EncSubmitBond` + `EncSubmitBondBurnBps` and a `MaxInFlightEncTx` sized to the
fleet - the defaults are permissive and the bond+burn is the economic anti-sybil lever; (b) the DKG
committee/share-budget coupling assumes the chain's consensus `MaxTxBytes >= ~20MB` - a chain set
lower MUST size `dkg_max_members`/`dkg_share_budget` down, or the injected vote-extension commit will
not fit and DKG will not progress (the runtime fallback is safe - no injection, not a halt - but the
round stalls); (c) `MaxVerifyOpsPerBlock` cannot be tuned below `max(256, S)` (a single ciphertext
needs up to S verifications) - lower S to lower per-block cost.

**Round-12 hardening (all in the default/production binary):** env vars can no longer drive
encmempool consensus state - the `ENCMEMPOOL_FORCE_UPGRADE`/`ENCMEMPOOL_ACTIVATION` path is behind
the `encmempoolforce` build tag; the production binary compiles a no-op, so activation is only the
deterministic baked GOV path (was a CRITICAL app-hash-divergence footgun). The legacy trusted-setup
decrypt path is now Byzantine-safe (combination recovery accepts only the GCM-authenticated share
set). RevealTx caps its payload + salt. The max DKG phase window is 10k blocks (was 100k), bounding
a stuck-round freeze to hours. applyEncMempoolInit validates params before writing them.

The former duplicate-DLEQ perf item is FIXED: an ingest-`Verified` flag on `EncShare` lets the
decrypt-path recover skip re-verifying VE-sourced shares (index-range + dedup guards still apply;
legacy-tx shares stay re-verified). Refs: `keeper/abci.go` recoverSharedSecret, `dkg/proof.go`
RecoverVerifiedWithKeys preVerified.

---

## 6. Genesis DKG-state serialization — IMPLEMENTED

Done (see residual #5 above). `keeper/genesis.go` serializes `EncSeq`, `EncTx`, `EncShare`,
`DkgRound`, `Dealing`, `ActiveThresholdKey`, epochs, and `EncPubKey` registrations; recomputes the
`GlobalEncCount`/`SubmitterEncCount`/`EpochEncCount` ref-counts from the imported EncTx set on
import; and skips ephemeral/self-rebuilding state. The consistency guarantee is asserted by
`keeper/audit_genesis_roundtrip_test.go` (state + every recomputed ref-count match the source).

---

## 7. Build & test

Toolchain: this repo builds with the Go at `~/go-sdk/bin/go` (GOROOT `~/go-sdk`). VCS stamping is
off in this environment — pass `-buildvcs=false`.

```
export PATH=$HOME/go-sdk/bin:$PATH
go build -buildvcs=false ./...                 # root module
(cd evmd && go build -buildvcs=false ./...)    # evmd module (separate go.mod)

go test -buildvcs=false ./x/encmempool/...     # unit + keeper suites (~2 min for keeper)
(cd evmd && go test -buildvcs=false ./tests/encmempool/...)  # decrypt→execute e2e on the full app
```

Two Go modules: root `github.com/cosmos/evm` and `evmd` (`github.com/cosmos/evm/evmd`).

Notes:
- The `evmd/tests/integration` + `evmd/tests/ibc` suites require `-tags=test` (they panic in
  `EVMConfigurator.ResetTestConfig` otherwise). The encmempool suites do not.
- The ExtendVote adversary is compiled ONLY with `-tags dkgattack` (throwaway/audit builds). A
  production binary must be built WITHOUT that tag, so the adversary is a no-op.

---

## 8. Suggested audit focus order

1. §3 topology assumption — is the trust model stated correctly, and is the confidentiality claim
   honest about the stake precondition?
2. The DKG soundness: dealing/complaint/finalize, QUAL selection, share derivation, the DLEQ proofs
   (`x/encmempool/dkg/`), and the vote-extension consume path's determinism.
3. `EncExecEnabled` re-injection (`keeper/evm_exec.go`) — the fee/nonce round-trip vs the real EVM
   ante, and residual #6 (precompile sub-calls) — this is the most halt-critical code.
4. The open residuals §5 (2/3/4) — are the deferrals sound, and what is the right mechanism?
