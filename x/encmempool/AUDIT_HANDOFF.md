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

1. **Topology / whale (see §3) — NOT a code bug.** A stake-dominant operator decrypts alone.
   Resolution = stake decentralization + (optionally) a fail-closed round-open VP-cap that refuses
   to provide false confidentiality when too concentrated. Auditor input on the VP-cap design is
   welcome.

2. **Offline-victim dealer poisoning — reactive-only (DESIGN).** Complaints are produced only by
   the affected validator during the complaint window; a dealer that poisons shares for an
   OFFLINE validator survives into QUAL. Mitigation is REACTIVE: DLEQ verification drops bad
   partials on the decrypt path, and a decrypt-health streak (now 16 stranded maturities, lowered
   from 32) force-rekeys. The STRUCTURAL fix (proactive derive-time Feldman verification, "the
   belt") was **attempted and reverted** — it broke the HIGH-2 complaint repro and the DLEQ
   backstop already prevents silent corruption. Refs: `evmd/dkg_voteext.go` buildDkgComplaints,
   `dkgnode/enckey.go:177,216`, `keeper/endblock.go` decryptHealthStrandThreshold.

3. **Sybil encrypted-submit spam — needs an ECONOMIC mechanism (DESIGN).** Admission is
   per-submitter (4/block) by DELIBERATE choice: a global cap re-introduces one-address
   censorship/DoS. A funded Sybil set can keep the per-block DLEQ-verify budget saturated. The
   complete fix is a stake/price ingress gate (a mechanism with UX implications), not a constant —
   a design decision for Limonata, informed by this audit. Refs: `keeper/msg_server.go` +
   `keeper/keeper.go:356`.

4. **Proposer can omit DKG vote-extension injection — ABCI++ dilemma (DESIGN).** A proposer may
   inject nothing on its blocks without failing consensus (injection is opportunistic; a proposer
   with no extensions and a censoring one are indistinguishable at Txs[0]). Making injection
   consensus-required has a real liveness cost. Refs: `evmd/dkg_voteext.go` wrapDkgProcessProposal.

5. **Genesis is not DKG-state-capable — SAFE today, SCOPED work (see §6).** ExportGenesis PANICS
   (loud, no corruption) if encrypted txs are in flight; genesis carries only params/commits/
   pending, not the DKG round/key/registrations/EncTx/shares/refcounts. **In-place upgrades (the
   normal Cosmos path, which keeps the full KV store) are UNAFFECTED.** Only a genesis-export
   migration with in-flight ciphertexts is blocked. The full serialization is scoped in §6.

6. **Decrypt→execute: precompile sub-call isolation is half-built (EncExecEnabled only).** The
   re-injection rejects a tx whose TOP-LEVEL `To` is a precompile, but a tx calling an ordinary
   contract that SUB-CALLs a precompile still reaches it, from the BeginBlock context (which runs
   before staking/distribution/gov BeginBlockers). No confirmed non-deterministic fork was found
   (precompiles are deterministic since DeliverTx runs them), but the isolation guarantee is not
   complete. Close with a call-hook/tracer that rejects any precompile touch, OR a per-precompile
   determinism audit, before enabling `EncExecEnabled`. Refs: `keeper/evm_exec.go` GetPrecompileInstance.

**Already fixed (do not re-report; verify if you wish):** DLEQ nonce/index binding (key-extraction),
same-A replay via PoK-of-r, early decrypt-share exposure (maturity gate), VE-decode DoS,
share/deal write-once (first-wins), admission-cap-disable, stale-stake rekey defaults, committee×
share-budget→MaxTxBytes coupling, cache-context panic rollback, and the re-injection fee/nonce/gas
correctness (fee-collector conservation, reverted-create nonce bump, per-tx + block gas caps,
TxIndex isolation, blob-tx reject).

---

## 6. `#5` genesis DKG-state serialization — scoped spec (if commissioned)

The safe interim is the export panic + "in-place upgrade only". A full implementation must:
- **Serialize (add to `GenesisState`):** `EncSeq` (0x05), all `EncTx` (0x06), all `EncShare`
  (0x07), all `DkgRound` (0x10), all `Dealing` (0x11), all `ActiveThresholdKey` (0x13),
  `CurrentEpoch` (0x14), `ActiveEpoch` (0x15), all `EncPubKey` registrations (0x1A + rebuild the
  0x1B reverse index on import).
- **RECOMPUTE on import (never export — consistency):** all EncTx ref-counts —
  `GlobalEncCount` (0x18), `SubmitterEncCount` (0x19), `EpochEncCount` (0x16) — by iterating the
  imported EncTx set; and the commit ref-counts (0x23/0x24) from the imported Commits.
- **Skip (ephemeral / self-rebuilding):** complaints (0x12), last-rekey height (0x17), complaint
  negative-cache (0x1C), submit-rate (0x1D), share-key cache + cursor (0x1E/0x1F, the recover path
  recomputes on a cache miss), decrypt-strand streak (0x20), rejected-share cache (0x21), key-
  rotation cooldown (0x22).
- **Test:** a round-trip that exports a populated state, imports into a fresh keeper, and asserts
  BOTH the state AND every recomputed ref-count match the source (the consistency guarantee).

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

---

## 8. Suggested audit focus order

1. §3 topology assumption — is the trust model stated correctly, and is the confidentiality claim
   honest about the stake precondition?
2. The DKG soundness: dealing/complaint/finalize, QUAL selection, share derivation, the DLEQ proofs
   (`x/encmempool/dkg/`), and the vote-extension consume path's determinism.
3. `EncExecEnabled` re-injection (`keeper/evm_exec.go`) — the fee/nonce round-trip vs the real EVM
   ante, and residual #6 (precompile sub-calls) — this is the most halt-critical code.
4. The open residuals §5 (2/3/4) — are the deferrals sound, and what is the right mechanism?
