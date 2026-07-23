package keeper

import (
	"errors"
	"fmt"
	"strconv"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// BeginBlock executes matured reveals in deterministic store-key order
// (big-endian commitHeight -> sender -> seq) and garbage-collects stale commits.
//
// All logic lives in BeginBlock so every node computes identical state: there is no
// proposer-only logic and no ABCI++ vote extension. This is the load-bearing reason
// the commit-reveal path is consensus-safe.
//
// SCOPE: the commit-reveal path here is a delay/ordering primitive, NOT encryption -
// its reveal is an ordinary user tx. The anti-MEV encryption layer is the transparent
// validator DKG threshold encryption (live on Limonata testnet 10777), which plugs
// into this exact commit/reveal/execute slot and, with EncExec on, re-injects the
// decrypted tx into the EVM (see decryptMatured / evm_exec.go).
func (k Keeper) BeginBlock(ctx sdk.Context) (err error) {
	// PANIC-GUARD (symmetry with EndBlockDKG): BeginBlock runs inside consensus, so an
	// unrecovered panic here halts the whole chain. The per-ciphertext decrypt path already
	// recovers data-dependent crypto panics; this last-resort top-level recover converts any
	// UNFORESEEN panic (e.g. in the reveal/GC scans) into a contained, DETERMINISTIC event
	// (identical committed state => identical outcome on every node) instead of a halt, and
	// does not propagate the error (a returned BeginBlock error is itself fatal to the chain).
	// AUDIT #6/DKG-3: run inside a BRANCHED cache context, committing only on CLEAN completion, so a
	// recovered panic discards all partial store writes (deterministic clean rollback on every node).
	realCtx := ctx
	cc, write := realCtx.CacheContext()
	ctx = cc
	defer func() {
		if r := recover(); r != nil {
			realCtx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_beginblock_panic",
				sdk.NewAttribute("height", strconv.FormatUint(uint64(realCtx.BlockHeight()), 10)),
				sdk.NewAttribute("reason", fmt.Sprintf("%v", r)),
			))
			err = nil
			return // discard the cache -> roll back every partial write
		}
		write() // write() flushes the cache store AND forwards the body's buffered events to realCtx
	}()

	p := k.GetParams(ctx)
	cur := uint64(ctx.BlockHeight())

	// EXTERNAL-REVIEW #7: reclaim past-block submit-rate counter entries (bounded per block) so the
	// per-submitter rate state cannot leak permanently. No-op (empty iterator) when nothing was submitted.
	k.gcEncSubmitRate(ctx, cur)

	// 1. Collect pending reveals into an explicit slice (keys already sorted).
	var pending []types.PendingReveal
	k.IteratePending(ctx, func(pr types.PendingReveal) { pending = append(pending, pr) })

	// 2. Execute matured reveals in deterministic order.
	order := uint64(0)
	for _, pr := range pending {
		if cur < addSat(pr.CommitHeight, p.RevealDelay) {
			continue // not matured (the reveal gate already enforces this; defensive)
		}
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_reveal_executed",
			sdk.NewAttribute("sender", pr.Sender),
			sdk.NewAttribute("commit_height", strconv.FormatUint(pr.CommitHeight, 10)),
			sdk.NewAttribute("seq", strconv.FormatUint(pr.Seq, 10)),
			sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
		))
		order++
		k.DeletePending(ctx, pr.CommitHeight, pr.Sender, pr.Seq)
		k.DeleteCommit(ctx, pr.CommitHeight, pr.Sender, pr.Seq)
	}

	// 3. GC commits that were never revealed within the window (bounded state).
	if p.MaxRevealWindow > 0 {
		var stale []types.Commit
		k.IterateCommits(ctx, func(c types.Commit) {
			if addSat(c.Height, p.MaxRevealWindow) < cur {
				stale = append(stale, c)
			}
		})
		for _, c := range stale {
			k.DeleteCommit(ctx, c.Height, c.Sender, c.Seq)
			k.DeletePending(ctx, c.Height, c.Sender, c.Seq)
		}
	}

	// 4. Threshold-encryption path (OPT-IN). Decrypt + reveal ciphertexts whose
	//    decrypt height is now, when >= t keyper shares are present. Fully
	//    deterministic (identical on every node) — consensus-safe.
	//
	//    KILL-SWITCH SAFE-DISABLE: when the path is LIVE we decrypt as usual. When it was
	//    turned OFF mid-flight (governance flipped EncEnabled/DkgEnabled via MsgUpdateParams)
	//    but EncTx are still in state, those ciphertexts must NOT strand forever —
	//    decryptMatured is the only path that removes an EncTx, and it is gated on the path
	//    being live. SubmitEncrypted already refuses NEW encrypted tx while disabled, so the
	//    in-flight set is finite; drainDisabledEncTx GC's it via the same bounded-scan +
	//    releaseEncTx path (releasing every ref-count and pruning the pinned epoch). The
	//    O(1) count guard keeps this zero-overhead in the default/dormant config.
	if p.EncEnabled && (p.Threshold > 0 || p.DkgEnabled) {
		// Transparent-DKG runtime unavailability is an admission gate, not an immediate
		// in-flight drop. SubmitEncrypted rejects new ciphertexts while vote extensions
		// are inactive or the injected commit cannot fit, so the already-accepted set is
		// finite. Let those entries follow the normal maturity/grace path: decrypt if
		// shares already exist, defer within grace if the outage is temporary, and release
		// loudly after grace if it never heals.
		k.decryptMatured(ctx, cur, p)
	} else if k.GetGlobalEncCount(ctx) > 0 {
		k.drainDisabledEncTx(ctx, cur, p)
	}
	return nil
}

// drainDisabledEncTx GARBAGE-COLLECTS matured in-flight EncTx when the encrypted path is
// DISABLED (the governance kill-switch flipped EncEnabled off, or DkgEnabled off with no
// legacy trusted key to fall back on). Without it, a disable would STRAND every already-
// submitted ciphertext forever: decryptMatured is the only remover of an EncTx and is gated
// on the path being live, so a disabled module would never decrypt AND never GC those
// entries — leaking EncTx state, the global/per-submitter ref-counts, and the pinned
// per-epoch DkgRound + ActiveThresholdKey indefinitely (a strand + unbounded-state fault).
//
// It mirrors decryptMatured's SAFETY INVARIANTS exactly, minus the decrypt attempt:
//   - BOUNDED SCAN: at most maxDecryptScanPerBlock matured entries per block (O(cap), NOT
//     O(backlog)) via CollectMaturedUpTo, so even a huge backlog drains over several blocks
//     without unbounded per-block work — the DROP->DEFER HIGH-fix is preserved.
//   - CLEAN RELEASE: every entry goes through releaseEncTx (delete EncTx + its shares, dec
//     the global/per-submitter/epoch ref-counts, maybePruneEpoch), so the HIGH-2 epoch
//     ref-count invariant is never re-leaked.
//   - DETERMINISTIC: a pure function of committed state, identical on every node.
//
// Only MATURED entries (decrypt_height <= cur) are drained; immature ones are drained on the
// block they mature. Since no new EncTx are admitted while disabled and DecryptDelay is
// bounded, the in-flight set fully drains within a bounded number of blocks — no permanent
// strand. GC (not decrypt) is the correct kill-switch semantics: the module is being turned
// OFF (in-flight ciphertexts are not executed on the way out), so shedding them
// with a loud event is the clean, non-stranding outcome.
func (k Keeper) drainDisabledEncTx(ctx sdk.Context, cur uint64, _ types.Params) {
	matured, truncated := k.CollectMaturedUpTo(ctx, cur, maxDecryptScanPerBlock)
	for _, e := range matured {
		ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_enc_drained_disabled",
			sdk.NewAttribute("submitter", e.Submitter),
			sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
			sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
			sdk.NewAttribute("height", strconv.FormatUint(cur, 10))))
		k.releaseEncTx(ctx, e)
	}
	if truncated {
		ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_drain_deferred",
			sdk.NewAttribute("height", strconv.FormatUint(cur, 10)),
			sdk.NewAttribute("scan_truncated", strconv.FormatBool(truncated))))
	}
}

// decryptMatured combines shares to decrypt every EncTx maturing at height cur, in
// deterministic (seq) order, and emits the decrypted-body event (proving decryption).
// When EncExec is enabled it also re-injects the decrypted RLP EVM tx and executes it
// in this deterministic order — decoding the tx and running it through x/vm's state
// transition + ante/gas/nonce accounting inside BeginBlock, bounded by a per-block gas
// ceiling (see evm_exec.go / executeDecryptedTx). With EncExec off, the decrypted-body
// event is the seam the execution step plugs into.
//
// On the DKG path (e.Epoch > 0) it routes through dkg.RecoverVerified: each keyper's
// partial is checked against its public share key (recomputed from the epoch's DKG
// commitments) via the stored DLEQ proof, so a malicious keyper's bad partial is
// DROPPED WITH ATTRIBUTION instead of silently corrupting the Lagrange combine. On
// the legacy path (epoch 0) it uses the unverified threshold.Recover as before.
const (
	// maxDecryptAttemptsPerBlock caps the threshold-recovery ATTEMPTS (each up to t DLEQ
	// verifications + a Lagrange combine) performed at a single height. It is the per-block
	// decrypt budget, fair-shared across submitters. Far above any legitimate per-block
	// volume, so normal operation never reaches it.
	maxDecryptAttemptsPerBlock = 2048
	// maxDecryptScanPerBlock caps how many matured EncTx are MATERIALIZED (scanned +
	// unmarshalled) per block. Set a small multiple above the decrypt budget so the block
	// still sees enough distinct submitters to fair-share, while guaranteeing the per-block
	// scan is O(cap) — NOT O(backlog). This closes the DROP->DEFER regression, where the old
	// "scan the whole matured backlog every block" grew unbounded under a flood. Anything
	// beyond this window stays in state and drains on a later block (deterministic suffix).
	maxDecryptScanPerBlock = 2 * maxDecryptAttemptsPerBlock
	// absMaxInFlightEncTx is the ALWAYS-ON absolute ceiling on in-flight EncTx. Even with
	// param admission disabled (Params.MaxInFlightEncTx == 0), decryptMatured sheds matured
	// entries above this with a loud, deterministic drop, so 'bounded state under flood'
	// holds unconditionally.
	absMaxInFlightEncTx = 1 << 20
	// maxCeilingDropsPerBlock bounds the last-resort drops per block so shedding excess is
	// itself O(cap) work, never an O(backlog) burst.
	maxCeilingDropsPerBlock = maxDecryptScanPerBlock
	// strandedDecryptGraceBlocks (cycle-3 H-B, non-silent drop): a matured ciphertext whose
	// shares are still short of t is DEFERRED — kept in state, re-attempted every block — for
	// up to this many blocks past its decrypt height before it is finally dropped with the
	// LOUD encmempool_decrypt_stranded event. Rationale: shares arrive via vote extensions /
	// keyper txs and can lag a few blocks behind maturity (validator restarts, the per-VE
	// share cap rationing a backlog), so an immediate drop silently loses a ciphertext the
	// committee was one block away from decrypting. The deferral is BOUNDED (grace, then a
	// releaseEncTx drop — never a strand), consistent with every flood-hardening rule: the
	// per-block scan stays O(cap) (deferred entries sit at the head of the bounded
	// CollectMaturedUpTo window), ref-counts stay intact while deferred, the final drop goes
	// through releaseEncTx (H2: epoch ref-count + maybePruneEpoch), and the always-on ceiling
	// drop still sheds excess regardless of grace. ~64s at 2s blocks.
	strandedDecryptGraceBlocks = 32
	// maxDeferredDecryptsPerBlock CAPS how many matured-but-short ciphertexts may be DEFERRED
	// (kept in state within their StrandedDecryptGrace window awaiting late shares) in a single
	// block. It bounds the concurrently-deferred set: once this many entries defer in a block,
	// any FURTHER shortfall is dropped IMMEDIATELY (loud encmempool_decrypt_deferral_capped,
	// H2-safe via releaseEncTx) instead of deferred.
	//
	// WHY (cycle-5): the grace deferral keeps short ciphertexts in state for up to 32 blocks. The
	// scan (CollectMaturedUpTo) and the vote-extension share serving (buildDecryptShares, from
	// h-grace) both process the (decryptHeight, seq) keyspace OLDEST-FIRST, so deferred entries —
	// being the oldest matured — sit at the HEAD of both windows. Without a cap, a flood of
	// ciphertexts that mature short (a broken/lagging committee, or an attacker spraying an epoch
	// that cannot reach t) would pile up unboundedly at that head and STARVE fresh healthy
	// ciphertexts of both the O(cap) decrypt scan (maxDecryptScanPerBlock) and the per-VE share
	// budget (VoteExtShareCap >= voteExtShareFloor). Capping the deferred set to a constant well
	// below BOTH windows guarantees the deferred head can never monopolize either. Under a flood
	// only the OLDEST maxDeferredDecryptsPerBlock short ciphertexts get their full grace; the
	// rest drop at once (loud, ref-counts released). Normal operation (a handful of transiently-
	// late ciphertexts) never approaches the cap, so behavior there is byte-identical.
	maxDeferredDecryptsPerBlock = 128
)

// MaxDeferredDecryptsPerBlock exposes the per-block deferral cap for regression tests (they
// assert the concurrently-deferred set never exceeds this under a backlog flood).
const MaxDeferredDecryptsPerBlock = maxDeferredDecryptsPerBlock

// StrandedDecryptGraceBlocks exposes the bounded decrypt-deferral window for the app layer
// (vote-extension share serving must keep serving matured-but-deferred ciphertexts) and for
// regression tests.
const StrandedDecryptGraceBlocks = strandedDecryptGraceBlocks

// MaxDecryptAttemptsPerBlock exposes the per-block decrypt budget for regression tests
// (they assert the per-block drain equals exactly this cap under a flood).
const MaxDecryptAttemptsPerBlock = maxDecryptAttemptsPerBlock

func (k Keeper) decryptMatured(ctx sdk.Context, cur uint64, p types.Params) {
	// BOUNDED SCAN: materialize at most maxDecryptScanPerBlock matured ciphertexts (decrypt
	// height <= cur), in deterministic (decryptHeight, seq) order, INCLUDING any deferred from
	// a prior block. Capping the scan is what keeps per-block cost O(cap), not O(backlog) — a
	// flood can no longer force every node to re-scan the whole matured backlog each block.
	matured, truncated := k.CollectMaturedUpTo(ctx, cur, maxDecryptScanPerBlock)

	// LAST-RESORT CEILING DROP (defense-in-depth BENEATH ingress admission). If in-flight
	// EncTx exceeds the effective absolute ceiling, shed the excess NEWEST scanned entries
	// (tail of the window — keeps the oldest / most-overdue ciphertexts for decryption) with
	// a LOUD, DETERMINISTIC event, bounded per block. This holds 'bounded state under flood'
	// even if admission was bypassed (e.g. a genesis import or a governance-lowered ceiling).
	// CRITICAL: every drop goes through releaseEncTx, which decEpochEncCount + maybePruneEpoch,
	// so a drop can never re-leak the epoch ref-count (that would regress the HIGH-2 fix).
	ceiling := uint64(absMaxInFlightEncTx)
	if p.MaxInFlightEncTx > 0 && p.MaxInFlightEncTx < ceiling {
		ceiling = p.MaxInFlightEncTx
	}
	if global := k.GetGlobalEncCount(ctx); global > ceiling {
		drop := int(global - ceiling)
		if drop > maxCeilingDropsPerBlock {
			drop = maxCeilingDropsPerBlock
		}
		if drop > len(matured) {
			drop = len(matured)
		}
		for i := 0; i < drop; i++ {
			e := matured[len(matured)-1-i] // newest scanned dropped first
			ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_enc_dropped_ceiling",
				sdk.NewAttribute("submitter", e.Submitter),
				sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
				sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
				sdk.NewAttribute("in_flight", strconv.FormatUint(global, 10)),
				sdk.NewAttribute("ceiling", strconv.FormatUint(ceiling, 10))))
			k.releaseEncTx(ctx, e)
		}
		matured = matured[:len(matured)-drop]
	}

	// ANTI-STARVATION FAIRNESS: fair-share the per-block decrypt budget across submitters via
	// a deterministic round-robin so one flooder cannot starve honest ciphertexts (which would
	// break the anti-MEV liveness property). When the matured set fits the budget EVERY entry
	// is selected — no reordering and no loss under normal load; the round-robin only rations
	// the budget under a flood.
	selected := selectFairDecrypts(matured, maxDecryptAttemptsPerBlock)

	// Process the SELECTED entries in the original (decryptHeight, seq) order — the anti-MEV
	// execution ordering is unchanged; fairness only decides WHICH subset drains this block.
	//
	// PASS 1 (attempt + terminal outcomes): attempt each selected ciphertext. Anything with a
	// TERMINAL outcome this block — decrypted, hard error, or a share-shortfall whose grace has
	// EXPIRED — is finalized here (released with its loud event). A share-shortfall still WITHIN
	// its grace is NOT resolved yet: it becomes a CANDIDATE for one of the bounded, fairly-shared
	// defer slots decided in PASS 2, so an attacker cannot monopolize the heal grace.
	order := uint64(0)
	processed := 0
	type deferCand struct {
		e          types.EncTx
		have, need int
	}
	var candidates []deferCand // matured-but-short, within grace — awaiting a fair defer slot
	// EVM re-injection (P2): decrypted txs execute this block up to a cumulative gas ceiling. When
	// on and the budget is spent, we STOP processing further matured ciphertexts — they stay in
	// state (ref-counts intact) and drain on a later block (the deterministic bounded-scan suffix),
	// never dropped. execGasUsed is updated by the success branch below.
	execOn := k.encExecEnabled(p.EncExecEnabled)
	execCeiling := decryptExecGasCeiling(ctx)
	var execGasUsed uint64
	for i := range matured {
		if !selected[i] {
			continue // fairness-deferred to a later block (still in state, ref-counts intact)
		}
		if execOn && execGasUsed >= execCeiling {
			break // decrypted-tx exec budget exhausted; defer the rest to a later block
		}
		e := matured[i]
		processed++
		// release decides whether this entry LEAVES state in PASS 1. Default true; the within-
		// grace share-shortfall branch flips it to false and records a candidate (resolved in
		// PASS 2). A recovered panic leaves it true, so a malformed entry is still shed and can
		// never wedge the chain into a crash loop.
		release := true
		deferExec := false // round-10 #5: set when a decrypted tx doesn't fit the remaining exec slice
		// CONSENSUS SAFETY: BeginBlock must never panic on data-dependent input, or a single
		// malformed EncTx (e.g. a permissionlessly-submitted ciphertext with an out-of-spec
		// nonce) would halt the whole chain. Process each ciphertext inside a recover guard;
		// any panic is contained and reported, and the ciphertext is released below so a bad
		// entry cannot wedge the chain into a crash loop.
		func(e types.EncTx) {
			defer func() {
				if r := recover(); r != nil {
					release = true
					ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("reason", fmt.Sprintf("panic recovered: %v", r))))
				}
			}()
			shares := k.CollectShares(ctx, e.DecryptHeight, e.Seq)
			shared, need, err := k.recoverSharedSecret(ctx, p, e, shares)
			switch {
			case err == errNotEnoughShares || err == errStakeMinority:
				// CYCLE-3 H-B (NON-SILENT): a matured ciphertext short of t shares/stake is
				// NOT silently dropped. Within the bounded grace it is DEFERRED — kept in
				// state with ref-counts intact, re-attempted next block as late shares land
				// via vote extensions / keyper txs. Past the grace it is dropped LOUDLY with
				// a dedicated stranded event (epoch/height/reason), through releaseEncTx
				// (H2-safe). Deterministic on every node (a pure function of committed
				// state + height).
				if cur >= addSat(e.DecryptHeight, strandedDecryptGraceBlocks) {
					ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_stranded",
						sdk.NewAttribute("submitter", e.Submitter),
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
						sdk.NewAttribute("height", strconv.FormatUint(cur, 10)),
						sdk.NewAttribute("have", strconv.Itoa(len(shares))),
						sdk.NewAttribute("need", strconv.Itoa(need)),
						sdk.NewAttribute("reason", err.Error())))
					k.bumpDecryptStrandStreak(ctx, e.Epoch) // MED-2: sustained per-epoch streak triggers a recovery rekey
					return                                  // release stays true
				}
				// Within grace: candidate for a bounded, fairly-shared defer slot (PASS 2).
				release = false
				candidates = append(candidates, deferCand{e: e, have: len(shares), need: need})
			case err != nil:
				ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("reason", err.Error())))
			default:
				plaintext, derr := threshold.Decrypt(shared, &threshold.Ciphertext{A: e.A, Nonce: e.Nonce, Body: e.Body})
				if derr != nil {
					ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("reason", derr.Error())))
					return // release stays true -> the ciphertext is consumed
				}
				k.resetDecryptStrandStreak(ctx, e.Epoch) // MED-2: this epoch decrypts -> clear its strand streak

				// CRITICAL (review #1): NEVER emit the plaintext - a public reveal lets a searcher
				// front-run. Either EXECUTE the decrypted EVM tx (P2, atomically in this block before
				// normal txs, so its position is already fixed and no one can front-run it) or, when the
				// execution path is off, consume it and record only that decryption happened (length,
				// never content).
				if !execOn {
					ctx.EventManager().EmitEvent(sdk.NewEvent(
						"encmempool_decrypted",
						sdk.NewAttribute("submitter", e.Submitter),
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
						sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
						sdk.NewAttribute("plaintext_len", strconv.Itoa(len(plaintext))),
						sdk.NewAttribute("executed", "false"),
					))
					order++
					return
				}

				// P2: execute on a PER-TX cache context with an isolated gas meter, so a reverted/
				// failed tx rolls back cleanly and one tx's meter reset cannot corrupt the block meter.
				// Commit only when the tx was actually included (executed==true, revert included).
				childCtx, commit := ctx.CacheContext()
				// Fresh infinite gas meter (isolate the block meter) + a HIGH, distinct TxIndex per
				// decrypted tx (audit A1): the EVM object store is keyed by TxIndex and reset only at
				// Commit, so running at the default TxIndex 0 would let a decrypted tx's transient
				// gas/sponsor state bleed into the first normal DeliverTx (also TxIndex 0). The base is
				// far above any real per-block tx count so it never collides with normal indices.
				childCtx = childCtx.
					WithGasMeter(storetypes.NewInfiniteGasMeter()).
					WithTxIndex(reinjectTxIndexBase + int(order))
				res := k.executeDecryptedTx(childCtx, plaintext, execCeiling, execCeiling-execGasUsed)
				if res.tag == "gas_deferred" {
					// round-10 #5: doesn't fit this block's remaining slice. KEEP it in state (no
					// release) and stop processing further matured cts this block; it retries next
					// block on a full budget. No overshoot, no user-tx loss.
					release = false
					deferExec = true
					return
				}
				if res.executed {
					commit()
					execGasUsed += res.gasUsed
				}
				ctx.EventManager().EmitEvent(sdk.NewEvent(
					"encmempool_tx_reinjected",
					sdk.NewAttribute("submitter", e.Submitter),
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
					sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
					sdk.NewAttribute("outcome", res.tag),
					sdk.NewAttribute("executed", strconv.FormatBool(res.executed)),
					sdk.NewAttribute("reverted", strconv.FormatBool(res.reverted)),
					sdk.NewAttribute("gas_used", strconv.FormatUint(res.gasUsed, 10)),
					sdk.NewAttribute("tx_hash", res.txHash),
				))
				order++
			}
		}(e)
		// Release the ciphertext + shares + ALL ref-counts (global, per-submitter, and — for a
		// DKG epoch — the epoch ref-count, pruning the epoch the instant it drains). HIGH-2 safe.
		// A within-grace share-shortfall candidate (release=false) is resolved in PASS 2; its
		// FINAL drop (grace expiry, deferral-cap shed, ceiling shed, or the kill-switch drain)
		// always goes through releaseEncTx — never a silent strand or leak.
		if release {
			k.releaseEncTx(ctx, e)
		}
		if deferExec {
			break // round-10 #5: exec slice full for this block; the rest stay in state (ref-counts intact)
		}
	}

	// PASS 2 (BOUNDED + FAIR DEFERRAL): grant up to maxDeferredDecryptsPerBlock defer slots to
	// the within-grace candidates, FAIR-SHARED across submitters via the same deterministic
	// round-robin the decrypt budget uses. This bounds the concurrently-deferred set (so it can
	// never monopolize the O(cap) decrypt scan or the per-VE share-serving budget) AND stops an
	// attacker who floods short spam (low seqs, the head of the window) from consuming every
	// heal slot and denying grace to honest ciphertexts. Candidates NOT granted a slot are
	// dropped NOW — LOUDLY (encmempool_decrypt_deferral_capped) and through releaseEncTx (H2:
	// ref-counts released + epoch pruned) — so nothing is silently lost. Granted candidates stay
	// in state (ref-counts intact) and are re-attempted next block. Deterministic on every node.
	if len(candidates) > 0 {
		candTx := make([]types.EncTx, len(candidates))
		for j, c := range candidates {
			candTx[j] = c.e
		}
		granted := selectFairDecrypts(candTx, maxDeferredDecryptsPerBlock)
		for j, c := range candidates {
			if granted[j] {
				ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_missed",
					sdk.NewAttribute("seq", strconv.FormatUint(c.e.Seq, 10)),
					sdk.NewAttribute("have", strconv.Itoa(c.have)),
					sdk.NewAttribute("need", strconv.Itoa(c.need)),
					sdk.NewAttribute("deferred_until", strconv.FormatUint(addSat(c.e.DecryptHeight, strandedDecryptGraceBlocks), 10))))
				continue // kept in state within its grace
			}
			// Over the per-block deferral cap: drop NOW (loud, H2-safe) rather than defer, so
			// the deferred backlog stays bounded. A distinct event lets operators tell a
			// backlog-flood shed apart from a genuine grace-expiry strand.
			ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_deferral_capped",
				sdk.NewAttribute("submitter", c.e.Submitter),
				sdk.NewAttribute("seq", strconv.FormatUint(c.e.Seq, 10)),
				sdk.NewAttribute("epoch", strconv.FormatUint(c.e.Epoch, 10)),
				sdk.NewAttribute("height", strconv.FormatUint(cur, 10)),
				sdk.NewAttribute("have", strconv.Itoa(c.have)),
				sdk.NewAttribute("need", strconv.Itoa(c.need)),
				sdk.NewAttribute("cap", strconv.Itoa(maxDeferredDecryptsPerBlock)),
				sdk.NewAttribute("reason", "deferred-set cap reached; dropped to bound backlog")))
			k.releaseEncTx(ctx, c.e)
		}
	}

	// Anything not processed this block (fairness-deferred, or beyond the bounded scan window)
	// is CARRIED, not dropped — deterministic on every node. Emit a defer signal so operators
	// can watch a backlog drain.
	if deferred := len(matured) - processed; truncated || deferred > 0 {
		ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_deferred",
			sdk.NewAttribute("height", strconv.FormatUint(cur, 10)),
			sdk.NewAttribute("deferred", strconv.Itoa(deferred)),
			sdk.NewAttribute("scan_truncated", strconv.FormatBool(truncated))))
	}
}

// selectFairDecrypts picks up to `budget` indices of `matured` to decrypt this block,
// fair-sharing the budget across distinct submitters via a deterministic round-robin
// (layer 0 = each submitter's first pending ciphertext, layer 1 = each submitter's second,
// …). When len(matured) <= budget every index is selected (fast path: no rationing under
// normal load). Deterministic: submitter order is first-appearance within the (decryptHeight,
// seq)-ordered matured slice, identical on every node. Cost is O(len(matured)) <= O(scan
// window) = O(cap).
func selectFairDecrypts(matured []types.EncTx, budget int) []bool {
	sel := make([]bool, len(matured))
	if len(matured) <= budget {
		for i := range sel {
			sel[i] = true
		}
		return sel
	}
	order := make([]string, 0)
	queues := make(map[string][]int)
	for i, e := range matured {
		if _, seen := queues[e.Submitter]; !seen {
			order = append(order, e.Submitter)
		}
		queues[e.Submitter] = append(queues[e.Submitter], i)
	}
	picked := 0
	for picked < budget {
		progressed := false
		for _, s := range order {
			q := queues[s]
			if len(q) == 0 {
				continue
			}
			sel[q[0]] = true
			queues[s] = q[1:]
			picked++
			progressed = true
			if picked >= budget {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return sel
}

var errNotEnoughShares = errors.New("not enough shares")

// errStakeMinority is returned when a DKG-epoch decrypting set clears the COUNT threshold
// but the contributing members hold only a stake MINORITY of the committee (HIGH-3). It is
// treated as a normal (deterministic) decrypt failure, never a halt.
var errStakeMinority = errors.New("decrypting set holds only a stake minority")

// recoverSharedSecret recovers x*A for an EncTx from the collected keyper shares,
// choosing the DKG-verified path (epoch > 0) or the legacy path (epoch 0). It
// returns errNotEnoughShares (with the required count) when < t shares are present.
func (k Keeper) recoverSharedSecret(ctx sdk.Context, p types.Params, e types.EncTx, shares []types.EncShare) (shared *secp256k1.JacobianPoint, need int, err error) {
	if e.Epoch > 0 {
		ak, ok := k.GetActiveKey(ctx, e.Epoch)
		if !ok {
			return nil, 0, errors.New("no active key for epoch")
		}
		need = int(ak.Threshold)
		// CYCLE-7 (fix #2): this count gate — and the memberPresent stake map built below —
		// govern on the DLEQ-VERIFIED share count. On the transparent path that holds BY
		// CONSTRUCTION: IngestDecryptShareFromVE now verifies each share's DLEQ proof BEFORE
		// SetEncShare, so a structurally-valid-but-cryptographically-garbage CHAFF share never
		// enters state — `len(shares)` is exactly the count of verified shares, and every index
		// in memberPresent is backed by a verified share. A coalition can therefore no longer
		// inflate this count past `need` (nor mark itself present) with chaff to sail through
		// both gates and land in RecoverVerified's hard-drop. Any share that somehow reached
		// state without ingest verification is still caught downstream: RecoverVerified drops it
		// and returns ErrInsufficientVerified, which is routed back into this same errNotEnoughShares
		// DEFER path (see the RecoverVerified call site below).
		if len(shares) < need {
			return nil, need, errNotEnoughShares
		}
		// HIGH-3 DEFENSE-IN-DEPTH: the crypto threshold is now a strict >2/3 of eval points.
		// Map each present evaluation point to its owning member and require those members to
		// also hold >2/3 of snapshotted stake, so rounded apportionment cannot make on-chain
		// decryption succeed with a <=2/3-stake set.
		if round, ok := k.GetDkgRound(ctx, e.Epoch); ok && len(round.Members) > 0 {
			memberPresent := make(map[uint64]bool, len(shares))
			for _, s := range shares {
				if owner := types.EvalPointOwner(round.Members, s.Index); owner != 0 {
					memberPresent[owner] = true
				}
			}
			if !DecryptingSetMeetsStake(round.Members, memberPresent) {
				return nil, need, errStakeMinority
			}
		}
		commitments, perr := dkg.ParseCommitmentPoints(ak.PublicCommitments)
		if perr != nil {
			return nil, need, perr
		}
		partials := make([]dkg.VerifiedShare, 0, len(shares))
		// round-9 #5: shares whose DLEQ was already checked at vote-extension ingest carry Verified.
		// RecoverVerifiedWithKeys trusts those (skips the redundant EC verify) while still applying the
		// index-range + dedup guards; legacy/genesis shares (Verified=false) are re-verified.
		preVer := make(map[uint64]bool, len(shares))
		for _, s := range shares {
			proof, perr := dkg.ParseDLEQProof(s.Proof)
			if perr != nil {
				continue // unproven share: RecoverVerified would drop it anyway
			}
			if s.Verified {
				preVer[s.Index] = true
			}
			partials = append(partials, dkg.VerifiedShare{
				Share: &threshold.DecryptShare{Index: s.Index, D: s.D}, Proof: proof,
			})
		}
		// CRIT-3 AUDIT FIX: resolve each partial's public share key Y from the epoch Y-cache
		// (getShareKeyCache, populated at/after finalize for THIS epoch's commitments) instead of an
		// O(t) SharePubKey recompute per partial, so the on-chain combine is O(t), not O(t^2). ak is the
		// e.Epoch key (GetActiveKey above), so the cache and ak.PublicCommitments agree; a cache miss
		// falls back to SharePubKey inside RecoverVerifiedWithKeys, keeping the result identical.
		shared, err = dkg.RecoverVerifiedWithKeys(commitments, e.A, need, partials, func(index uint64) []byte {
			return k.getShareKeyCache(ctx, e.Epoch, index)
		}, func(index uint64) bool { return preVer[index] })
		if errors.Is(err, dkg.ErrInsufficientVerified) {
			// CYCLE-7 (belt-and-suspenders, fix #3): fewer than `need` partials survived DLEQ
			// verification — the SAME healable condition as a raw share shortfall, not a
			// terminal fault. Route it into the WITHIN-GRACE DEFER branch (errNotEnoughShares)
			// so the ciphertext is KEPT and re-attempted as late HONEST shares land, instead of
			// being HARD-DROPPED (encmempool_decrypt_failed). With ingest-time DLEQ verification
			// (IngestDecryptShareFromVE) this is normally UNREACHABLE on the transparent path —
			// every stored share is already verified, so `len(shares) < need` trips
			// errNotEnoughShares above before we get here — but it defends any share that
			// reached state WITHOUT ingest verification (a legacy/declared msg path or a genesis
			// import), so a padded raw count can never convert a healable defer into a drop.
			return nil, need, errNotEnoughShares
		}
		return shared, need, err
	}

	// legacy trusted-setup path
	need = int(p.Threshold)
	if len(shares) < need {
		return nil, need, errNotEnoughShares
	}
	// round-12 #4 (legacy Byzantine safety): the legacy path carries NO per-share DLEQ, so blindly
	// combining the first `need` shares lets ONE Byzantine keyper's bad share yield a wrong key and
	// STRAND the ciphertext. Instead try combinations and accept the one whose AES-GCM decryption
	// AUTHENTICATES (a wrong key fails the GCM tag), tolerating up to len(shares)-need bad shares. The
	// legacy keyper set is small, so the enumeration is bounded; if too large, fall back to first-need.
	shared, ok := k.legacyRecoverRobust(e, shares, need)
	if !ok {
		// We already have >= need shares (checked above), but no combination formed a usable key
		// (e.g. threshold=0/empty, or unparseable shares). This is a genuine failure, NOT a
		// wait-for-more-shares case: return a generic error so decryptMatured consumes it via
		// encmempool_decrypt_failed (no strand), rather than errNotEnoughShares (which would defer).
		return nil, need, errLegacyRecoverFailed
	}
	return shared, need, nil
}

var errLegacyRecoverFailed = errors.New("legacy recover: no usable share combination")

// maxLegacyRecoverCombos bounds the per-ciphertext combination search on the legacy path (round-12
// #4). A legacy trusted-setup keyper set is small (e.g. 3-of-5), so C(n, need) is tiny; above this
// bound the search falls back to the first-`need` shares (best effort) to keep BeginBlock work bounded.
const maxLegacyRecoverCombos = 128

// legacyRecoverRobust returns the threshold shared secret whose AES-GCM decryption of e authenticates,
// searching combinations of `need` shares (round-12 #4). Deterministic: shares are in canonical order
// and threshold.Recover/Decrypt are pure, so every node selects the same combination.
func (k Keeper) legacyRecoverRobust(e types.EncTx, shares []types.EncShare, need int) (*secp256k1.JacobianPoint, bool) {
	if need < 0 || len(shares) < need {
		return nil, false
	}
	ct := &threshold.Ciphertext{A: e.A, Nonce: e.Nonce, Body: e.Body}
	recover := func(idx []int) (*secp256k1.JacobianPoint, bool) {
		ds := make([]*threshold.DecryptShare, len(idx))
		for i, ci := range idx {
			ds[i] = &threshold.DecryptShare{Index: shares[ci].Index, D: shares[ci].D}
		}
		shared, err := threshold.Recover(ds)
		if err != nil {
			return nil, false
		}
		if _, derr := threshold.Decrypt(shared, ct); derr != nil {
			return nil, false // wrong key: GCM tag failed
		}
		return shared, true
	}
	// Too many combinations: best-effort first-`need` (bounds worst-case BeginBlock compute).
	if countCombos(len(shares), need) > maxLegacyRecoverCombos {
		first := make([]int, need)
		for i := range first {
			first[i] = i
		}
		return recover(first)
	}
	comb := make([]int, need)
	var found *secp256k1.JacobianPoint
	var rec func(start, depth int) bool
	rec = func(start, depth int) bool {
		if depth == need {
			if shared, ok := recover(comb); ok {
				found = shared
				return true
			}
			return false
		}
		for i := start; i <= len(shares)-(need-depth); i++ {
			comb[depth] = i
			if rec(i+1, depth+1) {
				return true
			}
		}
		return false
	}
	if rec(0, 0) {
		return found, true
	}
	// No combination AUTHENTICATED. Fall back to the first-`need` shares (the pre-#4 behavior) so the
	// decrypt path runs its normal decrypt-or-fail: a genuinely undecryptable ciphertext (e.g. a
	// malformed nonce, or a wrong body) still fails GRACEFULLY via encmempool_decrypt_failed and is
	// consumed, exactly as before. This never yields a wrong-but-authenticating key - only the GCM-
	// verified combination above is a success; the fallback key is expected to fail decryption.
	first := make([]int, need)
	for i := range first {
		first[i] = i
	}
	ds := make([]*threshold.DecryptShare, need)
	for i, ci := range first {
		ds[i] = &threshold.DecryptShare{Index: shares[ci].Index, D: shares[ci].D}
	}
	shared, err := threshold.Recover(ds)
	if err != nil {
		return nil, false
	}
	return shared, true
}

// countCombos returns C(n, k), capped at maxLegacyRecoverCombos+1 to avoid overflow / needless work.
func countCombos(n, k int) int {
	if k < 0 || k > n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	res := 1
	for i := 0; i < k; i++ {
		res = res * (n - i) / (i + 1)
		if res > maxLegacyRecoverCombos {
			return maxLegacyRecoverCombos + 1
		}
	}
	return res
}
