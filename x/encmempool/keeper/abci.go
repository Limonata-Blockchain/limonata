package keeper

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

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
// the prototype is consensus-safe.
//
// HONESTY: this is a delay/ordering primitive, NOT encryption. "Execute" here means
// the module records the deterministic execution order and emits an event; it does
// not re-inject the payload into the EVM/tx pipeline. The reveal that a user submits
// is itself an ordinary tx. Real MEV resistance requires threshold encryption with
// >= 2 independent keypers, which plugs into this exact commit/reveal/execute slot.
func (k Keeper) BeginBlock(ctx sdk.Context) (err error) {
	// PANIC-GUARD (symmetry with EndBlockDKG): BeginBlock runs inside consensus, so an
	// unrecovered panic here halts the whole chain. The per-ciphertext decrypt path already
	// recovers data-dependent crypto panics; this last-resort top-level recover converts any
	// UNFORESEEN panic (e.g. in the reveal/GC scans) into a contained, DETERMINISTIC event
	// (identical committed state => identical outcome on every node) instead of a halt, and
	// does not propagate the error (a returned BeginBlock error is itself fatal to the chain).
	defer func() {
		if r := recover(); r != nil {
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_beginblock_panic",
				sdk.NewAttribute("height", strconv.FormatUint(uint64(ctx.BlockHeight()), 10)),
				sdk.NewAttribute("reason", fmt.Sprintf("%v", r)),
			))
			err = nil
		}
	}()

	p := k.GetParams(ctx)
	cur := uint64(ctx.BlockHeight())

	// 1. Collect pending reveals into an explicit slice (keys already sorted).
	var pending []types.PendingReveal
	k.IteratePending(ctx, func(pr types.PendingReveal) { pending = append(pending, pr) })

	// 2. Execute matured reveals in deterministic order.
	order := uint64(0)
	for _, pr := range pending {
		if cur < pr.CommitHeight+p.RevealDelay {
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
			if c.Height+p.MaxRevealWindow < cur {
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
// OFF and the PoC never re-injects decrypted bodies into the EVM, so shedding the in-flight
// ciphertexts with a loud event is the clean, non-stranding outcome.
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

// decryptMatured combines keyper shares to decrypt every EncTx maturing at height
// cur, in deterministic (seq) order. PROTOTYPE: it emits the decrypted body as an
// event (proving decryption) rather than re-injecting it into the EVM pipeline.
//
// REMAINING GAP (deferred): re-injecting the decrypted plaintext (an RLP EVM tx) into
// EVM execution. That requires decoding the tx, running it through x/vm's state
// transition + ante/gas/nonce accounting inside BeginBlock in this deterministic
// order — a large, halt-risk pipeline change. It is intentionally NOT done here so
// the multi-node reliability hardening stays build-stable; the decrypted-body event
// is the stable seam a future EVM-injection step plugs into.
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
)

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
	order := uint64(0)
	processed := 0
	for i := range matured {
		if !selected[i] {
			continue // fairness-deferred to a later block (still in state, ref-counts intact)
		}
		e := matured[i]
		processed++
		// CONSENSUS SAFETY: BeginBlock must never panic on data-dependent input, or a single
		// malformed EncTx (e.g. a permissionlessly-submitted ciphertext with an out-of-spec
		// nonce) would halt the whole chain. Process each ciphertext inside a recover guard;
		// any panic is contained and reported, and the ciphertext is released below so a bad
		// entry cannot wedge the chain into a crash loop.
		func(e types.EncTx) {
			defer func() {
				if r := recover(); r != nil {
					ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("reason", fmt.Sprintf("panic recovered: %v", r))))
				}
			}()
			shares := k.CollectShares(ctx, e.DecryptHeight, e.Seq)
			shared, need, err := k.recoverSharedSecret(ctx, p, e, shares)
			switch {
			case err == errNotEnoughShares:
				ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_missed",
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("have", strconv.Itoa(len(shares))),
					sdk.NewAttribute("need", strconv.Itoa(need))))
			case err != nil:
				ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
					sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
					sdk.NewAttribute("reason", err.Error())))
			default:
				plaintext, derr := threshold.Decrypt(shared, &threshold.Ciphertext{A: e.A, Nonce: e.Nonce, Body: e.Body})
				if derr == nil {
					ctx.EventManager().EmitEvent(sdk.NewEvent(
						"encmempool_decrypted",
						sdk.NewAttribute("submitter", e.Submitter),
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
						sdk.NewAttribute("execution_order", strconv.FormatUint(order, 10)),
						sdk.NewAttribute("plaintext_hex", hex.EncodeToString(plaintext)),
					))
					order++
				} else {
					ctx.EventManager().EmitEvent(sdk.NewEvent("encmempool_decrypt_failed",
						sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
						sdk.NewAttribute("reason", derr.Error())))
				}
			}
		}(e)
		// Release the ciphertext + shares + ALL ref-counts (global, per-submitter, and — for a
		// DKG epoch — the epoch ref-count, pruning the epoch the instant it drains). HIGH-2 safe.
		k.releaseEncTx(ctx, e)
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
		if len(shares) < need {
			return nil, need, errNotEnoughShares
		}
		commitments, perr := dkg.ParseCommitmentPoints(ak.PublicCommitments)
		if perr != nil {
			return nil, need, perr
		}
		partials := make([]dkg.VerifiedShare, 0, len(shares))
		for _, s := range shares {
			proof, perr := dkg.ParseDLEQProof(s.Proof)
			if perr != nil {
				continue // unproven share: RecoverVerified would drop it anyway
			}
			partials = append(partials, dkg.VerifiedShare{
				Share: &threshold.DecryptShare{Index: s.Index, D: s.D}, Proof: proof,
			})
		}
		shared, err = dkg.RecoverVerified(commitments, e.A, need, partials)
		return shared, need, err
	}

	// legacy trusted-setup path
	need = int(p.Threshold)
	if len(shares) < need {
		return nil, need, errNotEnoughShares
	}
	ds := make([]*threshold.DecryptShare, 0, need)
	for _, s := range shares[:need] {
		ds = append(ds, &threshold.DecryptShare{Index: s.Index, D: s.D})
	}
	shared, err = threshold.Recover(ds)
	return shared, need, err
}
