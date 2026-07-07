// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package evmd

import (
	"bytes"
	"math/bits"
	"sort"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"

	encmempooldkg "github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	encmempoolkeeper "github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// TRANSPARENT in-node DKG — ABCI++ vote-extension wiring (the hardest consensus
// surface in the repo). A validator that simply RUNS THE BINARY participates in the
// DKG automatically: its node attaches its dealing / decryption shares / enc-key
// announcement to its consensus pre-commit vote (ExtendVote), CometBFT signs+tags it
// with the node's consensus identity, the proposer injects the H-1 ExtendedCommitInfo
// as a block-data pseudo-tx, ProcessProposal self-certifies it (ValidateVoteExtensions),
// and a PreBlocker deterministically consumes it into module state. No daemon, no
// account, no fees, no manual key registration.
//
// DORMANCY: every handler is a strict no-op unless the module params say DkgEnabled &&
// DkgTransparent AND CometBFT vote extensions are enabled (VoteExtensionsEnableHeight, a
// consensus param). So the default binary behaves EXACTLY as before — the gov kill-switch
// keeps the whole surface off.
// ============================================================================

// veInjectMarker prefixes the injected ExtendedCommitInfo pseudo-tx so ProcessProposal /
// PreBlock can recognize + strip it. A real protobuf-encoded sdk.Tx never begins with 0x00
// (protobuf field 0 is invalid), so this cannot collide with a genuine tx.
var veInjectMarker = []byte("\x00LIMO-DKG-VE\x00")

// isVeInjectMarkerTx reports whether txBytes is the transparent-DKG injected ExtendedCommitInfo
// pseudo-tx. The tx decoder uses it to reject the pseudo-tx EXPLICITLY (DKG-5) so it is never run as a
// normal tx — instead of relying on it happening to fail protobuf decode (a future tx type could break
// that). No genuine tx can begin with the NUL-prefixed marker, so this rejects nothing real.
func isVeInjectMarkerTx(txBytes []byte) bool {
	return bytes.HasPrefix(txBytes, veInjectMarker)
}

// veActive reports whether the transparent in-node DKG is switched on FOR THIS HEIGHT. It
// requires BOTH switches: the module params (DkgEnabled && DkgTransparent) AND CometBFT
// vote extensions active at this height (the consensus param VoteExtensionsEnableHeight).
//
// HIGH-1: keying only off the module params (as before) let governance flip DkgTransparent
// on while vote extensions were not enabled at the CometBFT level. ProcessProposal would then
// require/self-certify an injected commit whose extension signatures ValidateVoteExtensions
// cannot validate for a VE-disabled height -> every validator REJECTs -> chain HALT. Coupling
// veActive to the consensus param EXACTLY as baseapp.ValidateVoteExtensions gates (via
// VoteExtEnabledAt: enableHeight != 0 && height > enableHeight) makes every handler a strict
// no-op until VE is genuinely active, so flipping the module param on can never halt.
func (app *EVMD) veActive(ctx sdk.Context) bool {
	p := app.EncMempoolKeeper.GetParams(ctx)
	if !p.DkgEnabled || !p.DkgTransparent {
		return false
	}
	cp := app.GetConsensusParams(ctx)
	if cp.Abci == nil {
		return false
	}
	return encmempooltypes.VoteExtEnabledAt(cp.Abci.VoteExtensionsEnableHeight, ctx.BlockHeight())
}

// myOperator resolves THIS node's validator operator address for the transparent DKG. It
// reads the node's consensus address from <home>/config/priv_validator_key.json ONCE
// (node-local, no consensus obligation), then maps it to the operator via staking (a
// committed, deterministic read). It returns "" when the node is not a resolvable bonded
// validator (a full node, or staking not yet aware of it), in which case the node simply
// does not participate. This is what lets a node self-identify by OPERATOR — its real
// consensus identity — instead of by a spoofable enc-key match (HIGH-4), and sign an
// operator-bound proof-of-possession for its announced enc key (HIGH-2).
func (app *EVMD) myOperator(ctx sdk.Context) string {
	app.dkgConsAddrOnce.Do(func() {
		if app.dkgHome == "" {
			return
		}
		app.dkgConsAddr, _ = dkgnode.LoadConsAddress(app.dkgHome)
	})
	if len(app.dkgConsAddr) == 0 {
		return ""
	}
	val, err := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(app.dkgConsAddr))
	if err != nil {
		return ""
	}
	return val.GetOperator()
}

// encKey lazily loads (or, on first boot, generates+persists) the node's secp256k1 DKG
// enc key from <home>/dkg_enc_key.json. Errors degrade to non-participation (nil), never a
// halt — a node that cannot key itself simply contributes nothing.
func (app *EVMD) encKey() *dkgnode.EncKey {
	app.dkgEncKeyOnce.Do(func() {
		if app.dkgHome == "" {
			return
		}
		app.dkgEncKey, app.dkgEncKeyErr = dkgnode.LoadOrCreateEncKey(app.dkgHome)
	})
	return app.dkgEncKey
}

// ---- ExtendVote: attach this node's DKG contribution to its pre-commit vote ----

func (app *EVMD) dkgExtendVoteHandler() sdk.ExtendVoteHandler {
	return func(ctx sdk.Context, _ *abci.RequestExtendVote) (*abci.ResponseExtendVote, error) {
		empty := &abci.ResponseExtendVote{VoteExtension: []byte{}}
		if !app.veActive(ctx) {
			return empty, nil
		}
		ek := app.encKey()
		if ek == nil {
			return empty, nil // no key => no participation (never halt)
		}
		op := app.myOperator(ctx)
		if op == "" {
			return empty, nil // can't resolve our operator => can't self-identify / prove PoP
		}
		k := app.EncMempoolKeeper
		// Announce the enc key WITH an operator-bound proof-of-possession (HIGH-2/HIGH-4): the
		// consume path rejects an announcement whose PoP does not prove we hold this key under
		// this operator, so a node cannot claim another validator's observed public key.
		ve := encmempooltypes.VoteExtension{
			EncPubKey:    ek.Pub,
			EncPubKeyPoP: encmempooldkg.SignEncKeyPoP(ek.Priv, op),
		}

		// Dealing for the currently-open round, if I am a member and have not dealt yet.
		// Self-identify by OPERATOR (not by enc-key match) so a colliding key can't misindex us.
		if cur := k.GetCurrentEpoch(ctx); cur > 0 {
			if round, ok := k.GetDkgRound(ctx, cur); ok &&
				round.Status == encmempooltypes.DkgStatusOpen &&
				uint64(ctx.BlockHeight()) <= round.DealDeadline {
				if idx := encmempooltypes.MemberIndexByOperator(round.Members, op); idx != 0 {
					if _, dealt := k.GetDealing(ctx, round.Epoch, idx); !dealt {
						if d, err := dkgnode.BuildDealing(round.Epoch, round.Members, idx, int(round.Threshold)); err == nil {
							ve.Dealing = d
						}
					}
				}
			}
		}

		// Decryption shares for not-yet-matured ciphertexts I can serve.
		ve.Shares = app.buildDecryptShares(ctx, ek, op)

		// Justified complaints against QUAL-candidate dealers, ONLY inside the complaint window
		// (after dealing closes, before finalize). The share-validity gate: I open each other
		// dealer's enc-share to a point I own and, on a bad/missing share, emit a framing-resistant
		// complaint so finalizeRound disqualifies the cheater (HIGH-2 / HIGH-3). Node-local, so it
		// never touches the app-hash; the consume side re-verifies deterministically.
		if cur := k.GetCurrentEpoch(ctx); cur > 0 {
			if round, ok := k.GetDkgRound(ctx, cur); ok &&
				round.Status == encmempooltypes.DkgStatusOpen &&
				uint64(ctx.BlockHeight()) > round.DealDeadline &&
				uint64(ctx.BlockHeight()) <= round.ComplaintDeadline {
				ve.Complaints = app.buildDkgComplaints(ctx, ek, op, round)
			}
		}
		// ENV-GATED, ExtendVote-ONLY adversary (throwaway audit builds only; strict no-op unless a
		// DKG_HOLD_FILE / DKG_CHAFF9 env var is set). Mutates only THIS node's node-local vote-extension
		// share list — no committed state, so app-hash stays identical to the honest binary.
		ve.Shares = app.dkgAttackShares(ctx, op, ve.Shares)

		return &abci.ResponseExtendVote{VoteExtension: encmempooltypes.MarshalVoteExtension(ve)}, nil
	}
}

// buildDecryptShares produces this node's DLEQ-proved decryption shares for in-flight
// ciphertexts of epochs it holds shares for — both NOT-YET-MATURED ones and matured ones
// still inside the keeper's bounded decrypt-deferral window (cycle-3 H-B: a matured
// ciphertext short of t shares is deferred up to StrandedDecryptGraceBlocks before its loud
// drop, so late shares from a recovering validator must keep being served or the deferral
// could never heal anything). HIGH-3: on the stake-weighted path this node owns a SET of
// Shamir evaluation points, so it contributes ONE decryption share per owned point per
// ciphertext. The per-epoch shares X_p are derived once from COMMITTED dealings + the
// epoch's QUAL set, then reused.
//
// CYCLE-3 M-2: the per-extension share cap is COUPLED to the share budget S
// (params.VoteExtShareCap() = max(256, S)): a member may own up to ALL S points of one
// ciphertext, so a fixed cap below S would leave a high-stake member unable to ever ship a
// complete share set (liveness break); the coupled cap still bounds the extension because
// validation bounds S itself (<= 2048, sized against VoteExtMaxBytes).
func (app *EVMD) buildDecryptShares(ctx sdk.Context, ek *dkgnode.EncKey, op string) []encmempooltypes.VoteExtShare {
	k := app.EncMempoolKeeper
	h := uint64(ctx.BlockHeight())
	shareCap := k.GetParams(ctx).VoteExtShareCap()
	// Serve from the start of the deferral window, not from the current height: entries
	// below h that are still stored are exactly the matured-but-deferred ones awaiting
	// shares (decrypted entries have left state). Already-recorded shares are deduped by
	// the consume path (first-wins per eval point), so re-serving is idempotent.
	from := uint64(0)
	if h > encmempoolkeeper.StrandedDecryptGraceBlocks {
		from = h - encmempoolkeeper.StrandedDecryptGraceBlocks
	}
	shareByEpoch := map[uint64]*sharedCache{}
	var out []encmempooltypes.VoteExtShare
	k.IterateInFlightFrom(ctx, from, shareCap, func(e encmempooltypes.EncTx) bool {
		if len(out) >= shareCap {
			return false // vote-extension share budget reached
		}
		if e.Epoch == 0 {
			return true // legacy trusted-setup path is not served by the in-node DKG
		}
		sc := shareByEpoch[e.Epoch]
		if sc == nil {
			sc = app.deriveEpochShares(ctx, ek, op, e.Epoch)
			shareByEpoch[e.Epoch] = sc
		}
		if !sc.ok {
			return true // not a member / not finalized: nothing to contribute
		}
		// C2 (MARGINAL supply, HIGH-T-skew fix): emit only owned points NOT already stored on-chain,
		// and skip a ciphertext already at threshold. This stops a high-stake member (a whale — the
		// ~70%-VP validator case) from re-burning its per-VE budget re-serving shares already stored on
		// a saturated OLDEST ciphertext, so it advances to the grace-critical ciphertexts BEHIND it
		// instead of being throttled to ~1 ct/block. All reads are committed-state, so honest nodes
		// converge on the same marginal, oldest-first schedule. (Node-local ExtendVote: app-hash-invariant.)
		stored := k.CollectShares(ctx, e.DecryptHeight, e.Seq)
		if ak, okk := k.GetActiveKey(ctx, e.Epoch); okk && int(ak.Threshold) > 0 && len(stored) >= int(ak.Threshold) {
			return true // threshold-complete: it will decrypt; no marginal work needed
		}
		storedIdx := make(map[uint64]bool, len(stored))
		for i := range stored {
			storedIdx[stored[i].Index] = true
		}
		for _, sh := range sc.shares {
			if len(out) >= shareCap {
				break
			}
			if storedIdx[sh.Index] {
				continue // this owned point is already stored on-chain; do not re-serve it (marginal)
			}
			d, proof, err := dkgnode.ProveShareFor(sh, e.A)
			if err != nil {
				continue
			}
			out = append(out, encmempooltypes.VoteExtShare{
				Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
				Index: sh.Index, D: d, Proof: proof,
			})
		}
		return true
	})
	return out
}

type sharedCache struct {
	ok     bool
	shares []threshold.Share
}

func (app *EVMD) deriveEpochShares(ctx sdk.Context, ek *dkgnode.EncKey, op string, epoch uint64) *sharedCache {
	k := app.EncMempoolKeeper
	round, ok := k.GetDkgRound(ctx, epoch)
	if !ok {
		return &sharedCache{}
	}
	idx := encmempooltypes.MemberIndexByOperator(round.Members, op)
	if idx == 0 {
		return &sharedCache{}
	}
	// Resolve THIS node's owned evaluation points from the round (its stake-allocated share
	// indices; a single point == its Index on the unweighted path).
	var myPoints []uint64
	for _, m := range round.Members {
		if m.Index == idx {
			myPoints = m.OwnedEvalPoints()
			break
		}
	}
	if len(myPoints) == 0 {
		return &sharedCache{}
	}
	ak, ok := k.GetActiveKey(ctx, epoch)
	if !ok {
		return &sharedCache{} // round not finalized yet
	}
	dealings := map[uint64]encmempooltypes.Dealing{}
	k.IterateDealings(ctx, epoch, func(d encmempooltypes.Dealing) { dealings[d.DealerIndex] = d })
	shares, err := dkgnode.DeriveShares(myPoints, ek.Priv, ak.Qual, dealings)
	if err != nil {
		return &sharedCache{}
	}
	return &sharedCache{ok: true, shares: shares}
}

// buildDkgComplaints is the share-validity DETECTOR: for each OTHER dealer, it opens the enc-share
// the dealer sealed to a point THIS node owns and runs the Feldman VerifyShare; a bad (inconsistent
// with the dealer's public commitments, unopenable) or MISSING share yields a framing-resistant
// justified complaint (SharedPoint = encPriv·A_p + a DLEQ binding it to my EncPubKey and to point p).
// This is the accountless complaint channel that populates finalizeRound's disq set so a byzantine
// QUAL-candidate dealer is excluded (HIGH-2 / HIGH-3). It runs in ExtendVote (node-local): the list
// changes only this node's own signed vote extension, never committed state, so the app-hash is
// identical across nodes; IngestComplaintFromVE re-verifies every complaint deterministically before
// it can affect QUAL. Bounded to <= one complaint per other dealer (the first owned point it mistreats).
func (app *EVMD) buildDkgComplaints(ctx sdk.Context, ek *dkgnode.EncKey, op string, round encmempooltypes.DkgRound) []encmempooltypes.VoteExtComplaint {
	k := app.EncMempoolKeeper
	myIdx := encmempooltypes.MemberIndexByOperator(round.Members, op)
	if myIdx == 0 {
		return nil // not a member of this round
	}
	var myPoints []uint64
	for _, m := range round.Members {
		if m.Index == myIdx {
			myPoints = m.OwnedEvalPoints()
			break
		}
	}
	if len(myPoints) == 0 {
		return nil
	}
	var out []encmempooltypes.VoteExtComplaint
	for _, m := range round.Members {
		d := m.Index
		if d == myIdx {
			continue // never complain about myself
		}
		dealing, ok := k.GetDealing(ctx, round.Epoch, d)
		if !ok {
			continue // dealer has not dealt (yet): nothing to check
		}
		commitments, err := encmempooldkg.ParseCommitmentPoints(dealing.Commitments)
		if err != nil {
			continue // malformed commitments are a structural fault caught at ingest; skip here
		}
		for _, p := range myPoints { // one complaint per dealer: the first owned point it mistreats
			var enc *encmempooltypes.DkgStoredEncShare
			for i := range dealing.EncShares {
				if dealing.EncShares[i].MemberIndex == p {
					enc = &dealing.EncShares[i]
					break
				}
			}
			if enc == nil {
				// no share dealt to a point I own -> disqualifying NO-DEAL complaint (no crypto).
				out = append(out, encmempooltypes.VoteExtComplaint{Epoch: round.Epoch, Against: d, EvalPoint: p})
				break
			}
			ct := &threshold.Ciphertext{A: enc.A, Nonce: enc.Nonce, Body: enc.Body}
			s, derr := encmempooldkg.DecryptShareFrom(ek.Priv, p, ct)
			if derr == nil && encmempooldkg.VerifyShare(commitments, p, s) {
				continue // valid share at this point -> nothing to complain about
			}
			// bad / unopenable share at a point I own -> build the DLEQ-proved complaint.
			ds, proof, perr := encmempooldkg.ProveDecryptShare(threshold.Share{Index: p, Xi: ek.Priv}, &threshold.Ciphertext{A: enc.A})
			if perr != nil {
				continue // cannot prove (malformed A); the no-deal/structural path covers it at ingest
			}
			out = append(out, encmempooltypes.VoteExtComplaint{
				Epoch: round.Epoch, Against: d, EvalPoint: p,
				SharedPoint: ds.D, DleqProof: encmempooldkg.MarshalDLEQProof(proof),
			})
			break
		}
	}
	return out
}

// ---- VerifyVoteExtension: lenient structural check (heavy validation is on-chain) ----

func (app *EVMD) dkgVerifyVoteExtensionHandler() sdk.VerifyVoteExtensionHandler {
	return func(ctx sdk.Context, req *abci.RequestVerifyVoteExtension) (*abci.ResponseVerifyVoteExtension, error) {
		accept := &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_ACCEPT}
		reject := &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}
		if len(req.VoteExtension) == 0 {
			return accept, nil // a non-participating node is fine
		}
		if len(req.VoteExtension) > encmempooltypes.VoteExtMaxBytes {
			return reject, nil // oversized: refuse (bounds block size — preserves VE <= 1 MiB)
		}
		ve, ok := encmempooltypes.UnmarshalVoteExtension(req.VoteExtension)
		if !ok {
			return reject, nil // undecodable: refuse
		}
		// CYCLE-8 SHARE-COUNT CAPS (HIGH-A/HIGH-B, defense-in-depth ahead of the authoritative PreBlock
		// bound): bytes-only bounding let one member pack a 1-MiB extension with THOUSANDS of decryption
		// shares, each an O(t) DLEQ verification on the PreBlock consensus path — a halt-class stall. Two
		// honest-safe structural caps let a peer refuse a padded extension EARLY, before it is ever
		// injected/consumed:
		//   PER-VE:  an honest extension carries at most VoteExtShareCap == max(256, S) shares total (the
		//            exact cap buildDecryptShares stops at), so a larger count is padding.
		//   PER-CIPHERTEXT: an operator owns at most S eval points, so it can owe at most S shares for any
		//            one (decryptHeight, seq); more than S at a single ciphertext is padding. Using S (the
		//            budget upper-bounds every operator's owned-point count) keeps this a pure param check
		//            that never needs the round, so it can NEVER drop an honest vote.
		// Both are non-binding LOCAL filters — the DETERMINISTIC, authoritative bound (bounded oldest-first
		// processed-ciphertext set + per-VE cap + per-(operator,ciphertext) verify budget == owned points +
		// within-block dedup + global O(cap × S) ceiling) is enforced in the keeper's
		// ConsumeVoteExtensions/ingestDecryptSharesBounded. Params are committed
		// consensus state (GetParams falls back to defaults), so both caps are deterministic per height.
		p := app.EncMempoolKeeper.GetParams(ctx)
		if len(ve.Shares) > p.VoteExtShareCap() {
			return reject, nil
		}
		perCiphertext := p.EffectiveShareBudget() // S: the max eval points any single operator can own
		if len(ve.Shares) > perCiphertext {
			perCt := make(map[[2]uint64]int, len(ve.Shares))
			for i := range ve.Shares {
				k := [2]uint64{ve.Shares[i].DecryptHeight, ve.Shares[i].Seq}
				perCt[k]++
				if perCt[k] > perCiphertext {
					return reject, nil // > S shares at one ciphertext: padding, refuse
				}
			}
		}
		// AUDIT FIX (COMPLAINT-COUNT CAP, mirroring the share caps): an honest node emits at most one
		// complaint per OTHER dealer (<= committee size). VerifyVoteExtension otherwise bounds only bytes
		// (VoteExtMaxBytes 1 MiB) — a peer could pack ~20k minimal complaints, each forcing membership /
		// ownership / store-read work on the deterministic PreBlock complaint path. Refuse the padding early.
		if len(ve.Complaints) > p.EffectiveMaxMembers() {
			return reject, nil
		}
		// Everything else (crypto validity, membership, dedup) is enforced deterministically on-chain in
		// ProcessProposal + PreBlock, so accept structurally-valid extensions generously — an honest
		// node's extension always passes, preserving liveness.
		return accept, nil
	}
}

// ---- PrepareProposal: inject the H-1 extended commit ahead of the normal txs ----

func (app *EVMD) wrapDkgPrepareProposal(inner sdk.PrepareProposalHandler) sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
		// Dormant, or CometBFT vote extensions not yet enabled (empty LocalLastCommit) =>
		// behave EXACTLY like the underlying EVM-mempool handler.
		if !app.veActive(ctx) || len(req.LocalLastCommit.Votes) == 0 {
			return inner(ctx, req)
		}
		blob, ok := boundedInjectedCommit(req.LocalLastCommit, req.MaxTxBytes)
		if !ok {
			return inner(ctx, req) // no valid (> 2/3-power) injection fits: fall back cleanly
		}
		// Reserve the blob's bytes so the composed proposal stays within MaxTxBytes.
		sub := *req
		sub.MaxTxBytes = req.MaxTxBytes - int64(len(blob))
		resp, err := inner(ctx, &sub)
		if err != nil {
			return nil, err
		}
		resp.Txs = append([][]byte{blob}, resp.Txs...)
		return resp, nil
	}
}

// marshalInjectedCommit serializes an ExtendedCommitInfo behind the inject marker.
func marshalInjectedCommit(ec abci.ExtendedCommitInfo) ([]byte, error) {
	bz, err := ec.Marshal()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(veInjectMarker)+len(bz))
	out = append(out, veInjectMarker...)
	return append(out, bz...), nil
}

// perVoteMarshalOverhead approximates the protobuf framing bytes per ExtendedVoteInfo (field tags +
// length prefixes for the validator, flag, extension, and signature) — used only to GUIDE which
// extensions to drop; the final trimmed blob is measured exactly before use.
const perVoteMarshalOverhead = 24

// trimCand is one extending vote considered for the injected-commit trim: its index in the commit, its
// consensus voting power, and its approximate marshaled byte cost.
type trimCand struct {
	idx      int
	vp, cost int64
}

// knapsackKeepMaxPower selects the MAX-total-power subset of cands whose byte cost fits `budget`, via an
// exact 0/1-knapsack DP with the byte dimension scaled to knapsackBuckets so the table stays bounded.
// Scaling rounds each cost UP, so a DP-selected subset never exceeds the real budget (the exact marshaled
// size is still re-checked by the caller). This is the backstop two fixed greedy orderings cannot match.
// The round-up leaves a completeness slack of O(N*gran) = O(budget*N/knapsackBuckets) (~1.2% of budget at
// N~=100 kept items) — the caller's TOP-UP pass then reclaims that slack against the REAL budget, so the
// trim is effectively exact. Deterministic; runs only when both greedy passes fell short (rare).
func knapsackKeepMaxPower(cands []trimCand, votesLen int, budget int64) ([]bool, int64) {
	keep := make([]bool, votesLen)
	if len(cands) == 0 || budget <= 0 {
		return keep, 0
	}
	const knapsackBuckets = 8192
	gran := budget/knapsackBuckets + 1 // >= 1: bytes-per-DP-bucket
	B := int(budget / gran)
	sc := make([]int, len(cands))
	for i, c := range cands {
		s := int((c.cost + gran - 1) / gran) // round cost UP -> conservative (never overflow the real budget)
		if s <= 0 {
			s = 1
		}
		sc[i] = s
	}
	// dp[b] = max power with scaled cost <= b; taken[i][b] records item i's inclusion for backtracking
	// (standard 1D-knapsack reconstruction: taken[i][b] reflects the optimum over items 0..i at budget b).
	dp := make([]int64, B+1)
	taken := make([][]bool, len(cands))
	for i := range cands {
		taken[i] = make([]bool, B+1)
		w, v := sc[i], cands[i].vp
		if w > B {
			continue // does not fit even alone
		}
		for b := B; b >= w; b-- {
			if dp[b-w]+v > dp[b] {
				dp[b] = dp[b-w] + v
				taken[i][b] = true
			}
		}
	}
	var keptVP int64
	b := B
	for i := len(cands) - 1; i >= 0; i-- {
		if taken[i][b] {
			keep[cands[i].idx] = true
			keptVP += cands[i].vp
			b -= sc[i]
		}
	}
	return keep, keptVP
}

// boundedInjectedCommit returns the marker-prefixed blob for the injected extended commit, and whether a
// usable one was built. HIGH-2: if the FULL commit already fits under maxTxBytes it is used as-is. Else it
// TRIMS — keeping the highest-STAKE vote extensions up to ~7/8 of maxTxBytes and marking the rest Absent
// (dropping only their extension) — so the blob fits AND the kept extensions still carry > 2/3 of the FULL
// committed power (ValidateVoteExtensions counts every present vote toward totalVP, so a dropped-to-Absent
// vote still counts; we can therefore shed only a < 1/3-stake minority's bloat, which is exactly the
// minority-bloat stall this defends). If > 2/3 of the extensions cannot be made to fit, it returns
// (nil,false) and the caller falls back to no injection — never a partial/forged commit. The dropped
// dealings/shares are simply re-carried and consumed on a later block within their window. Proposer-local:
// a wrong choice only yields a rejected proposal (ProcessProposal re-runs ValidateVoteExtensions), never a
// fork.
func boundedInjectedCommit(ec abci.ExtendedCommitInfo, maxTxBytes int64) ([]byte, bool) {
	if blob, err := marshalInjectedCommit(ec); err == nil && int64(len(blob)) < maxTxBytes {
		return blob, true
	}
	budget := maxTxBytes - maxTxBytes/8 // reserve ~1/8 of the block for normal txs
	if budget <= int64(len(veInjectMarker)) {
		return nil, false
	}
	votes := ec.Votes
	var totalVP int64
	for i := range votes {
		totalVP += votes[i].Validator.Power
	}
	if totalVP <= 0 {
		return nil, false
	}
	requiredVP := (totalVP*2)/3 + 1

	// Only a COMMIT vote carrying a valid (non-empty) extension + signature is usable; everything else
	// becomes Absent (it could not pass ValidateVoteExtensions as a committed-but-unextended vote).
	cands := make([]trimCand, 0, len(votes))
	for i := range votes {
		v := votes[i]
		if v.BlockIdFlag != cmtproto.BlockIDFlagCommit || len(v.VoteExtension) == 0 || len(v.ExtensionSignature) == 0 {
			continue
		}
		cands = append(cands, trimCand{
			idx:  i,
			vp:   v.Validator.Power,
			cost: int64(len(v.VoteExtension)+len(v.ExtensionSignature)) + perVoteMarshalOverhead,
		})
	}
	// Greedily fill the budget in a given order, returning which votes to keep and their total power.
	greedy := func(order []trimCand) ([]bool, int64) {
		keep := make([]bool, len(votes))
		used := int64(len(veInjectMarker))
		var keptVP int64
		for _, c := range order {
			if used+c.cost > budget {
				continue // over budget: dropped (marked Absent below)
			}
			used += c.cost
			keep[c.idx] = true
			keptVP += c.vp
		}
		return keep, keptVP
	}
	addr := func(c trimCand) []byte { return votes[c.idx].Validator.Address }
	// This is a byte-budgeted maximize-power 0/1 knapsack: keep a subset of extensions that FITS the budget
	// and carries > 2/3 power. FAST PATH — try two cheap deterministic greedy orderings that resolve the
	// common shapes: (1) VP-per-byte DENSITY desc drops low-density bloat (any stake) in favor of many cheap
	// honest extensions (closes the high-stake-cartel bloat); (2) raw POWER desc keeps a single large
	// high-power extension a density fill could skip (closes the near-whale). AUDIT: two fixed greedy
	// orderings cannot be COMPLETE for 0/1 knapsack (a config exists where the optimal 2/3 subset requires
	// DROPPING the highest-power item, which no forward greedy does), so a knapsack DP backstop below finds
	// any fitting > 2/3 subset the greedies miss — no adversarial size-padding can force a false stall.
	byDensity := append([]trimCand(nil), cands...)
	sort.SliceStable(byDensity, func(a, b int) bool {
		l, r := byDensity[a], byDensity[b]
		// l.vp/l.cost > r.vp/r.cost via a 128-bit cross-multiply (overflow-safe even at CometBFT-max power,
		// unlike a plain int64 vp*cost), integer + deterministic. vp >= 0 and cost >= 1, so the uint64 casts
		// are exact.
		lhi, llo := bits.Mul64(uint64(l.vp), uint64(r.cost))
		rhi, rlo := bits.Mul64(uint64(r.vp), uint64(l.cost))
		if lhi != rhi {
			return lhi > rhi
		}
		if llo != rlo {
			return llo > rlo
		}
		return bytes.Compare(addr(l), addr(r)) < 0
	})
	keep, keptVP := greedy(byDensity)
	if keptVP < requiredVP {
		byPower := append([]trimCand(nil), cands...)
		sort.SliceStable(byPower, func(a, b int) bool {
			l, r := byPower[a], byPower[b]
			if l.vp != r.vp {
				return l.vp > r.vp
			}
			return bytes.Compare(addr(l), addr(r)) < 0
		})
		keep, keptVP = greedy(byPower)
	}
	if keptVP < requiredVP {
		// KNAPSACK BACKSTOP: 0/1-knapsack DP (bytes scaled to a coarse budget dimension) finding the
		// max-power subset within the budget, so a fitting > 2/3 subset the greedies miss is still found.
		// Runs only when both greedies fell short (adversarial/rare). Its round-up scaling slack is
		// reclaimed by the TOP-UP below; the exact marshaled size is re-checked before use. Deterministic.
		keep, keptVP = knapsackKeepMaxPower(cands, len(votes), budget-int64(len(veInjectMarker)))
	}
	// TOP-UP (reclaim the DP's round-up scaling slack, and fill any leftover budget in a greedy path so more
	// dealings are consumed per block): greedily add still-dropped extensions HIGHEST-POWER first that fit
	// the REAL remaining budget. This makes the trim effectively EXACT — the DP scales costs UP by up to
	// N*gran, and this adds back exactly the items that rounding excluded but genuinely fit. Real byte costs.
	usedReal := int64(len(veInjectMarker))
	dropped := make([]trimCand, 0, len(cands))
	for _, c := range cands {
		if keep[c.idx] {
			usedReal += c.cost
		} else {
			dropped = append(dropped, c)
		}
	}
	sort.SliceStable(dropped, func(a, b int) bool {
		if dropped[a].vp != dropped[b].vp {
			return dropped[a].vp > dropped[b].vp
		}
		return bytes.Compare(addr(dropped[a]), addr(dropped[b])) < 0
	})
	for _, c := range dropped {
		if usedReal+c.cost <= budget {
			keep[c.idx] = true
			keptVP += c.vp
			usedReal += c.cost
		}
	}
	if keptVP < requiredVP {
		return nil, false // no > 2/3 subset fits the budget: fall back to no injection (never a partial commit)
	}

	trimmed := ec
	trimmed.Votes = make([]abci.ExtendedVoteInfo, len(votes))
	for i := range votes {
		v := votes[i]
		if !keep[i] {
			v.BlockIdFlag = cmtproto.BlockIDFlagAbsent
			v.VoteExtension = nil
			v.ExtensionSignature = nil
		}
		trimmed.Votes[i] = v
	}
	blob, err := marshalInjectedCommit(trimmed)
	if err != nil || int64(len(blob)) >= maxTxBytes {
		return nil, false // approximation under-counted: fall back rather than overflow
	}
	return blob, true
}

// ---- ProcessProposal: self-certify the injected extended commit, then delegate ----

func (app *EVMD) wrapDkgProcessProposal(inner sdk.ProcessProposalHandler) sdk.ProcessProposalHandler {
	reject := func() (*abci.ResponseProcessProposal, error) {
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
	}
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		if len(req.Txs) == 0 || !bytes.HasPrefix(req.Txs[0], veInjectMarker) {
			// No injected blob: normal proposal. (First block after enable, or a proposer
			// that had no extensions.) Delegate unchanged.
			return inner(ctx, req)
		}
		// An injected blob is only legitimate while the transparent path is active.
		if !app.veActive(ctx) {
			return reject()
		}
		var ext abci.ExtendedCommitInfo
		if err := ext.Unmarshal(req.Txs[0][len(veInjectMarker):]); err != nil {
			return reject()
		}
		// SELF-CERTIFY: every extension signature must verify against its validator's consensus
		// key and the set must carry >= 2/3 voting power (else a proposer could inject forged /
		// partial extensions). Deterministic (reads consensus params + last commit + staking).
		if err := baseapp.ValidateVoteExtensions(ctx, app.StakingKeeper, req.Height, ctx.ChainID(), ext); err != nil {
			return reject()
		}
		// Validate the REMAINING txs exactly as the underlying handler would.
		sub := *req
		sub.Txs = req.Txs[1:]
		return inner(ctx, &sub)
	}
}

// ---- PreBlock: deterministically consume the injected extended commit ----

// consumeDkgVoteExtensions is invoked from app.PreBlocker BEFORE module PreBlock/BeginBlock/
// EndBlock, so enc-key announcements, dealings, and decryption shares are all in committed
// state before the DKG EndBlocker opens/finalizes and before BeginBlock decrypts. It resolves
// each extension's CONSENSUS address to an OPERATOR via staking (deterministic committed read)
// and hands the resolved pairs to the keeper's canonicalizing consume path.
func (app *EVMD) consumeDkgVoteExtensions(ctx sdk.Context, txs [][]byte) {
	if len(txs) == 0 || !bytes.HasPrefix(txs[0], veInjectMarker) || !app.veActive(ctx) {
		return
	}
	var ext abci.ExtendedCommitInfo
	if err := ext.Unmarshal(txs[0][len(veInjectMarker):]); err != nil {
		return
	}
	entries := make([]encmempoolkeeper.VEEntry, 0, len(ext.Votes))
	for _, v := range ext.Votes {
		// Only votes actually committed carry a usable, signed extension.
		if v.BlockIdFlag != cmtproto.BlockIDFlagCommit || len(v.VoteExtension) == 0 {
			continue
		}
		ve, ok := encmempooltypes.UnmarshalVoteExtension(v.VoteExtension)
		if !ok {
			continue
		}
		val, err := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(v.Validator.Address))
		if err != nil {
			continue
		}
		entries = append(entries, encmempoolkeeper.VEEntry{Operator: val.GetOperator(), VE: ve})
	}
	app.EncMempoolKeeper.ConsumeVoteExtensions(ctx, entries)
}
