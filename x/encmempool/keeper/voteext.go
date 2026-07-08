// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// TRANSPARENT in-node DKG: the deterministic CONSUME half of the ABCI++ vote
// extension pipeline. The app layer (evmd/dkg_voteext.go) verifies the injected
// ExtendedCommitInfo (ValidateVoteExtensions: ext-signatures + >=2/3 power), resolves
// each extension's CONSENSUS address to an OPERATOR via staking, and hands the
// resolved (operator, payload) pairs here. Everything below is a pure function of
// COMMITTED state + those pairs, canonicalized (sorted by operator, deduped, first-
// wins), so every node writes byte-identical state — the #1 fork-safety requirement.
//
// This REPLACES the tx paths (MsgDkgDeal / MsgSubmitDecryptionShare) and the declared
// DkgMembers list with:
//   1. auto-announced enc keys (RecordEncPubKey), so members = bonded validators that
//      simply ran the binary;
//   2. dealings ingested from votes (IngestDealingFromVE);
//   3. decryption shares ingested from votes (IngestDecryptShareFromVE).
// The EndBlockDKG finalize + BeginBlock decrypt paths are UNCHANGED — they already read
// only committed state.
// ============================================================================

// VEEntry is one validator's resolved, signature-verified vote-extension contribution.
// Operator is the valoper the app resolved from the consensus address CometBFT tagged
// the extension with; the app has ALREADY verified the extension signature + 2/3 power
// before constructing these.
type VEEntry struct {
	Operator string
	VE       types.VoteExtension
}

// --- enc-pubkey registration (operator -> announced compressed secp256k1 key) ---

func encPubKeyKey(operator string) []byte { return concat(types.EncPubKeyPrefix, []byte(operator)) }
func encKeyOwnerKey(key []byte) []byte    { return concat(types.EncKeyOwnerPrefix, key) }

// RecordEncPubKey stores a bonded validator's auto-announced DKG enc key IDEMPOTENTLY,
// and only after it PROVES OWNERSHIP and passes CROSS-OPERATOR UNIQUENESS (HIGH-2/HIGH-4):
//
//   - IDEMPOTENT: a no-op when the stored key already equals key, so a validator
//     re-announcing the same key every block causes no state churn (and no MembersHash
//     flap). The PoP was already verified when the key was first stored, so the hot
//     re-announce path does no signature work.
//   - PROOF-OF-POSSESSION: a first announce / rotation is rejected unless `pop` is a valid
//     proof that the announcer holds the enc PRIVATE key, bound to `operator`. This stops a
//     validator from announcing another's observed PUBLIC key as its own.
//   - UNIQUENESS: a key already bound to a DIFFERENT operator is rejected, so two operators
//     can never sit in the committee under one key (which would misroute/silence shares).
//
// Deterministic: every read is committed state and every write is first-wins by operator
// (the caller feeds entries in a canonical, operator-sorted order). Returns whether it
// wrote a new/rotated key.
func (k Keeper) RecordEncPubKey(ctx sdk.Context, operator string, key, pop []byte) bool {
	// EXTERNAL-REVIEW #2: key is a 33-byte point (ValidCompressedPoint); cap the PoP too (an honest DER
	// ECDSA proof is ~72 bytes) so an announcement cannot carry a padded multi-KB pop blob.
	if operator == "" || !dkg.ValidCompressedPoint(key) || len(pop) > maxEncKeyPoPBytes {
		return false
	}
	cur, had := k.GetEncPubKey(ctx, operator)
	if had && bytes.Equal(cur, key) {
		return false // idempotent: already registered with this exact key (PoP already proven)
	}
	// PROOF-OF-POSSESSION: only the holder of the enc private key, announcing under its OWN
	// operator, can register (or rotate to) a key.
	if !dkg.VerifyEncKeyPoP(key, operator, pop) {
		return false
	}
	// CROSS-OPERATOR UNIQUENESS: refuse a key already owned by a different operator.
	if owner, ok := k.GetEncKeyOwner(ctx, key); ok && owner != operator {
		return false
	}
	h := uint64(ctx.BlockHeight())
	// EXTERNAL-REVIEW #4 FOLLOW-UP (rekey-churn): MembersHash binds the enc key, so an un-throttled rotation
	// would let ONE Byzantine committee member flap its own key every block to force a member-change
	// re-genesis every round (free, perpetual griefing). Rate-limit a ROTATION (replacing an existing key)
	// per operator: a rotation within encKeyRotationCooldownBlocks is refused (the operator keeps its current
	// key until the cooldown elapses). A FIRST announce is never throttled, and a legitimate rotation (key
	// compromise, rare) simply lands one cooldown later.
	if had {
		if last, ok := k.getEncKeyRotatedHeight(ctx, operator); ok && h < last+encKeyRotationCooldownBlocks {
			return false
		}
		_ = k.store(ctx).Delete(encKeyOwnerKey(cur)) // drop the reverse index for the previous key
	}
	st := k.store(ctx)
	_ = st.Set(encPubKeyKey(operator), append([]byte(nil), key...))
	_ = st.Set(encKeyOwnerKey(key), []byte(operator))
	k.setEncKeyRotatedHeight(ctx, operator, h)
	return true
}

// encKeyRotationCooldownBlocks is the minimum spacing between an operator's enc-key CHANGES. It is well
// above the default round length (deal+complaint windows) so a key rotation cannot out-pace round finalize
// to churn the committee, yet short enough that a legitimate compromise-driven rotation lands within
// minutes at ~2s blocks.
const encKeyRotationCooldownBlocks uint64 = 200

func encKeyRotatedHeightKey(operator string) []byte {
	return concat(types.EncKeyRotatedHeightPrefix, []byte(operator))
}

func (k Keeper) getEncKeyRotatedHeight(ctx sdk.Context, operator string) (uint64, bool) {
	bz, err := k.store(ctx).Get(encKeyRotatedHeightKey(operator))
	if err != nil || len(bz) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(bz), true
}

func (k Keeper) setEncKeyRotatedHeight(ctx sdk.Context, operator string, height uint64) {
	_ = k.store(ctx).Set(encKeyRotatedHeightKey(operator), u64(height))
}

// GetEncKeyOwner returns the operator that owns an announced enc key, if any (the reverse
// index backing the HIGH-2 cross-operator uniqueness check).
func (k Keeper) GetEncKeyOwner(ctx context.Context, key []byte) (string, bool) {
	bz, err := k.store(ctx).Get(encKeyOwnerKey(key))
	if err != nil || len(bz) == 0 {
		return "", false
	}
	return string(bz), true
}

// GetEncPubKey returns a validator's registered enc key, if any.
func (k Keeper) GetEncPubKey(ctx context.Context, operator string) ([]byte, bool) {
	bz, err := k.store(ctx).Get(encPubKeyKey(operator))
	if err != nil || len(bz) == 0 {
		return nil, false
	}
	return bz, true
}

// IterateEncPubKeys visits every registered (operator, enc key) pair.
func (k Keeper) IterateEncPubKeys(ctx context.Context, fn func(operator string, key []byte)) {
	it, err := k.store(ctx).Iterator(types.EncPubKeyPrefix, prefixEnd(types.EncPubKeyPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		fn(string(it.Key()[len(types.EncPubKeyPrefix):]), append([]byte(nil), it.Value()...))
	}
}

// maxEncKeyGCPerBlock bounds how many stale enc-key registrations gcStaleEncKeys reclaims per sweep, so a
// mass-unbond cannot make the sweep unbounded; the backlog drains over subsequent sweeps.
const maxEncKeyGCPerBlock = 64

// DeleteEncPubKey removes an operator's enc-key registration AND its reverse-owner index (lock-step with
// RecordEncPubKey), freeing the key for reuse by another operator.
func (k Keeper) DeleteEncPubKey(ctx sdk.Context, operator string) {
	st := k.store(ctx)
	if key, ok := k.GetEncPubKey(ctx, operator); ok {
		_ = st.Delete(encKeyOwnerKey(key))
	}
	_ = st.Delete(encPubKeyKey(operator))
	_ = st.Delete(encKeyRotatedHeightKey(operator)) // clear the rotation cooldown so a re-bond re-announces fresh
}

// gcStaleEncKeys reclaims enc-key registrations for operators that are no longer bonded validators
// (EXTERNAL-REVIEW #8: member selection already IGNORES them, but the records — plus their reverse-owner
// index that blocks another operator reusing that key — otherwise accumulate forever as the validator set
// churns). Bounded to maxEncKeyGCPerBlock deletions per sweep. A validator that re-bonds simply
// re-announces its key (idempotent) on its next vote, so deletion is safe. Deterministic: the bonded set
// and the iteration order are pure functions of committed state.
func (k Keeper) gcStaleEncKeys(ctx sdk.Context) {
	if k.stakingKeeper == nil {
		return
	}
	bonded := make(map[string]bool)
	_ = k.stakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		bonded[v.GetOperator()] = true
		return false
	})
	var stale []string
	k.IterateEncPubKeys(ctx, func(operator string, _ []byte) {
		if len(stale) < maxEncKeyGCPerBlock && !bonded[operator] {
			stale = append(stale, operator)
		}
	})
	for _, op := range stale {
		k.DeleteEncPubKey(ctx, op)
	}
}

// --- transparent member set = bonded validators that registered an enc key ---

// transparentCandidate is a bonded validator eligible for the DKG committee.
type transparentCandidate struct {
	op     string
	tokens sdkmath.Int
	key    []byte
}

// TransparentMembers derives the DKG member set for the CURRENT bonded validator set on
// the transparent path: every bonded validator that has AUTO-ANNOUNCED an enc key, capped
// to the top-N by stake weight (p.EffectiveMaxMembers) to bound VE / injected-block-data
// size. The committee is chosen by (power desc, operator asc); the chosen members are then
// RANKED BY OPERATOR ADDRESS (1-based) so the index assignment — and therefore MembersHash
// — is a deterministic pure function of committed state, identical on every node.
func (k Keeper) TransparentMembers(ctx context.Context, p types.Params) []types.RoundMember {
	if k.stakingKeeper == nil {
		return nil
	}
	var cands []transparentCandidate
	_ = k.stakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		op := v.GetOperator()
		if key, ok := k.GetEncPubKey(ctx, op); ok {
			cands = append(cands, transparentCandidate{op: op, tokens: v.GetTokens(), key: key})
		}
		return false
	})
	// Rank by stake weight (desc), operator address (asc) as the deterministic tie-break.
	sort.Slice(cands, func(i, j int) bool {
		if !cands[i].tokens.Equal(cands[j].tokens) {
			return cands[i].tokens.GT(cands[j].tokens) // higher stake first
		}
		return cands[i].op < cands[j].op
	})
	if max := p.EffectiveMaxMembers(); len(cands) > max {
		cands = cands[:max]
	}
	// CYCLE-3 H-A runtime guard (defense-in-depth BENEATH Params.Validate, which already
	// rejects any genesis/gov config with S < MinShareBudgetPerMember * committee cap):
	// never FORM a committee larger than the share budget can secure. With fewer than
	// MinShareBudgetPerMember points of stake resolution per seat, Hamilton apportionment
	// degenerates and decryption power tracks operator-address order instead of stake
	// (the reproduced HIGH-3 re-opening). Clamping HERE — while still stake-sorted, so the
	// lowest-stake candidates are shed — keeps MembersHash, the round machine, and the
	// stakeThreshold safety/liveness proof consistent (S >= 8n always holds at round-open).
	// Deterministic (pure function of committed state), LOUD, never a halt.
	if maxByBudget := p.EffectiveShareBudget() / types.MinShareBudgetPerMember; len(cands) > maxByBudget {
		clamped := len(cands) - maxByBudget
		cands = cands[:maxByBudget]
		if sdkCtx, ok := ctx.(sdk.Context); ok {
			sdkCtx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_committee_clamped",
				sdk.NewAttribute("share_budget", u64str(uint64(p.EffectiveShareBudget()))),
				sdk.NewAttribute("max_by_budget", u64str(uint64(maxByBudget))),
				sdk.NewAttribute("clamped", u64str(uint64(clamped))),
			))
		}
	}
	// Assign indices by operator address order (stable, committed-state-derived). Each
	// member also carries its STAKE weight (HIGH-3), snapshotted here from committed state.
	// The stake-proportional eval-point ALLOCATION happens at round-open (openRound), where
	// the epoch is known — it seeds the epoch-rotating remainder-seat tie-break (L-2).
	sort.Slice(cands, func(i, j int) bool { return cands[i].op < cands[j].op })
	out := make([]types.RoundMember, len(cands))
	for i, c := range cands {
		out[i] = types.RoundMember{Index: uint64(i + 1), OperatorAddr: c.op, EncPubKey: c.key, Weight: c.tokens}
	}
	return out
}

// memberIndexByOperator returns a round member's index by operator address, or 0.
func memberIndexByOperator(round types.DkgRound, op string) uint64 {
	return types.MemberIndexByOperator(round.Members, op)
}

// DecryptingSetMeetsStake reports whether the committee MEMBERS whose indices are in `present`
// collectively hold a STRICT MAJORITY of the committee's snapshotted stake weight (2*got > total).
//
// HIGH-3 (DEMOTED to defense-in-depth): stake is now baked into the CRYPTOGRAPHY via
// stake-weighted Shamir evaluation points (see AllocateEvalPoints / stakeThreshold), so the
// real capability check is "does the decrypting set hold >= t = floor(2S/3)-n+1 evaluation
// points", which the recover path enforces directly (the PROVEN crypto bar is > 1/3 of
// committee stake in all valid configs, >= 2/3 - 2n/S in general — NOT ">2/3"; see the
// stakeThreshold comment, cycle-3 M-1). This member-stake-majority test is retained as a
// redundant guard on the ON-CHAIN combine (recoverSharedSecret maps present eval points to
// their owning members before calling it). HONESTY: in worst-case rounding a set can hold t
// points at just under a stake majority, so this gate can bind ABOVE the crypto bar for
// on-chain decryption; it can never block the guaranteed liveness case (an online >2/3-stake
// set is also a strict majority), and it does nothing against OFF-chain reconstruction —
// only the crypto bar does. It reduces to a no-op on the LEGACY/unweighted path (no weights
// recorded => returns true), preserving existing behavior. It is overflow-safe (sdkmath.Int).
func DecryptingSetMeetsStake(members []types.RoundMember, present map[uint64]bool) bool {
	total := sdkmath.ZeroInt()
	got := sdkmath.ZeroInt()
	weighted := false
	for _, m := range members {
		w := m.Weight
		if w.IsNil() || !w.IsPositive() {
			continue
		}
		weighted = true
		total = total.Add(w)
		if present[m.Index] {
			got = got.Add(w)
		}
	}
	if !weighted || !total.IsPositive() {
		return true // legacy / unweighted committee: the count threshold alone governs
	}
	return got.Add(got).GT(total) // strict stake majority: 2*got > total
}

// ============================================================================
// The deterministic consume entry point.
// ============================================================================

// ConsumeVoteExtensions ingests a block's resolved vote-extension contributions into
// module state, deterministically. It is a NO-OP unless the transparent path is active
// (DkgEnabled && DkgTransparent), so the module stays fully dormant by default.
//
// DETERMINISM CONTRACT (fork-safety): the output state is a pure function of (committed
// state, entries). Entries are canonicalized here — sorted by operator, deduped first-wins
// — before any state write, and every downstream write is idempotent / first-wins, so node
// A and node B computing over the same committed block produce identical state regardless
// of the order CometBFT happened to list the votes in.
//
// PANIC-GUARD: it runs in PreBlock (inside consensus); a data-dependent panic would halt
// the chain, so a last-resort recover contains it into a deterministic event (identical
// committed state => identical outcome on every node).
func (k Keeper) ConsumeVoteExtensions(ctx sdk.Context, entries []VEEntry) {
	// AUDIT #6/DKG-3: run inside a BRANCHED cache context, committing only on CLEAN completion, so a
	// recovered panic discards all partial store writes (deterministic clean rollback on every node)
	// instead of leaving partial committed state.
	realCtx := ctx
	cc, write := realCtx.CacheContext()
	ctx = cc
	defer func() {
		if r := recover(); r != nil {
			realCtx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_ve_consume_panic",
				sdk.NewAttribute("height", u64str(uint64(realCtx.BlockHeight()))),
				sdk.NewAttribute("reason", fmt.Sprintf("%v", r)),
			))
			return // discard the cache -> roll back every partial write
		}
		write() // write() flushes the cache store AND forwards the body's buffered events to realCtx
	}()

	p := k.GetParams(ctx)
	if !p.DkgEnabled || !p.DkgTransparent {
		return
	}

	// Canonicalize: STABLE sort by operator, keep first entry per operator (first-wins
	// dedup). A stable sort matters for fork-safety: the input order is the committed
	// ExtendedCommitInfo vote order (identical on every node), so preserving it for any
	// equal-operator tie keeps the first-wins choice deterministic even in the degenerate
	// (and, in a well-formed commit, impossible) case of a repeated operator.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Operator < entries[j].Operator })
	seenOp := make(map[string]bool, len(entries))
	canon := entries[:0:0]
	for _, e := range entries {
		if e.Operator == "" || seenOp[e.Operator] {
			continue
		}
		seenOp[e.Operator] = true
		canon = append(canon, e)
	}

	// Phase 1: enc-key announcements FIRST, so a newly-registered key is visible to the
	// EndBlocker's member-set computation THIS block.
	announced := 0
	for _, e := range canon {
		if k.RecordEncPubKey(ctx, e.Operator, e.VE.EncPubKey, e.VE.EncPubKeyPoP) {
			announced++
		}
	}

	// Load the currently-open round once (dealings target the open epoch).
	cur := k.GetCurrentEpoch(ctx)
	var openRound types.DkgRound
	haveOpen := false
	if cur > 0 {
		if r, ok := k.GetDkgRound(ctx, cur); ok && r.Status == types.DkgStatusOpen {
			openRound, haveOpen = r, true
		}
	}
	h := uint64(ctx.BlockHeight())

	// Phase 2: dealings for the open round.
	dealt := 0
	if haveOpen && h <= openRound.DealDeadline {
		for _, e := range canon {
			if e.VE.Dealing == nil {
				continue
			}
			if k.IngestDealingFromVE(ctx, openRound, e.Operator, *e.VE.Dealing) {
				dealt++
			}
		}
	}

	// Phase 4: justified complaints against QUAL-candidate dealers, only inside the complaint
	// window (after dealing closes, before finalize). This is the ingestion channel that finally
	// reaches the ACCOUNTLESS transparent path — it populates the disq set finalizeRound reads, so
	// a byzantine dealer that sealed a bad/missing share to a point an honest member owns is
	// excluded from QUAL and the epoch decrypts over the healthy set (HIGH-2 / HIGH-3). Verify work is
	// bounded by committee size x a PER-ACCUSER quota (each operator gets its own budget, so a byzantine
	// accuser cannot starve honest complaints — audit fix); the VE complaint COUNT is capped in
	// VerifyVoteExtension; a verified-and-rejected complaint is negative-cached in IngestComplaintFromVE
	// so garbage cannot re-charge the O(t) DLEQ.
	if haveOpen && h > openRound.DealDeadline && h <= openRound.ComplaintDeadline {
		complained := 0
		// Defense-in-depth (re-audit): the len(ve.Complaints) count-cap in VerifyVoteExtension is a
		// node-local, non-binding filter; re-cap the number PROCESSED per VE here on the deterministic
		// PreBlock path too, so an injected oversized extension (or one that slipped VerifyVoteExtension)
		// cannot force unbounded cheap-reject work (cheap rejects do not charge the per-accuser verify quota).
		maxPerVE := len(openRound.Members)
		for _, e := range canon {
			opVerifies := 0 // independent per-accuser verify quota (anti-starvation)
			for i := range e.VE.Complaints {
				if i >= maxPerVE || opVerifies >= maxComplaintVerifiesPerAccuser {
					break
				}
				if k.IngestComplaintFromVE(ctx, openRound, e.Operator, e.VE.Complaints[i], &opVerifies) {
					complained++
				}
			}
		}
		if complained > 0 {
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_ve_complaints",
				sdk.NewAttribute("height", u64str(h)),
				sdk.NewAttribute("stored", u64str(uint64(complained))),
			))
		}
	}

	// Phase 3: decryption shares for in-flight ciphertexts, under a HARD, DETERMINISTIC per-block
	// bound on DLEQ-verification work (cycle-8 bound, cycle-9 granularity). ingestDecryptSharesBounded
	// composes a bounded oldest-first PROCESSED-ciphertext set (cheap pre-classification of chaff aimed
	// at non-processed / stranded / nonexistent ciphertexts), a per-VE share-count cap, a within-block
	// eval-point dedup, a per-(operator,CIPHERTEXT) verify budget equal to the operator's owned
	// eval-point count, and a global O(cap × S) ceiling, so the block's TOTAL O(t) DLEQ verification is
	// O(maxVerifyCiphertextsPerBlock × S) regardless of how much chaff any committee member sprays —
	// keeping the cycle-8 compute-DoS closed (HIGH-A/HIGH-B) while RESTORING honest liveness: a member
	// serving many in-flight ciphertexts of one epoch now ingests owned-points shares for EACH within
	// grace, instead of being throttled to one ciphertext/block and dropped. The cycle-7 drop-DoS fix is
	// preserved (chaff is still DLEQ-rejected; honest defers + heals).
	shared := k.ingestDecryptSharesBounded(ctx, canon, p)

	if announced+dealt+shared > 0 {
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_dkg_ve_consumed",
			sdk.NewAttribute("height", u64str(h)),
			sdk.NewAttribute("enc_keys", u64str(uint64(announced))),
			sdk.NewAttribute("dealings", u64str(uint64(dealt))),
			sdk.NewAttribute("shares", u64str(uint64(shared))),
		))
	}
}

// IngestDealingFromVE validates + stores a dealer's dealing carried on a vote extension,
// authorizing by OPERATOR (the vote extension's consensus identity), NOT by an account /
// signer — this is what removes the fee account entirely. It mirrors the DkgDeal msg-server
// validation EXACTLY (epoch match, membership, one well-formed enc-share per member, valid
// commitment points) so a malformed dealing can never enter QUAL. First-wins: a dealer that
// already dealt this epoch is not overwritten. Returns whether it stored a new dealing.
func (k Keeper) IngestDealingFromVE(ctx sdk.Context, round types.DkgRound, operator string, d types.VoteExtDealing) bool {
	if d.Epoch != round.Epoch {
		return false // stale (the round rolled over since the node dealt); it re-deals next height
	}
	idx := memberIndexByOperator(round, operator)
	if idx == 0 {
		return false // not a member of this round
	}
	if _, exists := k.GetDealing(ctx, round.Epoch, idx); exists {
		return false // first-wins: already dealt
	}
	if err := validateDealingShape(round, d.Commitments, d.EncShares); err != nil {
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_dkg_ve_deal_rejected",
			sdk.NewAttribute("epoch", u64str(round.Epoch)),
			sdk.NewAttribute("dealer_index", u64str(idx)),
			sdk.NewAttribute("reason", err.Error()),
		))
		return false
	}
	dealing := types.Dealing{
		Epoch: round.Epoch, DealerIndex: idx, Dealer: operator,
		Commitments: d.Commitments, EncShares: append([]types.DkgStoredEncShare(nil), d.EncShares...),
	}
	if k.SetDealing(ctx, dealing) != nil {
		return false
	}
	return true
}

// IngestComplaintFromVE verifies + stores a justified complaint carried on a vote extension,
// authorizing the accuser by OPERATOR identity (Pillar 3: transparent members carry no account).
// It is the accountless equivalent of msgServer.DkgComplaint, wired for the STAKE-WEIGHTED path:
// the complaint disputes a specific EVAL-POINT the accuser owns (member index != eval point on a
// weighted committee), so the enc-share is selected BY that point and the point (not the member
// index) is fed into the Feldman VerifyShare inside VerifyJustifiedComplaint. A verified-and-
// rejected complaint is negative-cached so a byzantine accuser cannot re-charge the O(t) DLEQ every
// block. `verifies` is bumped for each EC verification actually performed so the caller can cap
// per-block complaint work. Returns true only when a NEW complaint is stored (a real dealer fault).
func (k Keeper) IngestComplaintFromVE(ctx sdk.Context, round types.DkgRound, operator string, c types.VoteExtComplaint, verifies *int) bool {
	if c.Epoch != round.Epoch {
		return false // stale (round rolled over)
	}
	accuserIdx := memberIndexByOperator(round, operator)
	if accuserIdx == 0 {
		return false // accuser is not a member of this round
	}
	if c.Against == 0 || c.Against == accuserIdx {
		return false // null target / self-complaint
	}
	// RE-AUDIT FIX: c.Against must be a real member of this round BEFORE any store write. Without this a
	// byzantine accuser could pack complaints against arbitrary non-member indices, each writing a
	// negative-cache entry (SetComplaintRejected in the no-dealing path) for a bogus target — bounded
	// state-write amplification keyed on an unvalidated index.
	if _, ok := memberByIndex(round, c.Against); !ok {
		return false // complaint against a non-member index
	}
	accuser, ok := memberByIndex(round, accuserIdx)
	if !ok {
		return false
	}
	// SAFETY (weighted path, the load-bearing check): the accuser must actually OWN the disputed
	// eval-point. Without it a member could dispute a point sealed to a DIFFERENT member — that
	// point's enc-share will not open under the accuser's key, so VerifyJustifiedComplaint would
	// return cheated=true against an HONEST dealer (a single-member frame-out-of-QUAL).
	if !accuser.OwnsEvalPoint(c.EvalPoint) {
		return false
	}
	// first-wins: an already-accepted complaint from this pair needs no re-verify.
	if k.GetComplaint(ctx, round.Epoch, c.Against, accuserIdx) {
		return false
	}
	// negative-cache: a prior verified-and-rejected complaint from this pair is dropped O(1),
	// before any EC work, so garbage cannot re-charge the DLEQ or starve honest complaints.
	if k.HasComplaintRejected(ctx, round.Epoch, c.Against, accuserIdx, c.EvalPoint) {
		return false
	}
	dealing, ok := k.GetDealing(ctx, round.Epoch, c.Against)
	if !ok {
		// No dealing from c.Against: a non-dealing dealer is structurally excluded from QUAL anyway, so
		// this complaint is pointless. Negative-cache it (audit fix) so a byzantine accuser cannot re-send
		// it every block to re-force the membership / ownership / store-read work on the PreBlock path.
		_ = k.SetComplaintRejected(ctx, round.Epoch, c.Against, accuserIdx, c.EvalPoint)
		return false // no dealing to complain about
	}
	// Select the enc-share the dealer sealed AT the disputed eval-point (weighted: keyed by point).
	var enc *types.DkgStoredEncShare
	for i := range dealing.EncShares {
		if dealing.EncShares[i].MemberIndex == c.EvalPoint {
			enc = &dealing.EncShares[i]
			break
		}
	}
	if enc == nil {
		// The dealer never sealed a share to a point the accuser provably owns -> disqualifying
		// (no crypto needed; the accuser's ownership of the point was checked above).
		_ = k.SetComplaint(ctx, types.DkgComplaintRec{Epoch: round.Epoch, Against: c.Against, AccuserIndex: accuserIdx})
		return true
	}
	*verifies++ // charge the O(t) DLEQ before performing it
	cheated, proofValid := dkg.VerifyJustifiedComplaint(
		c.EvalPoint, accuser.EncPubKey, dealing.Commitments,
		enc.A, enc.Nonce, enc.Body, c.SharedPoint, c.DleqProof,
	)
	if !proofValid || !cheated {
		// framing (bad DLEQ) or frivolous (share is actually valid): reject, negative-cache THIS point, do
		// NOT store. Keyed by eval-point so it cannot suppress a valid complaint about another owned point.
		_ = k.SetComplaintRejected(ctx, round.Epoch, c.Against, accuserIdx, c.EvalPoint)
		return false
	}
	_ = k.SetComplaint(ctx, types.DkgComplaintRec{Epoch: round.Epoch, Against: c.Against, AccuserIndex: accuserIdx})
	return true
}

// validateDealingShape enforces well-formedness of a stake-weighted dealing: exactly
// `threshold` valid compressed commitment points (the degree-(t-1) Feldman polynomial), and
// exactly one well-formed enc-share (valid compressed A, exact-length nonce, non-empty body)
// per EVALUATION POINT in the round's budget domain — each addressed to a point some member
// owns, with no duplicates. On the unweighted legacy path each member owns a single point ==
// its index, so this reduces to one enc-share per member. This mirrors the DkgDeal handler's
// intent so a malformed dealing can never enter QUAL.
func validateDealingShape(round types.DkgRound, commitments [][]byte, encShares []types.DkgStoredEncShare) error {
	if len(commitments) != int(round.Threshold) {
		return fmt.Errorf("expected %d commitments, got %d", round.Threshold, len(commitments))
	}
	if _, err := dkg.ParseCommitmentPoints(commitments); err != nil {
		return fmt.Errorf("malformed commitment: %w", err)
	}
	want := types.TotalEvalPoints(round.Members)
	if len(encShares) != want {
		return fmt.Errorf("expected %d enc_shares (one per eval point), got %d", want, len(encShares))
	}
	seen := make(map[uint64]bool, want)
	for _, s := range encShares {
		if types.EvalPointOwner(round.Members, s.MemberIndex) == 0 {
			return fmt.Errorf("enc_share for unowned eval point %d", s.MemberIndex)
		}
		if seen[s.MemberIndex] {
			return fmt.Errorf("duplicate enc_share for eval point %d", s.MemberIndex)
		}
		if !dkg.ValidCompressedPoint(s.A) {
			return fmt.Errorf("enc_share for eval point %d has malformed A", s.MemberIndex)
		}
		if len(s.Nonce) != threshold.NonceSize {
			return fmt.Errorf("enc_share for eval point %d has bad nonce length %d", s.MemberIndex, len(s.Nonce))
		}
		if n := len(s.Body); n == 0 || n > maxEncShareBodyBytes {
			// EXTERNAL-REVIEW #2: an honest GCM-sealed share body is ~48 bytes; cap it so a dealer cannot pad
			// each of the `want` enc_shares up to the 1-MiB VE limit (structurally valid junk every node then
			// unmarshals, validates, and STORES). The rest of the dealing is already byte-bounded: exactly t
			// commitments + want enc_shares, each A/commitment a 33-byte point, nonce an exact length.
			return fmt.Errorf("enc_share body for eval point %d has bad length %d", s.MemberIndex, n)
		}
		seen[s.MemberIndex] = true
	}
	return nil
}

// IngestDecryptShareFromVE authorizes, DLEQ-VERIFIES, and stores a SINGLE decryption share carried
// on a vote extension, authorizing by OPERATOR against the ciphertext's epoch round: the operator
// must be a member AND the share's index must be an EVALUATION POINT that member OWNS (HIGH-3 — so a
// member can only ever contribute shares at its own stake-allocated points, never claim another
// member's point). It mirrors the SubmitDecryptionShare msg-server authorization, minus the
// account/signer. First-wins per (decryptHeight, seq, evalPoint).
//
// This is the UNBUDGETED single-share primitive. The CONSENSUS path — ConsumeVoteExtensions Phase 3
// — instead goes through ingestDecryptSharesBounded, which wraps the SAME classify + verify+store
// steps in the cycle-8 per-block verify bound. The split is deliberate: the cheap authorization /
// dedup checks (classifyDecryptShare) run BEFORE the expensive DLEQ verify (verifyAndStoreDecryptShare),
// so the bounded path can apply its caps between the two and never pay an O(t) verify for a share it
// will drop.
//
// CYCLE-7 (fix #1): the share's DLEQ proof is VERIFIED (in verifyAndStoreDecryptShare) before
// SetEncShare — against the epoch's DKG public commitments and this ciphertext's ephemeral A. A
// structurally-valid but cryptographically-garbage CHAFF share (non-empty D, absent/garbage proof)
// is REJECTED at ingest and NEVER enters state, so it can never (1) inflate the matured-decrypt count
// gate past `need`, nor (2) mark its member present in the stake gate — the two effects a <=1/3-stake
// coalition combined to convert a healable within-grace DEFER into a hard DROP. A stored share is an
// already-verified share (the first-wins check short-circuits a re-send before the verify), so
// verification is a one-time ingest cost. It is a PURE function of committed state + the share bytes
// (identical verdict on every node), mandatory in this PreBlock/consensus path.
//
// The stored EncShare.Keyper is the operator address (attribution only); the decrypt path
// (recoverSharedSecret) uses only Index/D/Proof. Returns whether it stored a new share.
func (k Keeper) IngestDecryptShareFromVE(ctx sdk.Context, operator string, s types.VoteExtShare) bool {
	// CRITICAL MATURITY GATE (defense-in-depth): never store a share for a not-yet-matured
	// ciphertext - a stored share is public and t of them reconstruct the AES key, so an early
	// share would expose the plaintext before its decrypt_height. The batch consume path enforces
	// this via its processed-set; this single-share primitive (currently test-only) enforces it
	// directly so it can never bypass the gate if it is ever wired into a live path.
	if s.DecryptHeight > uint64(ctx.BlockHeight()) {
		return false
	}
	member, ctA, epoch, ok := k.classifyDecryptShare(ctx, operator, s, nil)
	if !ok {
		return false
	}
	_ = member // the single-share path enforces no per-operator budget; the batch path uses it
	return k.verifyAndStoreDecryptShare(ctx, epoch, ctA, operator, s)
}

// ============================================================================
// CYCLE-8: deterministic, HARD-BOUNDED ingest of a block's decryption shares.
//
// Closes the two DoS the cycle-7 ingest-DLEQ-verify introduced:
//   HIGH-A (halt-class): the consume loop verified EVERY share in EVERY extension with no count cap,
//     so one member packing a 1-MiB extension with thousands of shares forced thousands of O(t)
//     elliptic-curve verifications on the PreBlock consensus path every block -> consensus stall.
//   HIGH-B (<=1/3-stake compute DoS): a REJECTED chaff share is never stored, so the first-wins dedup
//     never suppressed it and the identical chaff was re-verified from scratch every block.
//
// The bound is four composed, pure, NO-persistent-state controls (see ingestDecryptSharesBounded).
// ============================================================================

// shareSlot is a decryption share's per-round eval-point coordinate. A Shamir evaluation point is
// owned by exactly ONE committee member, so (decryptHeight, seq, index) is a globally-unique slot —
// the key for BOTH the persistent first-wins dedup (stored shares) and the within-block verify dedup.
type shareSlot struct {
	decryptHeight uint64
	seq           uint64
	index         uint64
}

// txKey keys the in-flight-ciphertext read cache by (decryptHeight, seq).
type txKey struct {
	decryptHeight uint64
	seq           uint64
}

// opCiphertext keys the PER-OPERATOR, PER-CIPHERTEXT verify budget (cycle-9). Within one block an
// operator may force at most len(its owned eval points) DLEQ verifications FOR EACH in-flight
// ciphertext it serves — the exact number of decryption shares an honest member owes PER ciphertext
// (a decryption share is D = x*A, bound to that ciphertext's ephemeral A, so a member owes one share
// per owned point PER ciphertext, NOT one per owned point per epoch). A ciphertext (decryptHeight,
// seq) fixes its epoch, so this IS the per-(operator, epoch, ciphertext) budget; epoch is redundant
// in the key. Cycle-8 keyed this per (operator, epoch), which capped an honest member to ONE
// ciphertext's worth of shares per block and hard-dropped the rest past grace — the HIGH this fixes.
type opCiphertext struct {
	operator      string
	decryptHeight uint64
	seq           uint64
}

// opEpoch memoizes the owned-eval-point COUNT for an (operator, epoch) — the per-(operator,
// ciphertext) budget VALUE. Every ciphertext of the same epoch grants the same operator the same
// owned-point budget, so len(OwnedEvalPoints()) is computed once per (operator, epoch) per block
// rather than once per share.
type opEpoch struct {
	operator string
	epoch    uint64
}

// maxVerifyCiphertextsPerBlock bounds how many DISTINCT in-flight ciphertexts may consume
// per-(operator,ciphertext) verify budget in a single block (cycle-9). It is the multiplier that
// takes the per-block DLEQ-verify bound from cycle-8's O(S) to O(maxVerifyCiphertextsPerBlock × S):
// with the per-ciphertext budget summing to at most S over the committee (Σ owned points == S), and
// at most this many distinct ciphertexts budgeted, the block's TOTAL verify work is bounded by
// maxVerifyCiphertextsPerBlock × S — a constant × S, deterministic and NOT attacker-scalable. It is
// tied to the decrypt-side defer cap (maxDeferredDecryptsPerBlock): the ciphertexts that legitimately
// need shares in a block are exactly the bounded, oldest-first set the decrypt+defer machinery works,
// so the share-ingest window and the decrypt/heal window advance in lockstep. An attacker CANNOT
// inflate this count — shares for any ciphertext outside the oldest-maxVerifyCiphertextsPerBlock
// processed set (future spam, stranded-past-grace, or nonexistent) are cheaply classified out by an
// O(1) map lookup BEFORE any per-ciphertext verify budget is touched.
const maxVerifyCiphertextsPerBlock = maxDeferredDecryptsPerBlock

// The CRIT-2 K_max — the HARD per-block first-time DLEQ-verify budget — is now the governance-tunable
// param MaxVerifyOpsPerBlock (types.Params.EffectiveMaxVerifyOps(), default defaultMaxVerifyOps). It caps
// the TOTAL O(t) verify work a block performs independent of the share budget S, so block time stays flat
// under any valid S at the cost of decrypt throughput (~K_max/S ciphertexts fully verified per block; the
// rest defer + heal). The live fleet re-measures and sets it to its hardware budget.

// MaxVerifyCiphertextsPerBlock exposes the cycle-9 per-block distinct-ciphertext verify cap for
// regression tests (they assert the block's DLEQ-verify work never exceeds this * S under a flood,
// and that an honest member serving up to this many in-flight ciphertexts is never throttled).
const MaxVerifyCiphertextsPerBlock = maxVerifyCiphertextsPerBlock

// maxComplaintVerifiesPerAccuser caps the framing-resistant complaint DLEQ verifications ONE accuser
// (operator) may charge per block in Phase 4. AUDIT FIX: a single GLOBAL per-block cap processed in
// operator-address order let a byzantine accuser (grinding its address to sort first) fill the whole
// budget with framing spam and STARVE honest accusers' complaints past ComplaintDeadline on a large
// (governance-set) committee. A PER-ACCUSER quota gives every operator its own independent budget, so
// a byzantine accuser can only exhaust its OWN — honest complaints always reach the DLEQ. Total block
// verify work is then bounded by (committee size) x this quota, independent of address ordering.
// UNLIKE decryption-share work (scales with the UNBOUNDED in-flight ciphertext count, needs the O(cap*S)
// ceiling), complaint work is bounded by COMMITTEE SIZE and the negative-cache makes each (accuser,
// against) pair cost at most ONE verify per epoch; a quota of 8/block over the window (default 10)
// clears every honest accuser's real complaints (a round with > that many bad dealers fails QUAL anyway).
const maxComplaintVerifiesPerAccuser = 8

// EXTERNAL-REVIEW #2 field-byte caps: VerifyVoteExtension bounds the VE's TOTAL bytes (1 MiB) + element
// COUNTS, and the crypto fields are self-bounding (a 33-byte point, a 64-byte DLEQ proof — ParseDLEQProof
// rejects any other length). These cap the two remaining variable-length fields so a peer cannot pad a
// structurally-valid VE that every node then unmarshals / validates / stores.
const (
	maxEncShareBodyBytes = 128 // honest GCM-sealed DKG share body is ~48 bytes
	maxEncKeyPoPBytes    = 128 // honest DER ECDSA proof-of-possession is ~70-72 bytes
)

// consumeCaches memoizes the two committed-state decodes the cheap share classification repeats
// across a block: the DKG round (which carries the whole member set) and the in-flight ciphertext. It
// changes NO verdict — it only avoids re-unmarshaling the same round/ciphertext for every share and
// every re-sent chaff copy. A nil *consumeCaches is a valid (uncached) value for the single-share path.
type consumeCaches struct {
	rounds map[uint64]roundHit
	txs    map[txKey]txHit
}
type roundHit struct {
	r  types.DkgRound
	ok bool
}
type txHit struct {
	e  types.EncTx
	ok bool
}

func newConsumeCaches() *consumeCaches {
	return &consumeCaches{rounds: map[uint64]roundHit{}, txs: map[txKey]txHit{}}
}

func (k Keeper) roundCached(ctx sdk.Context, c *consumeCaches, epoch uint64) (types.DkgRound, bool) {
	if c != nil {
		if h, hit := c.rounds[epoch]; hit {
			return h.r, h.ok
		}
	}
	r, ok := k.GetDkgRound(ctx, epoch)
	if c != nil {
		c.rounds[epoch] = roundHit{r: r, ok: ok}
	}
	return r, ok
}

func (k Keeper) txCached(ctx sdk.Context, c *consumeCaches, h, seq uint64) (types.EncTx, bool) {
	if c != nil {
		if hit, ok := c.txs[txKey{decryptHeight: h, seq: seq}]; ok {
			return hit.e, hit.ok
		}
	}
	e, ok := k.GetEncTx(ctx, h, seq)
	if c != nil {
		c.txs[txKey{decryptHeight: h, seq: seq}] = txHit{e: e, ok: ok}
	}
	return e, ok
}

// classifyDecryptShare runs the CHEAP (no elliptic-curve) authorization + dedup checks for a
// decryption share carried on a vote extension. It returns the resolved member, the ciphertext's
// ephemeral A, and the epoch when — and ONLY when — the share is a FRESH, well-authorized candidate
// for DLEQ verification: non-empty D, a matching in-flight ciphertext, a real round, the operator is a
// member, the claimed eval point is one it OWNS, and no share is already stored at that slot
// (first-wins, O(1) point lookup). ok=false => the share is cheaply rejected or already-stored: it
// does NO elliptic-curve work and consumes NO verify budget. Deterministic pure read of committed
// state (consensus-safe); the *consumeCaches only memoizes reads and may be nil.
func (k Keeper) classifyDecryptShare(ctx sdk.Context, operator string, s types.VoteExtShare, c *consumeCaches) (types.RoundMember, []byte, uint64, bool) {
	if len(s.D) == 0 {
		return types.RoundMember{}, nil, 0, false
	}
	e, ok := k.txCached(ctx, c, s.DecryptHeight, s.Seq)
	if !ok || e.Epoch == 0 || e.Epoch != s.Epoch {
		return types.RoundMember{}, nil, 0, false // no such ciphertext, legacy epoch, or epoch mismatch
	}
	round, ok := k.roundCached(ctx, c, e.Epoch)
	if !ok {
		return types.RoundMember{}, nil, 0, false
	}
	idx := memberIndexByOperator(round, operator)
	if idx == 0 {
		return types.RoundMember{}, nil, 0, false // operator is not a member of the epoch
	}
	member, ok := memberByIndex(round, idx)
	if !ok || !member.OwnsEvalPoint(s.Index) {
		return types.RoundMember{}, nil, 0, false // the claimed eval point is not one this member owns
	}
	// First-wins per EVALUATION POINT (O(1) point lookup): an already-recorded share at this exact
	// slot (by anyone; a point has one owner) is not overwritten and, crucially, is never re-verified
	// — a stored share is an already-DLEQ-verified one, so verification stays a one-time ingest cost.
	if k.hasEncShareAt(ctx, s.DecryptHeight, s.Seq, s.Index) {
		return types.RoundMember{}, nil, 0, false
	}
	return member, e.A, e.Epoch, true
}

// verifyAndStoreDecryptShare performs the ONE expensive step — the DLEQ verification — and, iff it
// passes, stores the share. A failed verification is a chaff rejection (loud event, not stored), so
// "stored share" == "DLEQ-verified share" and a chaff share can never enter state (cycle-7 fix #1).
func (k Keeper) verifyAndStoreDecryptShare(ctx sdk.Context, epoch uint64, ctA []byte, operator string, s types.VoteExtShare) bool {
	if !k.verifyDecryptShareDLEQ(ctx, epoch, ctA, s.Index, s.D, s.Proof) {
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_dkg_ve_share_rejected",
			sdk.NewAttribute("epoch", u64str(epoch)),
			sdk.NewAttribute("operator", operator),
			sdk.NewAttribute("index", u64str(s.Index)),
			sdk.NewAttribute("decrypt_height", u64str(s.DecryptHeight)),
			sdk.NewAttribute("seq", u64str(s.Seq)),
			sdk.NewAttribute("reason", "dleq_verification_failed"),
		))
		// LIVENESS-4: negative-cache this slot so a re-sent chaff is dropped O(1) next block instead of
		// re-charging the DLEQ. Only the eval-point's owner can reach here, so this only suppresses a
		// Byzantine owner's own bad share (an honest owner never fails DLEQ). Cleared with the ciphertext.
		k.setRejectedShare(ctx, s.DecryptHeight, s.Seq, s.Index)
		return false
	}
	if k.SetEncShare(ctx, types.EncShare{
		Keyper: operator, DecryptHeight: s.DecryptHeight, Seq: s.Seq, Index: s.Index, D: s.D, Proof: s.Proof,
		Verified: true, // round-9 #5: DLEQ just checked above; the decrypt-time recover may trust + skip re-verify
	}) != nil {
		return false
	}
	return true
}

// ingestDecryptSharesBounded is the DETERMINISTIC, HARD-BOUNDED consensus-path ingest of a block's
// decryption shares (cycle-8 bound, cycle-9 granularity fix). It caps the block's total O(t) DLEQ
// verification at O(maxVerifyCiphertextsPerBlock × S) REGARDLESS of attacker input, via five composed,
// pure, NO-persistent-state controls applied to the CANONICAL (operator-sorted, deduped) entries:
//
//  0. PROCESSED-CIPHERTEXT PRE-CLASSIFICATION (cycle-9): once per block the ≤ maxVerifyCiphertextsPerBlock
//     OLDEST in-flight ciphertexts from the start of the decrypt-deferral window (h - grace) are read
//     from committed state into a set — byte-for-byte the head of the set the honest builder
//     (buildDecryptShares) serves. A share whose (decryptHeight, seq) is NOT in this set targets a
//     non-processed / stranded-past-grace / nonexistent ciphertext; it is dropped by an O(1) map lookup
//     BEFORE any per-ciphertext verify budget is touched. This is what makes the count of budgeted
//     ciphertexts attacker-UNinflatable: a flood of shares aimed at ciphertexts outside the bounded
//     oldest-first window can neither exhaust an honest member's per-ciphertext budgets nor inflate work.
//  1. PER-VE SHARE-COUNT CAP: a single extension may carry at most VoteExtShareCap == max(256, S)
//     shares — the exact bound the honest builder stops at. Excess is dropped (deterministically: the
//     committed share order fixes which survive) BEFORE any per-share work. This defeats the 1-MiB,
//     thousands-of-shares extension (HIGH-A's raw magnitude).
//  2. WITHIN-BLOCK EVAL-POINT DEDUP: each (decryptHeight, seq, index) slot is verified at most ONCE
//     per block, so re-sending the same chaff slot many times costs one verify, not many.
//  3. PER-(operator,CIPHERTEXT) VERIFY BUDGET == the operator's owned eval-point count: for EACH
//     processed ciphertext an operator can force at most as many DLEQ verifications as it owns points —
//     the most it could ever legitimately owe for that ciphertext (one share per owned point per
//     ciphertext). Excess (chaff re-aimed at a processed ciphertext, or padding) is dropped BEFORE the
//     verify. Summed over the committee this budget is at most S PER CIPHERTEXT (Σ owned points == S),
//     and control 0 caps the number of budgeted ciphertexts, so together they bound the block's total
//     verify work to O(maxVerifyCiphertextsPerBlock × S). It is ALSO the "short-circuit re-sent chaff"
//     control (a spammer re-sending every block still only burns its owned-point budget per processed
//     ciphertext — HIGH-B) and stops a single member from monopolizing the budget of any ciphertext.
//     CYCLE-9: keying this per (operator, ciphertext) rather than per (operator, epoch) is the fix —
//     the per-epoch key throttled an honest member serving MANY in-flight ciphertexts of one epoch to
//     ONE ciphertext's worth of shares per block, hard-dropping the rest past the 32-block grace.
//  4. GLOBAL O(cap × S) CEILING: a belt at maxVerifyCiphertextsPerBlock × S (floored at VoteExtShareCap,
//     never below cycle-8's O(S)) so a gap in the controls-0/3 accounting can never let the block exceed
//     O(cap × S) verifications; the surplus DEFERS to a later block (re-sent idempotently), NOT rejected.
//
// A DEFERRED share (not-processed / budget / ceiling) is NOT a chaff rejection: nothing is stored and
// NO reject event fires, so an honest share throttled this block simply verifies on a later one — the
// cycle-7 defers+heals behavior is preserved. Every control is a pure function of committed state + the
// canonical entries (the accounting maps + processed set are rebuilt each block, never persisted, and
// the processed set is bounded to maxVerifyCiphertextsPerBlock so the budget maps hold at most that many
// distinct ciphertexts × committee entries), so every node accepts / rejects / defers identically — the
// fork-safety contract. Returns the number stored.
func (k Keeper) ingestDecryptSharesBounded(ctx sdk.Context, canon []VEEntry, p types.Params) int {
	shareCap := p.VoteExtShareCap() // (1) per-VE cap == max(256, S) == O(S)
	// (4) GLOBAL O(cap × S) CEILING belt. The authoritative bound is control 0 (≤ cap distinct
	// ciphertexts) × control 3 (≤ S verifications/ciphertext); this ceiling is a hard defense-in-depth
	// stop at cap × S so a gap in that accounting can never exceed O(cap × S). Floored at shareCap so
	// it is never below cycle-8's O(S).
	globalCeiling := maxVerifyCiphertextsPerBlock * p.EffectiveShareBudget()
	if kmax := p.EffectiveMaxVerifyOps(); globalCeiling > kmax {
		globalCeiling = kmax // CRIT-2 K_max: bound per-block DLEQ work by the (governance-tunable) budget, not × S
	}
	// LIVENESS FLOOR (audit #5): never below one honest VE's worth of shares (shareCap == max(256, S)). So the
	// EFFECTIVE ceiling is max(MaxVerifyOpsPerBlock, shareCap) — a governance K_max set BELOW shareCap is
	// intentionally overridden to preserve liveness (documented on the param), NOT silently ignored; it is a
	// floor, not a cap bypass. NOTE (audit #3 interaction): the floor is a share-COUNT, but a COLD verify
	// charges ~S EC-ops, so during the <=ceil(S/128)-block post-rekey WARMUP a fully-cold honest extension
	// clears only ~ceiling/S of its shares per block; the rest DEFER (nothing stored, no reject) and heal as
	// the Y-cache warms — always within the 32-block decrypt grace, so no ciphertext strands.
	if globalCeiling < shareCap {
		globalCeiling = shareCap
	}
	// (0) PROCESSED-CIPHERTEXT SET: the ≤ maxVerifyCiphertextsPerBlock oldest in-flight ciphertexts from
	// the start of the decrypt-deferral window (h - grace) — the exact window the honest builder serves.
	// Pure committed-state read in deterministic (decryptHeight, seq) order (identical on every node).
	h := uint64(ctx.BlockHeight())
	from := uint64(0)
	if h > strandedDecryptGraceBlocks {
		from = h - strandedDecryptGraceBlocks
	}
	processed := make(map[txKey]bool, maxVerifyCiphertextsPerBlock)
	k.IterateInFlightFrom(ctx, from, maxVerifyCiphertextsPerBlock, func(e types.EncTx) bool {
		// CRITICAL MATURITY GATE (anti-MEV confidentiality): NEVER store a decryption share for a
		// ciphertext that has not matured (decrypt_height > h). A stored share is public state, and
		// t stored shares reconstruct x*A = the AES key, so admitting shares early would let any
		// observer decrypt the body BEFORE its decrypt_height - defeating the timing guarantee the
		// whole scheme exists for. Entries are visited in ascending (decryptHeight, seq) order, so
		// the first not-yet-matured entry ends the matured window. This is the AUTHORITATIVE gate:
		// even a byzantine node serving early shares cannot get them stored, because a share whose
		// (decryptHeight, seq) is absent from `processed` is dropped below.
		if e.DecryptHeight > h {
			return false
		}
		processed[txKey{decryptHeight: e.DecryptHeight, seq: e.Seq}] = true
		return true
	})

	c := newConsumeCaches()
	seen := make(map[shareSlot]bool)    // (2) within-block eval-point dedup
	spent := make(map[opCiphertext]int) // (3) per-(operator,ciphertext) verifications performed this block
	owned := make(map[opEpoch]int)      // (3) memoized owned-eval-point count per (operator,epoch) == the budget value
	globalSpent := 0                    // (4) total verifications performed this block
	shared := 0
	deferred := false
	for _, e := range canon {
		if globalSpent >= globalCeiling {
			deferred = true
			break // (4) global O(cap × S) ceiling reached — defer the rest to a later block
		}
		shares := e.VE.Shares
		if len(shares) > shareCap { // (1) per-VE share-count cap
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_ve_shares_clamped",
				sdk.NewAttribute("operator", e.Operator),
				sdk.NewAttribute("submitted", u64str(uint64(len(shares)))),
				sdk.NewAttribute("cap", u64str(uint64(shareCap))),
			))
			shares = shares[:shareCap]
		}
		for i := range shares {
			if globalSpent >= globalCeiling {
				deferred = true
				break // (4) global ceiling reached mid-extension
			}
			s := shares[i]
			tk := txKey{decryptHeight: s.DecryptHeight, seq: s.Seq}
			if !processed[tk] {
				continue // (0) not a processed ciphertext — cheap O(1) drop BEFORE any budget/verify
			}
			slot := shareSlot{decryptHeight: s.DecryptHeight, seq: s.Seq, index: s.Index}
			if seen[slot] {
				continue // (2) this eval-point slot was already verified this block
			}
			if k.hasRejectedShare(ctx, s.DecryptHeight, s.Seq, s.Index) {
				continue // (LIVENESS-4) this slot already failed DLEQ this epoch: O(1) drop, no re-verify, no budget
			}
			member, ctA, epoch, ok := k.classifyDecryptShare(ctx, e.Operator, s, c)
			if !ok {
				continue // cheap-rejected / already-stored: no DLEQ work, no budget consumed
			}
			oc := opCiphertext{operator: e.Operator, decryptHeight: s.DecryptHeight, seq: s.Seq}
			oe := opEpoch{operator: e.Operator, epoch: epoch}
			b, hit := owned[oe]
			if !hit {
				b = len(member.OwnedEvalPoints()) // (3) budget value == the operator's owned eval-point count
				owned[oe] = b
			}
			if spent[oc] >= b {
				continue // (3) per-(operator,ciphertext) cap: excess dropped BEFORE the O(t) DLEQ verify
			}
			// AUDIT #3: the global ceiling is an EC-OP budget, not a share COUNT. A WARM share key is an
			// O(1) verify, but a COLD one (an index not yet precomputed — the first ~S/chunk blocks after a
			// finalize/rekey) falls back to the O(t) SharePubKey Horner. Charge a cold verify ~t (bounded by
			// EffectiveShareBudget) so a rekey-warmup window can never blow up per-block CPU while the count
			// reads "1 op/share"; a cold verify that would exceed the budget defers to a later (warmer) block.
			cost := 1
			if len(k.getShareKeyCache(ctx, epoch, s.Index)) == 0 {
				cost = p.EffectiveShareBudget()
			}
			if globalSpent+cost > globalCeiling {
				deferred = true
				break // (4) EC-op budget reached (counting the cold O(t) cost) — defer the rest
			}
			// ---- bounded: charge the budgets, then perform the one DLEQ verification + store ----
			seen[slot] = true
			spent[oc]++
			globalSpent += cost
			if k.verifyAndStoreDecryptShare(ctx, epoch, ctA, e.Operator, s) {
				shared++
			}
		}
	}
	if deferred {
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_dkg_ve_verify_bounded",
			sdk.NewAttribute("height", u64str(uint64(ctx.BlockHeight()))),
			sdk.NewAttribute("verified", u64str(uint64(globalSpent))),
			sdk.NewAttribute("cap", u64str(uint64(globalCeiling))),
		))
	}
	return shared
}

// verifyDecryptShareDLEQ deterministically checks the DLEQ proof carried on a decryption share
// against the epoch's DKG public commitments (the installed ActiveThresholdKey) and the
// ciphertext's ephemeral A. It recomputes the member's PUBLIC share key Y_index the exact way
// dkg.RecoverVerified does on the decrypt path, so "accepted at ingest" == "verifiable at
// recover" — the same pure function of committed state on every node (consensus-safe). A missing
// active key (the round has not finalized, or was pruned) or an unparseable commitment/proof is
// treated as a verification FAILURE: the share is rejected now and, if it is genuinely honest,
// re-arrives on a later vote and verifies once the key is present. Returns true iff D = x*A for
// the same x as Y_index = x*G.
func (k Keeper) verifyDecryptShareDLEQ(ctx sdk.Context, epoch uint64, ctA []byte, index uint64, d, proofBz []byte) bool {
	ak, ok := k.GetActiveKey(ctx, epoch)
	if !ok || len(ak.PublicCommitments) == 0 {
		return false
	}
	proof, err := dkg.ParseDLEQProof(proofBz)
	if err != nil {
		return false // absent / short / non-canonical proof — a chaff share
	}
	// Fix 1 C4' (HIGH-U flattener): use the O(1) cached public share key Y_index precomputed at finalize;
	// a single point-decompress here replaces the O(t) SharePubKey Horner recompute. Falls back to the
	// on-the-fly recompute only for a cold / pre-C4' epoch whose cache was never populated.
	if yb := k.getShareKeyCache(ctx, epoch, index); len(yb) > 0 {
		if pts, perr := dkg.ParseCommitmentPoints([][]byte{yb}); perr == nil && len(pts) == 1 {
			return dkg.VerifyDecryptShare(ctA, &threshold.DecryptShare{Index: index, D: d}, &pts[0], proof)
		}
	}
	commitments, cerr := dkg.ParseCommitmentPoints(ak.PublicCommitments)
	if cerr != nil {
		return false
	}
	Y := dkg.SharePubKey(commitments, index)
	return dkg.VerifyDecryptShare(ctA, &threshold.DecryptShare{Index: index, D: d}, Y, proof)
}
