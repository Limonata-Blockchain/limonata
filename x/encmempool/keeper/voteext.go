package keeper

import (
	"bytes"
	"context"
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
	if operator == "" || !dkg.ValidCompressedPoint(key) {
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
	// Rotation: drop the reverse index for this operator's previous key before rebinding.
	if had {
		_ = k.store(ctx).Delete(encKeyOwnerKey(cur))
	}
	st := k.store(ctx)
	_ = st.Set(encPubKeyKey(operator), append([]byte(nil), key...))
	_ = st.Set(encKeyOwnerKey(key), []byte(operator))
	return true
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
	defer func() {
		if r := recover(); r != nil {
			ctx.EventManager().EmitEvent(sdk.NewEvent(
				"encmempool_dkg_ve_consume_panic",
				sdk.NewAttribute("height", u64str(uint64(ctx.BlockHeight()))),
				sdk.NewAttribute("reason", fmt.Sprintf("%v", r)),
			))
		}
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

	// Phase 3: decryption shares for in-flight ciphertexts.
	shared := 0
	for _, e := range canon {
		for i := range e.VE.Shares {
			if k.IngestDecryptShareFromVE(ctx, e.Operator, e.VE.Shares[i]) {
				shared++
			}
		}
	}

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
		if len(s.Body) == 0 {
			return fmt.Errorf("empty enc_share body for eval point %d", s.MemberIndex)
		}
		seen[s.MemberIndex] = true
	}
	return nil
}

// IngestDecryptShareFromVE authorizes + stores a DLEQ-proved decryption share carried on a
// vote extension, authorizing by OPERATOR against the ciphertext's epoch round: the operator
// must be a member AND the share's index must be an EVALUATION POINT that member OWNS (HIGH-3 —
// so a member can only ever contribute shares at its own stake-allocated points, never claim
// another member's point). It mirrors the SubmitDecryptionShare msg-server authorization, minus
// the account/signer. First-wins per (decryptHeight, seq, evalPoint). The stored EncShare.Keyper
// is the operator address (attribution only); the decrypt path (recoverSharedSecret) uses only
// Index/D/Proof. Returns whether it stored a new share.
func (k Keeper) IngestDecryptShareFromVE(ctx sdk.Context, operator string, s types.VoteExtShare) bool {
	if len(s.D) == 0 {
		return false
	}
	e, ok := k.GetEncTx(ctx, s.DecryptHeight, s.Seq)
	if !ok || e.Epoch == 0 || e.Epoch != s.Epoch {
		return false // no such ciphertext, legacy epoch, or epoch mismatch
	}
	round, ok := k.GetDkgRound(ctx, e.Epoch)
	if !ok {
		return false
	}
	idx := memberIndexByOperator(round, operator)
	if idx == 0 {
		return false // operator is not a member of the epoch
	}
	member, ok := memberByIndex(round, idx)
	if !ok || !member.OwnsEvalPoint(s.Index) {
		return false // the claimed eval point is not one this member owns
	}
	// First-wins per EVALUATION POINT: an already-recorded share at this point (by anyone) is
	// not overwritten. Since each point is owned by exactly one member, this both dedups a
	// member's own re-submission and blocks a claim on another member's point.
	for _, ex := range k.CollectShares(ctx, s.DecryptHeight, s.Seq) {
		if ex.Index == s.Index {
			return false
		}
	}
	if k.SetEncShare(ctx, types.EncShare{
		Keyper: operator, DecryptHeight: s.DecryptHeight, Seq: s.Seq, Index: s.Index, D: s.D, Proof: s.Proof,
	}) != nil {
		return false
	}
	return true
}
