// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// DKG store accessors (plain JSON-in-store, big-endian keys — same pattern as
// the commit/enc-tx state above).
// ============================================================================

func dkgRoundKey(epoch uint64) []byte { return concat(types.DkgRoundPrefix, u64(epoch)) }
func dkgDealKey(epoch, dealerIndex uint64) []byte {
	return concat(types.DkgDealPrefix, u64(epoch), u64(dealerIndex))
}
func dkgComplaintKey(epoch, against, accuser uint64) []byte {
	return concat(types.DkgComplaintPrefix, u64(epoch), u64(against), u64(accuser))
}
func activeKeyKey(epoch uint64) []byte { return concat(types.ActiveKeyPrefix, u64(epoch)) }

func (k Keeper) SetDkgRound(ctx context.Context, r types.DkgRound) error {
	return k.store(ctx).Set(dkgRoundKey(r.Epoch), mustJSON(r))
}

func (k Keeper) GetDkgRound(ctx context.Context, epoch uint64) (types.DkgRound, bool) {
	bz, err := k.store(ctx).Get(dkgRoundKey(epoch))
	if err != nil || bz == nil {
		return types.DkgRound{}, false
	}
	var r types.DkgRound
	if json.Unmarshal(bz, &r) != nil {
		return types.DkgRound{}, false
	}
	return r, true
}

func (k Keeper) SetDealing(ctx context.Context, d types.Dealing) error {
	return k.store(ctx).Set(dkgDealKey(d.Epoch, d.DealerIndex), mustJSON(d))
}

func (k Keeper) GetDealing(ctx context.Context, epoch, dealerIndex uint64) (types.Dealing, bool) {
	bz, err := k.store(ctx).Get(dkgDealKey(epoch, dealerIndex))
	if err != nil || bz == nil {
		return types.Dealing{}, false
	}
	var d types.Dealing
	if json.Unmarshal(bz, &d) != nil {
		return types.Dealing{}, false
	}
	return d, true
}

// IterateDealings visits every stored dealing for an epoch in dealer-index order.
func (k Keeper) IterateDealings(ctx context.Context, epoch uint64, fn func(types.Dealing)) {
	pfx := concat(types.DkgDealPrefix, u64(epoch))
	it, err := k.store(ctx).Iterator(pfx, prefixEnd(pfx))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var d types.Dealing
		if json.Unmarshal(it.Value(), &d) == nil {
			fn(d)
		}
	}
}

func (k Keeper) SetComplaint(ctx context.Context, c types.DkgComplaintRec) error {
	return k.store(ctx).Set(dkgComplaintKey(c.Epoch, c.Against, c.AccuserIndex), mustJSON(c))
}

// GetComplaint reports whether a complaint from accuser against dealer is already stored
// for the epoch. The transparent Phase-4 ingest uses it as a first-wins short-circuit so a
// re-sent (already-accepted) complaint costs an O(1) lookup instead of a fresh O(t) DLEQ.
func (k Keeper) GetComplaint(ctx context.Context, epoch, against, accuser uint64) bool {
	bz, err := k.store(ctx).Get(dkgComplaintKey(epoch, against, accuser))
	return err == nil && bz != nil
}

func dkgComplaintRejectedKey(epoch, against, accuser, evalPoint uint64) []byte {
	return concat(types.DkgComplaintRejectedPrefix, u64(epoch), u64(against), u64(accuser), u64(evalPoint))
}

// SetComplaintRejected records that a complaint from accuser against dealer AT a specific eval-point was
// verified and REJECTED (framing/frivolous / no-dealing), so a re-send of THAT point is dropped before
// re-charging the DLEQ verify. AUDIT FIX (DKG-SM-5): the key includes evalPoint so a rejected complaint
// about one owned point cannot suppress a VALID complaint by the same accuser about the same dealer at a
// DIFFERENT point (the dealer may have poisoned only some of the accuser's points).
func (k Keeper) SetComplaintRejected(ctx context.Context, epoch, against, accuser, evalPoint uint64) error {
	return k.store(ctx).Set(dkgComplaintRejectedKey(epoch, against, accuser, evalPoint), []byte{1})
}

// HasComplaintRejected reports whether (accuser vs dealer AT evalPoint) already produced a rejected
// complaint this epoch (the negative-cache lookup, O(1), before any EC work).
func (k Keeper) HasComplaintRejected(ctx context.Context, epoch, against, accuser, evalPoint uint64) bool {
	bz, err := k.store(ctx).Get(dkgComplaintRejectedKey(epoch, against, accuser, evalPoint))
	return err == nil && bz != nil
}

// purgeDealings deletes every stored dealing + complaint (the BULK point-to-point
// state) for an epoch, leaving the small DkgRound record intact. Keys are collected
// first (a store iterator must not be mutated mid-scan) then deleted — deterministic
// (the key set is a pure function of committed state). Used when an epoch is superseded
// by a MEMBER CHANGE: the old dealing bulk is dead weight once the round finalized, but
// the round record is KEPT because in-flight ciphertexts stamped with the old (active)
// epoch still authorize their decryption shares against it (SubmitDecryptionShare reads
// the round's member set).
func (k Keeper) purgeDealings(ctx context.Context, epoch uint64) {
	st := k.store(ctx)
	var keys [][]byte
	for _, pfx := range [][]byte{
		concat(types.DkgDealPrefix, u64(epoch)),
		concat(types.DkgComplaintPrefix, u64(epoch)),
		// AUDIT FIX (DKG-SM-5-GC): the rejected-complaint negative cache had NO deleter and accumulated
		// permanently across every rekey; reclaim it with the epoch's dealings/complaints so per-epoch
		// state stays bounded (the eval-point key made the per-epoch cardinality O(n*S), worth GC'ing).
		concat(types.DkgComplaintRejectedPrefix, u64(epoch)),
	} {
		it, err := st.Iterator(pfx, prefixEnd(pfx))
		if err != nil {
			continue
		}
		for ; it.Valid(); it.Next() {
			keys = append(keys, append([]byte(nil), it.Key()...))
		}
		it.Close()
	}
	for _, key := range keys {
		_ = st.Delete(key)
	}
}

// purgeFailedRound GCs a FAILED, superseded round ENTIRELY — its dealings, complaints,
// AND the DkgRound record itself. It is called on auto-retry.
//
// HIGH-2 FIX: the previous code retained the per-epoch DkgRound record on every retry
// ("kept for history/telemetry"), and a DkgRound carries the full member list + enc
// keys. Under a SUSTAINED sub-quorum the EndBlocker opens a fresh epoch every backoff
// forever, so that retained record grew state without bound — a griefable, permanent
// DoS vector on the mempool key. Deleting the failed round's record here bounds retained
// round-record state to O(1) across an arbitrarily long outage. This is safe: a Failed
// round never became Active, so no ActiveThresholdKey and no EncTx/EncShare references
// its epoch (SubmitEncrypted stamps only the ACTIVE epoch), so nothing can dangle.
func (k Keeper) purgeFailedRound(ctx context.Context, epoch uint64) {
	k.purgeDealings(ctx, epoch)
	_ = k.store(ctx).Delete(dkgRoundKey(epoch))
}

// CountDkgRounds returns the number of retained DkgRound records. It backs the HIGH-2
// bounded-state regression test: a sustained sub-quorum must NOT grow round-record state
// without bound.
func (k Keeper) CountDkgRounds(ctx context.Context) int {
	return k.countPrefix(ctx, types.DkgRoundPrefix)
}

// CountActiveKeys returns the number of retained ActiveThresholdKey records. It backs
// the HIGH-2 VARIANT regression test: endless member-change rekeys must NOT grow retained
// active-epoch key state without bound (it stays O(epochs with pending ciphertexts)).
func (k Keeper) CountActiveKeys(ctx context.Context) int {
	return k.countPrefix(ctx, types.ActiveKeyPrefix)
}

func (k Keeper) countPrefix(ctx context.Context, pfx []byte) int {
	it, err := k.store(ctx).Iterator(pfx, prefixEnd(pfx))
	if err != nil {
		return 0
	}
	defer it.Close()
	n := 0
	for ; it.Valid(); it.Next() {
		n++
	}
	return n
}

// IterateComplaints visits every stored complaint for an epoch.
func (k Keeper) IterateComplaints(ctx context.Context, epoch uint64, fn func(types.DkgComplaintRec)) {
	pfx := concat(types.DkgComplaintPrefix, u64(epoch))
	it, err := k.store(ctx).Iterator(pfx, prefixEnd(pfx))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var c types.DkgComplaintRec
		if json.Unmarshal(it.Value(), &c) == nil {
			fn(c)
		}
	}
}

func (k Keeper) SetActiveKey(ctx context.Context, a types.ActiveThresholdKey) error {
	return k.store(ctx).Set(activeKeyKey(a.Epoch), mustJSON(a))
}

func (k Keeper) GetActiveKey(ctx context.Context, epoch uint64) (types.ActiveThresholdKey, bool) {
	bz, err := k.store(ctx).Get(activeKeyKey(epoch))
	if err != nil || bz == nil {
		return types.ActiveThresholdKey{}, false
	}
	var a types.ActiveThresholdKey
	if json.Unmarshal(bz, &a) != nil {
		return types.ActiveThresholdKey{}, false
	}
	return a, true
}

// DeleteActiveKey removes a superseded epoch's ActiveThresholdKey. HIGH-2 variant:
// the previous code had NO deleter, so every successful rekey retained its active key
// forever — a validator inducing member-change flaps could mint unbounded active-epoch
// records. This is only ever called by maybePruneEpoch, which first proves the epoch
// is superseded AND drained (no un-matured EncTx references it), so no in-flight
// decryption can lose its key.
func (k Keeper) DeleteActiveKey(ctx context.Context, epoch uint64) {
	_ = k.store(ctx).Delete(activeKeyKey(epoch))
	k.deleteShareKeyCache(ctx, epoch) // Fix 1 C4': the Y-cache is pinned to the epoch — drop it together
}

// ---- Fix 1 C4': precomputed public share-key cache (Y_index per epoch) ----

func activeShareKeyKey(epoch, index uint64) []byte {
	return concat(types.ActiveShareKeyPrefix, u64(epoch), u64(index))
}

// setShareKeyCache stores the compressed public share key Y_index for (epoch, index).
func (k Keeper) setShareKeyCache(ctx context.Context, epoch, index uint64, yCompressed []byte) {
	_ = k.store(ctx).Set(activeShareKeyKey(epoch, index), yCompressed)
}

// getShareKeyCache returns the cached compressed Y_index for (epoch, index), or nil if not cached
// (a cold / pre-C4' epoch, where verifyDecryptShareDLEQ falls back to recomputing SharePubKey).
func (k Keeper) getShareKeyCache(ctx context.Context, epoch, index uint64) []byte {
	bz, err := k.store(ctx).Get(activeShareKeyKey(epoch, index))
	if err != nil {
		return nil
	}
	return bz
}

// PrecomputeShareKeys computes + caches Y_1..Y_S for a finalized epoch (Fix 1 C4'), so every later
// decryption-share DLEQ verify is an O(1) cache read instead of an O(t) SharePubKey recompute. Called
// once at finalize. At the default budget (S=256) this is a sub-100ms one-shot; for a governance-max
// S=2048 committee it is a one-time ~1-2s finalize cost that a future change should chunk across the
// first blocks of the epoch (the verify fallback keeps it correct meanwhile). Deterministic (pure
// function of the committed PublicCommitments), so every node caches identical bytes.
// precomputeChunkSize bounds how many Y-cache indices are warmed per block, so the O(S*t) share-key
// precompute is spread over ceil(S/chunk) blocks instead of one halt-class finalize burst (HIGH-3).
// At the governance max S it caps per-block precompute EC work at chunk*O(t); the on-the-fly SharePubKey
// fallback in verify/recover keeps every not-yet-warmed index correct meanwhile.
const precomputeChunkSize uint64 = 128

func shareKeyCursorKey(epoch uint64) []byte {
	return concat(types.ShareKeyCursorPrefix, u64(epoch))
}

func (k Keeper) setShareKeyCursor(ctx context.Context, epoch, next uint64) {
	_ = k.store(ctx).Set(shareKeyCursorKey(epoch), u64(next))
}

func (k Keeper) getShareKeyCursor(ctx context.Context, epoch uint64) uint64 {
	bz, err := k.store(ctx).Get(shareKeyCursorKey(epoch))
	if err != nil || len(bz) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(bz)
}

func (k Keeper) deleteShareKeyCursor(ctx context.Context, epoch uint64) {
	_ = k.store(ctx).Delete(shareKeyCursorKey(epoch))
}

// PrecomputeShareKeys warms the FIRST chunk of the epoch's public-share-key cache at finalize and, if the
// point budget S exceeds one chunk, records a cursor so advancePrecomputeShareKeys warms the rest one
// bounded slice per block (HIGH-3: no O(S*t) finalize burst). The common small indices are hot
// immediately; every not-yet-warmed index is still correct via the on-the-fly SharePubKey fallback.
func (k Keeper) PrecomputeShareKeys(ctx context.Context, epoch uint64, publicCommitments [][]byte, budgetS int) {
	if budgetS <= 0 {
		return
	}
	S := uint64(budgetS)
	end := S
	if end > precomputeChunkSize {
		end = precomputeChunkSize
	}
	k.warmShareKeyRange(ctx, epoch, publicCommitments, 1, end)
	if S > end {
		k.setShareKeyCursor(ctx, epoch, end+1)
	}
}

// warmShareKeyRange computes + caches the compressed Y_from..Y_to for an epoch. Bounded EC work when the
// range is a chunk. A parse error leaves those indices cold (verify/recover recompute on the fly).
func (k Keeper) warmShareKeyRange(ctx context.Context, epoch uint64, publicCommitments [][]byte, from, to uint64) {
	keys, err := dkg.ShareKeysCompressedRange(publicCommitments, from, to)
	if err != nil {
		return
	}
	for i, yb := range keys {
		k.setShareKeyCache(ctx, epoch, from+uint64(i), yb)
	}
}

// advancePrecomputeShareKeys warms the next chunk of the ACTIVE epoch's Y-cache, one bounded slice per
// block, until [1, S] is fully cached (then it clears the cursor). Fully deterministic: it reads only
// committed state (active epoch, its cursor, its stored round + active key) and computes SharePubKey, so
// every node warms the exact same indices at the exact same heights. Called once per block from
// EndBlockDKG; a no-op when there is no pending precompute.
func (k Keeper) advancePrecomputeShareKeys(ctx context.Context) {
	// Warm EVERY epoch that still has a pending cursor — the ACTIVE epoch AND any superseded-but-pinned
	// epoch whose in-flight ciphertexts still need its Y-cache. XFIX (re-audit): keying only on
	// GetActiveEpoch stranded a superseded epoch's warm-up mid-way (a fast rekey moves the active pointer
	// on before the old epoch is fully warm), leaving indices cold forever and re-exposing the O(t^2)
	// cold decrypt/verify for that epoch's pinned ciphertexts. A GLOBAL per-block budget of
	// precomputeChunkSize indices is shared across the pending epochs in deterministic store order
	// (oldest epoch first — its ciphertexts mature soonest), so total per-block precompute EC work stays
	// bounded to one chunk even when several epochs warm concurrently.
	store := k.store(ctx)
	it, err := store.Iterator(types.ShareKeyCursorPrefix, prefixEnd(types.ShareKeyCursorPrefix))
	if err != nil {
		return
	}
	pfxLen := len(types.ShareKeyCursorPrefix)
	var epochs []uint64
	for ; it.Valid(); it.Next() {
		if key := it.Key(); len(key) >= pfxLen+8 {
			epochs = append(epochs, binary.BigEndian.Uint64(key[pfxLen:pfxLen+8]))
		}
	}
	it.Close()
	budget := precomputeChunkSize
	for _, epoch := range epochs {
		if budget == 0 {
			break
		}
		budget -= k.advanceEpochPrecompute(ctx, epoch, budget)
	}
}

// advanceEpochPrecompute warms up to `budget` of epoch's still-cold Y-cache indices (from its cursor),
// returning how many it warmed. Clears the cursor when [1,S] is fully warm or the epoch's key/round is
// gone. Deterministic: reads only committed state + computes SharePubKey.
func (k Keeper) advanceEpochPrecompute(ctx context.Context, epoch, budget uint64) uint64 {
	cursor := k.getShareKeyCursor(ctx, epoch)
	if cursor == 0 {
		return 0
	}
	ak, ok := k.GetActiveKey(ctx, epoch)
	if !ok {
		k.deleteShareKeyCursor(ctx, epoch)
		return 0
	}
	round, ok := k.GetDkgRound(ctx, epoch)
	if !ok {
		k.deleteShareKeyCursor(ctx, epoch)
		return 0
	}
	S := uint64(types.TotalEvalPoints(round.Members))
	if cursor > S {
		k.deleteShareKeyCursor(ctx, epoch)
		return 0
	}
	end := cursor + budget - 1
	if end > S {
		end = S
	}
	k.warmShareKeyRange(ctx, epoch, ak.PublicCommitments, cursor, end)
	if end >= S {
		k.deleteShareKeyCursor(ctx, epoch) // fully warm
	} else {
		k.setShareKeyCursor(ctx, epoch, end+1)
	}
	return end - cursor + 1
}

// deleteShareKeyCache removes the whole Y-cache for an epoch (keys collected first, then deleted, so
// the store iterator is not mutated mid-scan — deterministic). Called from DeleteActiveKey.
func (k Keeper) deleteShareKeyCache(ctx context.Context, epoch uint64) {
	pfx := concat(types.ActiveShareKeyPrefix, u64(epoch))
	it, err := k.store(ctx).Iterator(pfx, prefixEnd(pfx))
	if err != nil {
		return
	}
	var keys [][]byte
	for ; it.Valid(); it.Next() {
		keys = append(keys, append([]byte(nil), it.Key()...))
	}
	it.Close()
	for _, key := range keys {
		_ = k.store(ctx).Delete(key)
	}
	k.deleteShareKeyCursor(ctx, epoch)     // drop any pending precompute cursor with the cache
	k.resetDecryptStrandStreak(ctx, epoch) // drop the epoch's decrypt-health streak (MED-2) at prune
}

// ---- epoch in-flight ciphertext ref-count (pins an epoch's records until drained) ----

func epochEncCountKey(epoch uint64) []byte { return concat(types.EpochEncCountPrefix, u64(epoch)) }

// getEpochEncCount returns the number of un-matured EncTx stamped to an epoch.
func (k Keeper) getEpochEncCount(ctx context.Context, epoch uint64) uint64 {
	return k.readU64(ctx, epochEncCountKey(epoch))
}

// GetEpochEncCount exposes the per-epoch in-flight ref-count for regression tests that assert
// a drop path still releases the epoch ref-count (HIGH-2 safety).
func (k Keeper) GetEpochEncCount(ctx context.Context, epoch uint64) uint64 {
	return k.getEpochEncCount(ctx, epoch)
}

// incEpochEncCount is called when a ciphertext is submitted for an epoch.
func (k Keeper) incEpochEncCount(ctx context.Context, epoch uint64) {
	_ = k.store(ctx).Set(epochEncCountKey(epoch), u64(k.getEpochEncCount(ctx, epoch)+1))
}

// decEpochEncCount is called when a ciphertext matures (is deleted). It deletes the
// counter record when it returns to zero so the ref-count map stays O(live epochs).
func (k Keeper) decEpochEncCount(ctx context.Context, epoch uint64) {
	c := k.getEpochEncCount(ctx, epoch)
	if c > 0 {
		c--
	}
	if c == 0 {
		_ = k.store(ctx).Delete(epochEncCountKey(epoch))
		return
	}
	_ = k.store(ctx).Set(epochEncCountKey(epoch), u64(c))
}

// ---- last member-change rekey height (flap dampener) ----

func (k Keeper) GetLastRekeyHeight(ctx context.Context) uint64 {
	return k.readU64(ctx, types.LastRekeyHeightKey)
}
func (k Keeper) SetLastRekeyHeight(ctx context.Context, h uint64) {
	_ = k.store(ctx).Set(types.LastRekeyHeightKey, u64(h))
}

// maybePruneEpoch GCs a SUPERSEDED DKG epoch's DkgRound record + ActiveThresholdKey
// once it is safe — the HIGH-2 variant fix. GC-SAFETY RULE: an epoch is prunable ONLY
// when it is neither the currently-serving active epoch NOR the in-flight open round,
// AND no un-matured EncTx still references it (ref-count == 0). This preserves in-flight
// decryption: a ciphertext stamped to epoch E authorizes its decryption shares against
// GetDkgRound(E) and is recovered under GetActiveKey(E); both survive until E's last
// ciphertext matures, at which point the count hits zero and the epoch is reclaimed.
// It is deterministic (a pure function of committed state) so every node prunes
// identically. No-op when the epoch is not (yet) prunable.
func (k Keeper) maybePruneEpoch(ctx sdk.Context, epoch uint64) {
	if epoch == 0 {
		return // legacy trusted-setup path has no per-epoch DKG record
	}
	if epoch == k.GetActiveEpoch(ctx) || epoch == k.GetCurrentEpoch(ctx) {
		return // never prune the serving key or the in-flight open round
	}
	if k.getEpochEncCount(ctx, epoch) != 0 {
		return // still referenced by an un-matured ciphertext — keep for in-flight decrypt
	}
	// Superseded AND drained: reclaim the round record, the active key, and any residual
	// dealing bulk (defensive — member_change already purges dealings on a live rekey).
	k.purgeDealings(ctx, epoch)
	k.DeleteActiveKey(ctx, epoch)
	_ = k.store(ctx).Delete(dkgRoundKey(epoch))
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_dkg_epoch_pruned",
		sdk.NewAttribute("epoch", u64str(epoch)),
	))
}

func (k Keeper) GetCurrentEpoch(ctx context.Context) uint64 {
	return k.readU64(ctx, types.CurrentEpochKey)
}
func (k Keeper) SetCurrentEpoch(ctx context.Context, e uint64) {
	_ = k.store(ctx).Set(types.CurrentEpochKey, u64(e))
}
func (k Keeper) GetActiveEpoch(ctx context.Context) uint64 {
	return k.readU64(ctx, types.ActiveEpochKey)
}
func (k Keeper) SetActiveEpoch(ctx context.Context, e uint64) {
	_ = k.store(ctx).Set(types.ActiveEpochKey, u64(e))
}

func (k Keeper) readU64(ctx context.Context, key []byte) uint64 {
	bz, _ := k.store(ctx).Get(key)
	if len(bz) == 8 {
		return binary.BigEndian.Uint64(bz)
	}
	return 0
}

// ============================================================================
// Active member set = declared DkgMembers ∩ bonded validators (by operator addr),
// ranked by operator address, 1-based. A change to this set (validator bonds /
// unbonds / jails) changes MembersHash and triggers a DKG re-run.
// ============================================================================

// ActiveMembers returns the DKG member set for the current bonded validator set.
//
// TRANSPARENT path (p.DkgTransparent): members are the bonded validators that have
// AUTO-ANNOUNCED an enc key (top-N by stake), derived entirely on-chain — no declared
// list. LEGACY path: the genesis-declared DkgMembers INTERSECTED with the bonded set.
// If the staking keeper is unavailable it falls back to the full declared set (so unit
// tests and single-node smoke tests of the legacy path still function).
func (k Keeper) ActiveMembers(ctx context.Context, p types.Params) []types.RoundMember {
	if p.DkgTransparent {
		return k.TransparentMembers(ctx, p)
	}
	bonded := map[string]bool{}
	if k.stakingKeeper != nil {
		_ = k.stakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
			bonded[v.GetOperator()] = true
			return false
		})
	}
	// Select declared members that are currently bonded (or all, if we could not
	// read the bonded set at all — e.g. no staking keeper wired in a test).
	var chosen []types.DkgMember
	for _, m := range p.DkgMembers {
		if len(bonded) == 0 || bonded[m.OperatorAddr] {
			chosen = append(chosen, m)
		}
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].OperatorAddr < chosen[j].OperatorAddr })
	out := make([]types.RoundMember, len(chosen))
	for i, m := range chosen {
		out[i] = types.RoundMember{
			Index: uint64(i + 1), OperatorAddr: m.OperatorAddr,
			AccountAddr: m.AccountAddr, EncPubKey: m.EncPubKey,
		}
	}
	return out
}

// MembersHash is a deterministic digest of the active committee — the re-run trigger. It covers each
// member's identity/order AND its announced enc key (external-review #4: a key rotation must re-genesis so
// the epoch stops sealing to a stale key; rotations are rate-limited in RecordEncPubKey so this cannot be
// flapped for churn). It does NOT cover weights/eval-points, so AllocateEvalPoints (which mutates only
// those) never changes the hash after openRound computes it.
func MembersHash(members []types.RoundMember) []byte {
	h := sha256.New()
	for _, m := range members {
		h.Write([]byte(m.OperatorAddr))
		h.Write([]byte{0})
		// EXTERNAL-REVIEW #4: bind each member's announced ENC KEY into the hash so a key ROTATION changes
		// MembersHash and triggers a member-change re-genesis (the new epoch seals shares to the new key).
		// Without this, MembersHash saw only the operator set, so a rotated/compromised key kept being used
		// until decrypt-health failures (MED-2) eventually stranded + rekeyed. The 33-byte key is length-
		// fixed and the NUL separators keep the encoding unambiguous — still a pure function of committed state.
		h.Write(m.EncPubKey)
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// roundThreshold picks the COUNT threshold t for a round of n members: params.DkgThreshold
// if it is in [1, n], else the honest majority floor(n/2)+1. This governs the LEGACY/declared
// (unweighted) path, where every member holds exactly one Shamir share. The STAKE-WEIGHTED
// transparent path does NOT use it — there the threshold is t = floor(2S/3)-n+1 of the
// evaluation-point budget S (see stakeThreshold for the proof and the honest decrypt bar:
// assembling t points provably requires > 1/3 of committee stake in all valid configs,
// >= 2/3 - 2n/S in general — HIGH-3), and DkgThreshold (a member count) has no meaning.
func roundThreshold(p types.Params, n int) uint32 {
	if p.DkgThreshold >= 1 && int(p.DkgThreshold) <= n {
		return p.DkgThreshold
	}
	return uint32(n/2 + 1)
}

// ============================================================================
// Deterministic finalize: reconstruct the public dealings + verified complaints
// from committed state and run dkg.FinalizePublic. Every node computes an
// identical ActiveThresholdKey (or an identical "failed" outcome).
// ============================================================================

func (k Keeper) finalizeRound(ctx sdk.Context, round types.DkgRound) {
	// HIGH-3: build the per-member evaluation-point weights (stake-weighted transparent path)
	// or unit weights (unweighted legacy path, where OwnedEvalPoints == {Index}). The QUAL set
	// must collectively own >= round.Threshold points for the round to succeed — i.e. dealers
	// above the proven stake bar participated (> 1/3 of committee stake; see stakeThreshold) —
	// which for the unweighted path reduces EXACTLY to the original |QUAL| >= t check.
	members := make([]uint64, 0, len(round.Members))
	weightOf := make(map[uint64]int, len(round.Members))
	for _, m := range round.Members {
		members = append(members, m.Index)
		weightOf[m.Index] = len(m.OwnedEvalPoints())
	}

	var pubDealings []dkg.PublicDealing
	k.IterateDealings(ctx, round.Epoch, func(d types.Dealing) {
		pubDealings = append(pubDealings, dkg.PublicDealing{Dealer: d.DealerIndex, Commitments: d.Commitments})
	})

	var disq []uint64
	seenDisq := map[uint64]bool{}
	k.IterateComplaints(ctx, round.Epoch, func(c types.DkgComplaintRec) {
		if !seenDisq[c.Against] {
			seenDisq[c.Against] = true
			disq = append(disq, c.Against)
		}
	})

	res, err := dkg.FinalizePublicWeighted(members, int(round.Threshold), pubDealings, disq, weightOf, int(round.Threshold))
	if err != nil {
		round.Status = types.DkgStatusFailed
		_ = k.SetDkgRound(ctx, round)
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			"encmempool_dkg_failed",
			sdk.NewAttribute("epoch", u64str(round.Epoch)),
			sdk.NewAttribute("reason", err.Error()),
		))
		return
	}

	ak := types.ActiveThresholdKey{
		Epoch: round.Epoch, Pub: res.Pub, PublicCommitments: res.PublicCommitments,
		Threshold: round.Threshold, Qual: res.Qual,
	}
	_ = k.SetActiveKey(ctx, ak)
	// Fix 1 C4' (HIGH-U block-time flattener): precompute + cache the epoch's public share keys
	// Y_1..Y_S now, so every later decryption-share DLEQ verify is an O(1) cache read instead of an
	// O(t) SharePubKey recompute. Pinned to the epoch (dropped by DeleteActiveKey once drained).
	k.PrecomputeShareKeys(ctx, round.Epoch, ak.PublicCommitments, types.TotalEvalPoints(round.Members))
	// Capture the epoch this finalize SUPERSEDES before advancing the active pointer.
	prevActive := k.GetActiveEpoch(ctx)
	k.SetActiveEpoch(ctx, round.Epoch)
	round.Status = types.DkgStatusActive
	_ = k.SetDkgRound(ctx, round)
	// HIGH-2 variant: the just-superseded active epoch is now GC-eligible. Prune it
	// immediately if it holds ZERO in-flight ciphertexts; otherwise it stays pinned and
	// is reclaimed by decryptMatured when its last stamped ciphertext matures. This is
	// what bounds retained active-epoch state to O(pending epochs) across endless rekeys.
	if prevActive != 0 && prevActive != round.Epoch {
		k.maybePruneEpoch(ctx, prevActive)
	}

	qualJSON, _ := json.Marshal(res.Qual)
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_dkg_finalized",
		sdk.NewAttribute("epoch", u64str(round.Epoch)),
		sdk.NewAttribute("pub_hex", hexstr(res.Pub)),
		sdk.NewAttribute("threshold", u64str(uint64(round.Threshold))),
		sdk.NewAttribute("qual", string(qualJSON)),
	))
}
