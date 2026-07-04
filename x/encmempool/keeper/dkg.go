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
}

// ---- epoch in-flight ciphertext ref-count (pins an epoch's records until drained) ----

func epochEncCountKey(epoch uint64) []byte { return concat(types.EpochEncCountPrefix, u64(epoch)) }

// getEpochEncCount returns the number of un-matured EncTx stamped to an epoch.
func (k Keeper) getEpochEncCount(ctx context.Context, epoch uint64) uint64 {
	return k.readU64(ctx, epochEncCountKey(epoch))
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
// If the staking keeper is unavailable it falls back to the full declared set (so
// unit tests and single-node smoke tests still function).
func (k Keeper) ActiveMembers(ctx context.Context, p types.Params) []types.RoundMember {
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

// MembersHash is a deterministic digest of the active operator set — the re-run
// trigger. Only the identity/order of members matters (not their enc keys).
func MembersHash(members []types.RoundMember) []byte {
	h := sha256.New()
	for _, m := range members {
		h.Write([]byte(m.OperatorAddr))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// roundThreshold picks t for a round of n members: params.DkgThreshold if it is in
// [1, n], else the honest majority floor(n/2)+1.
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
	members := make([]uint64, 0, len(round.Members))
	for _, m := range round.Members {
		members = append(members, m.Index)
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

	res, err := dkg.FinalizePublic(members, int(round.Threshold), pubDealings, disq)
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
