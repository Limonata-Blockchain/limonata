package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"

	corestore "cosmossdk.io/core/store"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	anteinterfaces "github.com/cosmos/evm/ante/interfaces"
	"github.com/cosmos/evm/x/encmempool/types"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
)

// Keeper for x/encmempool. State is plain JSON-in-store (no proto), like x/contest.
// stakingKeeper is read-only and only consulted by the DKG EndBlocker to learn the
// bonded validator set (may be nil in unit tests that never exercise that path).
//
// evmKeeper + accountKeeper are used ONLY by the decrypt->EXECUTE re-injection path
// (EncExecEnabled, see evm_exec.go + DESIGN_EVM_REINJECTION.md). BOTH nil => execution is
// disabled - the dormant default AND the minimal-unit-test path. They are set only in the full
// app wiring (evmd/app.go).
type Keeper struct {
	storeService  corestore.KVStoreService
	stakingKeeper types.StakingKeeper
	evmKeeper     *evmkeeper.Keeper
	accountKeeper anteinterfaces.AccountKeeper
	bankKeeper    types.BankKeeper // round-9 #1: escrow/refund the submit bond; nil => bonding disabled
}

func NewKeeper(ss corestore.KVStoreService, sk types.StakingKeeper, evm *evmkeeper.Keeper, ak anteinterfaces.AccountKeeper, bk types.BankKeeper) Keeper {
	return Keeper{storeService: ss, stakingKeeper: sk, evmKeeper: evm, accountKeeper: ak, bankKeeper: bk}
}

func (k Keeper) store(ctx context.Context) corestore.KVStore { return k.storeService.OpenKVStore(ctx) }

// --- params ---

func (k Keeper) SetParams(ctx context.Context, p types.Params) error {
	bz, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(types.ParamsKey, bz)
}

func (k Keeper) GetParams(ctx context.Context) types.Params {
	bz, err := k.store(ctx).Get(types.ParamsKey)
	if err != nil || bz == nil {
		return types.DefaultParams()
	}
	var p types.Params
	if json.Unmarshal(bz, &p) != nil {
		return types.DefaultParams()
	}
	return p
}

// --- monotonic seq counter (disambiguates multiple commits at the same height) ---

func (k Keeper) nextSeq(ctx context.Context) uint64 {
	st := k.store(ctx)
	bz, _ := st.Get(types.SeqKey)
	var cur uint64
	if len(bz) == 8 {
		cur = binary.BigEndian.Uint64(bz)
	}
	_ = st.Set(types.SeqKey, u64(cur+1))
	return cur
}

// --- commits ---

func (k Keeper) SetCommit(ctx context.Context, c types.Commit) error {
	bz, err := json.Marshal(c)
	if err != nil {
		return err
	}
	st := k.store(ctx)
	key := commitKey(c.Height, c.Sender, c.Seq)
	// EXTERNAL-REVIEW #4: bump the admission ref-counts only for a genuinely NEW commit (idempotent — the
	// seq is monotonic so this is always new in practice, but the existence check keeps the count exact).
	if existing, _ := st.Get(key); existing == nil {
		k.incCommitCount(ctx, c.Sender)
	}
	return st.Set(key, bz)
}

func (k Keeper) GetCommit(ctx context.Context, height uint64, sender string, seq uint64) (types.Commit, bool) {
	bz, err := k.store(ctx).Get(commitKey(height, sender, seq))
	if err != nil || bz == nil {
		return types.Commit{}, false
	}
	var c types.Commit
	if json.Unmarshal(bz, &c) != nil {
		return types.Commit{}, false
	}
	return c, true
}

func (k Keeper) DeleteCommit(ctx context.Context, height uint64, sender string, seq uint64) {
	st := k.store(ctx)
	key := commitKey(height, sender, seq)
	// EXTERNAL-REVIEW #4: dec the admission ref-counts only if the commit was actually present, so a
	// double-delete (reveal path + GC path) can never underflow the count.
	if existing, _ := st.Get(key); existing != nil {
		k.decCommitCount(ctx, sender)
	}
	_ = st.Delete(key)
}

// --- pending reveals ---

func (k Keeper) SetPending(ctx context.Context, p types.PendingReveal) error {
	bz, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return k.store(ctx).Set(pendingKey(p.CommitHeight, p.Sender, p.Seq), bz)
}

func (k Keeper) DeletePending(ctx context.Context, commitHeight uint64, sender string, seq uint64) {
	_ = k.store(ctx).Delete(pendingKey(commitHeight, sender, seq))
}

// --- encrypted txs + decryption shares (threshold path) ---

func (k Keeper) nextEncSeq(ctx context.Context) uint64 {
	st := k.store(ctx)
	bz, _ := st.Get(types.EncSeqKey)
	var cur uint64
	if len(bz) == 8 {
		cur = binary.BigEndian.Uint64(bz)
	}
	_ = st.Set(types.EncSeqKey, u64(cur+1))
	return cur
}

// SubmitEncTx assigns a seq + decrypt height and stores the ciphertext, ordered by
// (decryptHeight, seq). The order is fixed here, before any body can be read.
func (k Keeper) SubmitEncTx(ctx context.Context, submitter string, submitHeight, decryptDelay uint64, a, nonce, body []byte, epoch uint64) types.EncTx {
	e := types.EncTx{
		Submitter: submitter, SubmitHeight: submitHeight,
		DecryptHeight: submitHeight + decryptDelay, Seq: k.nextEncSeq(ctx),
		A: a, Nonce: nonce, Body: body, Epoch: epoch,
	}
	_ = k.store(ctx).Set(encTxKey(e.DecryptHeight, e.Seq), mustJSON(e))
	// Ref-count this in-flight ciphertext against its DKG epoch so the epoch's
	// DkgRound + ActiveThresholdKey are pinned in state until it matures, and become
	// GC-eligible the instant the count returns to zero (HIGH-2 variant). Epoch 0 is
	// the legacy trusted-setup path (no per-epoch DKG record to prune).
	if epoch > 0 {
		k.incEpochEncCount(ctx, epoch)
	}
	// Admission-control ref-counts: total + per-submitter in-flight. These back the
	// ingress ceiling (SubmitEncrypted rejects when full) and the last-resort drop, and
	// are decremented by releaseEncTx when the ciphertext leaves state.
	k.incGlobalEncCount(ctx)
	k.incSubmitterEncCount(ctx, submitter)
	return e
}

// releaseEncTx removes an EncTx + its decryption shares from state and releases ALL of
// its ref-counts: the global + per-submitter in-flight admission counters and — for a
// DKG epoch — the epoch ref-count (pruning the epoch's DkgRound + ActiveThresholdKey if
// this was its last pending ciphertext). EVERY path that removes an EncTx (matured decrypt
// OR the last-resort ceiling drop) MUST go through here: a delete that skipped the epoch
// dec+prune would re-leak the epoch ref-count and REGRESS the HIGH-2 variant fix. It is
// deterministic (a pure function of committed state) so every node reclaims identically.
func (k Keeper) releaseEncTx(ctx sdk.Context, e types.EncTx) {
	k.DeleteEncTx(ctx, e.DecryptHeight, e.Seq)
	k.DeleteSharesFor(ctx, e.DecryptHeight, e.Seq)
	k.deleteRejectedSharesFor(ctx, e.DecryptHeight, e.Seq) // LIVENESS-4: drop the slot chaff cache with the ct
	k.decGlobalEncCount(ctx)
	k.decSubmitterEncCount(ctx, e.Submitter)
	if e.Epoch > 0 {
		k.decEpochEncCount(ctx, e.Epoch)
		k.maybePruneEpoch(ctx, e.Epoch)
	}
	k.refundBond(ctx, e) // round-9 #1: return the escrowed anti-sybil bond, whatever the release cause
}

// refundBond returns the anti-sybil bond escrowed for an EncTx (round-9 #1) IN FULL to its
// submitter. Called from releaseEncTx, the SINGLE choke point every EncTx removal passes through, so
// a matured decrypt AND a last-resort drop both refund. It returns exactly the amount stamped on the
// EncTx (immune to a later param change), and the module account always holds it (escrowed at submit),
// so the transfer cannot fail on funds. Deterministic (bank sends + committed EncTx fields).
func (k Keeper) refundBond(ctx sdk.Context, e types.EncTx) {
	if e.Bond == 0 || k.bankKeeper == nil {
		return
	}
	addr, err := sdk.AccAddressFromBech32(e.Submitter)
	if err != nil {
		return // submitter was bech32-validated at escrow, so this is unreachable; skip rather than panic
	}
	coins := sdk.NewCoins(sdk.NewCoin(e.BondDenom, sdkmath.NewIntFromUint64(e.Bond)))
	_ = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, coins)
}

// stampBond records the escrowed bond onto an already-stored EncTx (round-9 #1). Called from
// SubmitEncrypted right after SubmitEncTx, once the bond has been escrowed to the module account, so
// releaseEncTx later refunds exactly this amount.
func (k Keeper) stampBond(ctx context.Context, e types.EncTx, bond uint64, denom string) {
	e.Bond = bond
	e.BondDenom = denom
	_ = k.store(ctx).Set(encTxKey(e.DecryptHeight, e.Seq), mustJSON(e))
}

func (k Keeper) GetEncTx(ctx context.Context, decryptHeight, seq uint64) (types.EncTx, bool) {
	bz, err := k.store(ctx).Get(encTxKey(decryptHeight, seq))
	if err != nil || bz == nil {
		return types.EncTx{}, false
	}
	var e types.EncTx
	if json.Unmarshal(bz, &e) != nil {
		return types.EncTx{}, false
	}
	return e, true
}

func (k Keeper) DeleteEncTx(ctx context.Context, decryptHeight, seq uint64) {
	_ = k.store(ctx).Delete(encTxKey(decryptHeight, seq))
}

func (k Keeper) SetEncShare(ctx context.Context, s types.EncShare) error {
	return k.store(ctx).Set(encShareKey(s.DecryptHeight, s.Seq, s.Index), mustJSON(s))
}

func (k Keeper) DeleteSharesFor(ctx context.Context, decryptHeight, seq uint64) {
	for _, s := range k.CollectShares(ctx, decryptHeight, seq) {
		_ = k.store(ctx).Delete(encShareKey(decryptHeight, seq, s.Index))
	}
}

// IterateEncTxAtHeight visits every EncTx whose decrypt height == h, in seq order.
func (k Keeper) IterateEncTxAtHeight(ctx context.Context, h uint64, fn func(types.EncTx)) {
	pfx := concat(types.EncTxPrefix, u64(h))
	it, err := k.store(ctx).Iterator(pfx, prefixEnd(pfx))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var e types.EncTx
		if json.Unmarshal(it.Value(), &e) == nil {
			fn(e)
		}
	}
}

// IterateEncTxUpTo visits every EncTx whose decrypt height <= h, in (decryptHeight,
// seq) order — i.e. everything MATURED by height h, including any ciphertexts DEFERRED
// from an earlier height when the per-block decrypt cap was reached. Store keys are
// EncTxPrefix|be(decryptHeight)|be(seq), so a single ordered range scan [prefix,
// prefix|be(h+1)) yields exactly those in deterministic order on every node.
func (k Keeper) IterateEncTxUpTo(ctx context.Context, h uint64, fn func(types.EncTx)) {
	start := types.EncTxPrefix
	// Upper bound is EXCLUSIVE at be(h+1); saturate so h == MaxUint64 cannot wrap.
	end := concat(types.EncTxPrefix, u64(addSat(h, 1)))
	it, err := k.store(ctx).Iterator(start, end)
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var e types.EncTx
		if json.Unmarshal(it.Value(), &e) == nil {
			fn(e)
		}
	}
}

// CollectMaturedUpTo returns up to `limit` EncTx whose decrypt height <= h, in
// (decryptHeight, seq) order, and reports whether the scan was TRUNCATED (more matured
// entries exist beyond the limit). BOUNDED-SCAN GUARANTEE: it visits at most `limit`
// entries, so the per-block decrypt cost is O(limit), NOT O(backlog) — this is what makes
// a flood of ciphertexts unable to impose an unbounded per-block re-scan on every node.
// The truncated tail stays in state and is picked up on a later block (deterministic
// suffix on every node).
func (k Keeper) CollectMaturedUpTo(ctx context.Context, h uint64, limit int) (out []types.EncTx, truncated bool) {
	start := types.EncTxPrefix
	end := concat(types.EncTxPrefix, u64(addSat(h, 1))) // EXCLUSIVE upper bound at be(h+1)
	it, err := k.store(ctx).Iterator(start, end)
	if err != nil {
		return nil, false
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		if len(out) >= limit {
			return out, true // more remain beyond the bounded window
		}
		var e types.EncTx
		if json.Unmarshal(it.Value(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, false
}

// IterateInFlightFrom visits stored EncTx with decrypt_height >= minHeight, in
// (decryptHeight, seq) order, invoking fn for up to `limit` entries (stopping early if fn
// returns false). The upper bound is the exclusive end of the EncTx keyspace (the next
// prefix, EncSharePrefix). It backs the NODE-LOCAL construction of decryption-share vote
// extensions for not-yet-matured ciphertexts; the `limit` bounds the vote-extension size.
func (k Keeper) IterateInFlightFrom(ctx context.Context, minHeight uint64, limit int, fn func(types.EncTx) bool) {
	it, err := k.store(ctx).Iterator(concat(types.EncTxPrefix, u64(minHeight)), prefixEnd(types.EncTxPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	n := 0
	for ; it.Valid() && n < limit; it.Next() {
		var e types.EncTx
		if json.Unmarshal(it.Value(), &e) == nil {
			n++
			if !fn(e) {
				return
			}
		}
	}
}

// --- in-flight EncTx admission ref-counts (global + per-submitter) ---

func submitterEncCountKey(submitter string) []byte {
	return concat(types.SubmitterEncCountPrefix, []byte(submitter))
}

// GetGlobalEncCount returns the number of un-matured EncTx across all submitters. It is
// the O(1) admission gauge (never an O(backlog) scan) and backs the flood regression test.
func (k Keeper) GetGlobalEncCount(ctx context.Context) uint64 {
	return k.readU64(ctx, types.GlobalEncCountKey)
}

func (k Keeper) incGlobalEncCount(ctx context.Context) {
	_ = k.store(ctx).Set(types.GlobalEncCountKey, u64(k.GetGlobalEncCount(ctx)+1))
}

// --- decrypt-health streak (MED-2), keyed PER EPOCH: consecutive stranded maturities of THAT epoch's
// ciphertexts since the last successful decrypt of that epoch. A sustained streak signals that epoch's
// key cannot decrypt; when the ACTIVE epoch's streak trips, EndBlockDKG force-rekeys (recovery backstop).
func decryptStrandStreakKey(epoch uint64) []byte {
	return concat(types.DecryptStrandStreakPrefix, u64(epoch))
}

func (k Keeper) GetDecryptStrandStreak(ctx context.Context, epoch uint64) uint64 {
	return k.readU64(ctx, decryptStrandStreakKey(epoch))
}

func (k Keeper) bumpDecryptStrandStreak(ctx context.Context, epoch uint64) {
	_ = k.store(ctx).Set(decryptStrandStreakKey(epoch), u64(k.GetDecryptStrandStreak(ctx, epoch)+1))
}

func (k Keeper) resetDecryptStrandStreak(ctx context.Context, epoch uint64) {
	_ = k.store(ctx).Delete(decryptStrandStreakKey(epoch))
}

func (k Keeper) decGlobalEncCount(ctx context.Context) {
	c := k.GetGlobalEncCount(ctx)
	if c > 0 {
		c--
	}
	if c == 0 {
		_ = k.store(ctx).Delete(types.GlobalEncCountKey)
		return
	}
	_ = k.store(ctx).Set(types.GlobalEncCountKey, u64(c))
}

// GetSubmitterEncCount returns a submitter's un-matured EncTx count. The record is deleted
// at zero so live per-submitter counters stay O(submitters with pending ct).
func (k Keeper) GetSubmitterEncCount(ctx context.Context, submitter string) uint64 {
	return k.readU64(ctx, submitterEncCountKey(submitter))
}

func (k Keeper) incSubmitterEncCount(ctx context.Context, submitter string) {
	_ = k.store(ctx).Set(submitterEncCountKey(submitter), u64(k.GetSubmitterEncCount(ctx, submitter)+1))
}

// maxEncSubmitsPerBlockPerSubmitter is the PER-SUBMITTER per-block admission RATE limit (Fix 1 C3'):
// the missing rate dimension on top of the standing MaxInFlightPerSubmitter inventory cap. Being
// per-submitter (NEVER a single global slot) avoids the one-address permanent-DoS + proposer-censorship
// a global slot would create; a small constant keeps maturing-ciphertext inflow bounded so per-block
// DLEQ-verify work stays near marginal decryption progress (the "no admission rate limit => HIGH-U
// sustainable" clause). Final sizing + a sybil price on the submitter are tuned against a live drain;
// this const is the safe always-on backstop.
const maxEncSubmitsPerBlockPerSubmitter = 4

// maxCiphertextBodyBytes caps the GCM-sealed ciphertext body at ingress (external-review #2). The plaintext
// is a single anti-MEV transaction; 16 KiB is generous for one (a swap/trade is a few hundred bytes) while
// bounding per-ciphertext state + the later AES-GCM decrypt cost, so MaxInFlightEncTx * body stays bounded.
const maxCiphertextBodyBytes = 16384

// commit/reveal admission ceilings (external-review #4): bound the in-flight (un-revealed) commit state so
// the permissionless CommitTx path cannot be spammed into unbounded KV state + O(N) BeginBlock GC scans.
// The per-sender cap is a TINY fraction (1/512) of the global, so SATURATING the global — which would then
// reject honest senders' commits — needs ~512 funded sybil accounts, not the 16 a 1/16 ratio allowed
// (audit F1). A legit anti-MEV user holds only a handful of un-revealed commits, so 64 is ample headroom.
// (The COMPLETE anti-sybil answer is a stake/price gate on commit ingress — a design item, not a constant;
// this keeps the un-priced path bounded and far harder to wedge in the meantime.)
const (
	maxInFlightCommits  = 32768
	maxCommitsPerSender = 64
)

// --- commit/reveal in-flight ref-counts (O(1) admission gauges, inc in SetCommit, dec in DeleteCommit) ---

func submitterCommitCountKey(sender string) []byte {
	return concat(types.SubmitterCommitCountPrefix, []byte(sender))
}

// GetGlobalCommitCount returns the number of in-flight (un-revealed, un-GC'd) commits across all senders.
//
// DEPLOYMENT NOTE (audit F2): these counters are seeded by SetCommit (fresh genesis + live CommitTx). If
// this admission-cap feature is ever enabled via an IN-PLACE binary swap onto an ALREADY-POPULATED commit
// store, add a one-time migration that rebuilds them (IterateCommits -> incCommitCount) — otherwise the
// counter reads 0 until the pre-existing commit set turns over (bounded, self-healing, never underflows).
// The module is dormant/audit-gated, so a fresh genesis (which re-runs SetCommit) needs no migration.
func (k Keeper) GetGlobalCommitCount(ctx context.Context) uint64 {
	return k.readU64(ctx, types.GlobalCommitCountKey)
}

// GetSubmitterCommitCount returns a sender's in-flight commit count (record deleted at zero).
func (k Keeper) GetSubmitterCommitCount(ctx context.Context, sender string) uint64 {
	return k.readU64(ctx, submitterCommitCountKey(sender))
}

func (k Keeper) incCommitCount(ctx context.Context, sender string) {
	_ = k.store(ctx).Set(types.GlobalCommitCountKey, u64(k.GetGlobalCommitCount(ctx)+1))
	_ = k.store(ctx).Set(submitterCommitCountKey(sender), u64(k.GetSubmitterCommitCount(ctx, sender)+1))
}

func (k Keeper) decCommitCount(ctx context.Context, sender string) {
	if g := k.GetGlobalCommitCount(ctx); g > 1 {
		_ = k.store(ctx).Set(types.GlobalCommitCountKey, u64(g-1))
	} else {
		_ = k.store(ctx).Delete(types.GlobalCommitCountKey)
	}
	if s := k.GetSubmitterCommitCount(ctx, sender); s > 1 {
		_ = k.store(ctx).Set(submitterCommitCountKey(sender), u64(s-1))
	} else {
		_ = k.store(ctx).Delete(submitterCommitCountKey(sender))
	}
}

// EXTERNAL-REVIEW #7: key the per-block submit-rate counter by (height, submitter) so past-block entries
// form a delete-able prefix range and are GC'd (gcEncSubmitRate), instead of leaving one permanent entry
// per distinct-ever-submitter (a paid-sybil state leak the old submitter-only key allowed).
func encSubmitRateKey(height uint64, submitter string) []byte {
	return concat(types.EncSubmitRatePrefix, u64(height), []byte(submitter))
}

// maxRateGCPerBlock bounds how many stale submit-rate entries BeginBlock reclaims per block; the entries
// sort height-ascending so the oldest (stale) ones are reclaimed first and the backlog drains steadily.
// Set above the realistic per-block distinct-submitter inflow (a submit costs base gas, so even a
// high-gas-limit block admits well under this many distinct submitters) so the drain keeps pace with
// steady-state churn; a transient burst above it still drains, bounded, over subsequent blocks.
const maxRateGCPerBlock = 8192

// bumpEncSubmitsThisBlock increments and returns this submitter's admission count for `height`. The
// record is keyed by (height, submitter) so each block's counter is a fresh entry (count only), and
// past-block entries are reclaimed by gcEncSubmitRate in BeginBlock (EXTERNAL-REVIEW #7: the previous
// submitter-only key never deleted, leaking one entry per distinct-ever-submitter). The increment is O(1)
// in canonical DeliverTx order — deterministic on every node. A rejected submit's bump is discarded with
// its branched store, so the persisted count tracks ADMITTED submits.
func (k Keeper) bumpEncSubmitsThisBlock(ctx context.Context, submitter string, height uint64) uint64 {
	key := encSubmitRateKey(height, submitter) // height is IN the key -> each block's counter is separate
	bz, _ := k.store(ctx).Get(key)
	var cnt uint64
	if len(bz) == 8 {
		cnt = binary.BigEndian.Uint64(bz)
	}
	cnt++
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, cnt)
	_ = k.store(ctx).Set(key, out)
	return cnt
}

// gcEncSubmitRate reclaims up to maxRateGCPerBlock submit-rate entries from PAST blocks (height < current).
// Entries sort height-ascending, so the scan visits the oldest first and stops the instant it reaches the
// current height — bounded work per block that keeps the counter's KV footprint at ~one block's submitters.
func (k Keeper) gcEncSubmitRate(ctx context.Context, currentHeight uint64) {
	st := k.store(ctx)
	it, err := st.Iterator(types.EncSubmitRatePrefix, prefixEnd(types.EncSubmitRatePrefix))
	if err != nil {
		return
	}
	pfxLen := len(types.EncSubmitRatePrefix)
	var stale [][]byte
	for ; it.Valid() && len(stale) < maxRateGCPerBlock; it.Next() {
		key := it.Key()
		if len(key) < pfxLen+8 {
			continue
		}
		if binary.BigEndian.Uint64(key[pfxLen:pfxLen+8]) >= currentHeight {
			break // reached current/future entries (height-ascending order) — nothing older remains
		}
		stale = append(stale, append([]byte(nil), key...))
	}
	it.Close()
	for _, key := range stale {
		_ = st.Delete(key)
	}
}

func (k Keeper) decSubmitterEncCount(ctx context.Context, submitter string) {
	c := k.GetSubmitterEncCount(ctx, submitter)
	if c > 0 {
		c--
	}
	if c == 0 {
		_ = k.store(ctx).Delete(submitterEncCountKey(submitter))
		return
	}
	_ = k.store(ctx).Set(submitterEncCountKey(submitter), u64(c))
}

// CollectShares returns all decryption shares for a given (decryptHeight, seq).
func (k Keeper) CollectShares(ctx context.Context, h, seq uint64) []types.EncShare {
	pfx := concat(types.EncSharePrefix, u64(h), u64(seq))
	it, err := k.store(ctx).Iterator(pfx, prefixEnd(pfx))
	if err != nil {
		return nil
	}
	defer it.Close()
	var out []types.EncShare
	for ; it.Valid(); it.Next() {
		var s types.EncShare
		if json.Unmarshal(it.Value(), &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// hasEncShareAt reports whether a decryption share is ALREADY stored at the exact eval-point slot
// (decryptHeight, seq, index). It is an O(1) point lookup (encShareKey is keyed by the eval-point
// index, and a point is owned by exactly one member), so it backs the first-wins share dedup on the
// hot vote-extension ingest path WITHOUT the O(S) allocate-and-scan of CollectShares — the cheap
// pre-check the cycle-8 verify bound relies on to short-circuit a re-sent share before any DLEQ work.
func (k Keeper) hasEncShareAt(ctx context.Context, decryptHeight, seq, index uint64) bool {
	bz, err := k.store(ctx).Get(encShareKey(decryptHeight, seq, index))
	return err == nil && bz != nil
}

// --- iteration (genesis export + BeginBlock); keys are pre-sorted big-endian ---

func (k Keeper) IterateCommits(ctx context.Context, fn func(types.Commit)) {
	it, err := k.store(ctx).Iterator(types.CommitPrefix, prefixEnd(types.CommitPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var c types.Commit
		if json.Unmarshal(it.Value(), &c) == nil {
			fn(c)
		}
	}
}

func (k Keeper) IteratePending(ctx context.Context, fn func(types.PendingReveal)) {
	it, err := k.store(ctx).Iterator(types.PendingPrefix, prefixEnd(types.PendingPrefix))
	if err != nil {
		return
	}
	defer it.Close()
	for ; it.Valid(); it.Next() {
		var p types.PendingReveal
		if json.Unmarshal(it.Value(), &p) == nil {
			fn(p)
		}
	}
}

// --- key builders + helpers (big-endian height/seq for deterministic ordering) ---

func commitKey(height uint64, sender string, seq uint64) []byte {
	return concat(types.CommitPrefix, u64(height), []byte(sender), u64(seq))
}

func pendingKey(commitHeight uint64, sender string, seq uint64) []byte {
	return concat(types.PendingPrefix, u64(commitHeight), []byte(sender), u64(seq))
}

func encTxKey(decryptHeight, seq uint64) []byte {
	return concat(types.EncTxPrefix, u64(decryptHeight), u64(seq))
}

// encShareKey keys a decryption share by its Shamir evaluation-point INDEX (not the keyper).
// HIGH-3: on the stake-weighted path a single keyper owns MULTIPLE evaluation points and thus
// submits MULTIPLE shares per ciphertext, so keying by keyper would collide them. The eval-point
// index is globally unique per round (a point is owned by exactly one member) and unique per
// keyper on the unweighted legacy path (index == member index), so this is a safe, deterministic
// dedup key on both paths.
func encShareKey(decryptHeight, seq, index uint64) []byte {
	return concat(types.EncSharePrefix, u64(decryptHeight), u64(seq), u64(index))
}

// --- rejected-decrypt-share negative cache (LIVENESS-4): a slot (decryptHeight, seq, index) whose share
// failed the DLEQ verify, so a re-sent chaff is dropped O(1) instead of re-charging the O(t) DLEQ. Deleted
// with the ciphertext's shares in releaseEncTx.
func rejectedShareKey(decryptHeight, seq, index uint64) []byte {
	return concat(types.RejectedDecryptSharePrefix, u64(decryptHeight), u64(seq), u64(index))
}

func (k Keeper) setRejectedShare(ctx context.Context, decryptHeight, seq, index uint64) {
	_ = k.store(ctx).Set(rejectedShareKey(decryptHeight, seq, index), []byte{1})
}

func (k Keeper) hasRejectedShare(ctx context.Context, decryptHeight, seq, index uint64) bool {
	bz, err := k.store(ctx).Get(rejectedShareKey(decryptHeight, seq, index))
	return err == nil && bz != nil
}

func (k Keeper) deleteRejectedSharesFor(ctx context.Context, decryptHeight, seq uint64) {
	pfx := concat(types.RejectedDecryptSharePrefix, u64(decryptHeight), u64(seq))
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
}

func mustJSON(v any) []byte {
	bz, _ := json.Marshal(v)
	return bz
}

func u64str(v uint64) string { return strconv.FormatUint(v, 10) }

func hexstr(b []byte) string { return hex.EncodeToString(b) }

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func prefixEnd(p []byte) []byte {
	end := make([]byte, len(p))
	copy(end, p)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xFF {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}
