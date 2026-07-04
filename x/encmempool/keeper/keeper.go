package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"

	corestore "cosmossdk.io/core/store"

	"github.com/cosmos/evm/x/encmempool/types"
)

// Keeper for x/encmempool. State is plain JSON-in-store (no proto), like x/contest.
// stakingKeeper is read-only and only consulted by the DKG EndBlocker to learn the
// bonded validator set (may be nil in unit tests that never exercise that path).
type Keeper struct {
	storeService  corestore.KVStoreService
	stakingKeeper types.StakingKeeper
}

func NewKeeper(ss corestore.KVStoreService, sk types.StakingKeeper) Keeper {
	return Keeper{storeService: ss, stakingKeeper: sk}
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
	return k.store(ctx).Set(commitKey(c.Height, c.Sender, c.Seq), bz)
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
	_ = k.store(ctx).Delete(commitKey(height, sender, seq))
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
	return e
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
	return k.store(ctx).Set(encShareKey(s.DecryptHeight, s.Seq, s.Keyper), mustJSON(s))
}

func (k Keeper) DeleteSharesFor(ctx context.Context, decryptHeight, seq uint64) {
	for _, s := range k.CollectShares(ctx, decryptHeight, seq) {
		_ = k.store(ctx).Delete(encShareKey(decryptHeight, seq, s.Keyper))
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

func encShareKey(decryptHeight, seq uint64, keyper string) []byte {
	return concat(types.EncSharePrefix, u64(decryptHeight), u64(seq), []byte(keyper))
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
