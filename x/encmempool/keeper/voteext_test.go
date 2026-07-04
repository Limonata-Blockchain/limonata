package keeper_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	sdkmath "cosmossdk.io/math"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// encPoP builds a valid enc-key proof-of-possession for a test member (the enc key signs
// its own operator identity). Every transparent announce path needs one now (HIGH-2/HIGH-4).
func encPoP(m member) []byte { return dkg.SignEncKeyPoP(m.priv, m.op) }

// annVE builds a member's key-announcement vote extension (key + PoP).
func annVE(m member) types.VoteExtension {
	return types.VoteExtension{EncPubKey: m.pub, EncPubKeyPoP: encPoP(m)}
}

// mockStaking is a minimal StakingKeeper: it returns a fixed bonded validator set.
// Order is irrelevant — TransparentMembers re-ranks deterministically.
type mockStaking struct{ vals []stakingtypes.Validator }

func (m *mockStaking) IterateBondedValidatorsByPower(_ context.Context, fn func(int64, stakingtypes.ValidatorI) bool) error {
	for i := range m.vals {
		if fn(int64(i), m.vals[i]) {
			break
		}
	}
	return nil
}

func bondedVal(op string, tokens int64) stakingtypes.Validator {
	return stakingtypes.Validator{OperatorAddress: op, Tokens: sdkmath.NewInt(tokens), Status: stakingtypes.Bonded}
}

// newKeeperSK wires a keeper with a mock staking keeper (for the transparent path).
func newKeeperSK(t *testing.T, height int64, sk types.StakingKeeper) (keeper.Keeper, sdk.Context) {
	t.Helper()
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_encmempool_ve")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)
	k := keeper.NewKeeper(runtime.NewKVStoreService(key), sk)
	ctx := testCtx.Ctx.WithBlockHeight(height).WithEventManager(sdk.NewEventManager())
	return k, ctx
}

func transparentParams(thr uint32, maxMembers uint32) types.Params {
	return types.Params{
		RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: true, DecryptDelay: 2,
		DkgEnabled: true, DkgTransparent: true, DkgStartHeight: 1,
		DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: thr, DkgMaxMembers: maxMembers,
		DkgRetryBackoff: 5, DkgMaxAttempts: 8, DkgMinRekeyGap: 0,
		// HIGH-3: a SMALL stake-apportionment budget keeps test dealings tiny/fast while still
		// exercising the stake-weighted eval-point path (the live default is 256). With S=24 the
		// reconstruction threshold is t = floor(2*24/3)+1 = 17.
		DkgShareBudget: 24,
	}
}

// transparentStakeThreshold is the stake-weighted reconstruction threshold t = floor(2S/3)+1
// for the test share budget S, mirroring keeper.stakeThreshold for assertions.
const transparentStakeThreshold = 2*24/3 + 1 // = 17

func idxByOp(round types.DkgRound, op string) uint64 {
	for _, m := range round.Members {
		if m.OperatorAddr == op {
			return m.Index
		}
	}
	return 0
}

// TestTransparent_CommitteeSelection: members are the bonded validators that registered an
// enc key, capped to the top-N by stake, indexed by operator address (deterministic).
func TestTransparent_CommitteeSelection(t *testing.T) {
	m1, m2, m3, m4 := newMember("opA", ""), newMember("opB", ""), newMember("opC", ""), newMember("opD", "")
	sk := &mockStaking{vals: []stakingtypes.Validator{
		bondedVal("opA", 10), bondedVal("opB", 40), bondedVal("opC", 30), bondedVal("opD", 20),
		bondedVal("opE", 99), // highest stake but NO registered enc key -> excluded
	}}
	k, ctx := newKeeperSK(t, 1, sk)
	// Register enc keys for A..D (not E).
	for _, m := range []member{m1, m2, m3, m4} {
		k.RecordEncPubKey(ctx, m.op, m.pub, encPoP(m))
	}
	p := transparentParams(2, 2) // committee cap = 2

	members := k.ActiveMembers(ctx, p)
	if len(members) != 2 {
		t.Fatalf("expected top-2 committee, got %d", len(members))
	}
	// Top-2 by stake are opB(40) and opC(30); indexed by operator order -> opB=1, opC=2.
	if members[0].OperatorAddr != "opB" || members[0].Index != 1 {
		t.Fatalf("member[0] = %+v, want opB idx 1", members[0])
	}
	if members[1].OperatorAddr != "opC" || members[1].Index != 2 {
		t.Fatalf("member[1] = %+v, want opC idx 2", members[1])
	}
	if !bytes.Equal(members[0].EncPubKey, m2.pub) || !bytes.Equal(members[1].EncPubKey, m3.pub) {
		t.Fatal("committee enc keys do not match the registered keys")
	}
}

// TestTransparent_EncKeyIdempotentAndDormant: ConsumeVoteExtensions records enc keys only
// when the transparent path is active, and re-announcing the same key is a no-op.
func TestTransparent_EncKeyIdempotentAndDormant(t *testing.T) {
	m1 := newMember("opA", "")
	k, ctx := newKeeperSK(t, 1, &mockStaking{})

	// Dormant: DkgEnabled/DkgTransparent off -> no registration.
	_ = k.SetParams(ctx, types.DefaultParams())
	k.ConsumeVoteExtensions(ctx, []keeper.VEEntry{{Operator: m1.op, VE: annVE(m1)}})
	if _, ok := k.GetEncPubKey(ctx, m1.op); ok {
		t.Fatal("dormant path must not register enc keys")
	}

	// Active: registers on first announce; idempotent thereafter.
	_ = k.SetParams(ctx, transparentParams(1, 0))
	if changed := k.RecordEncPubKey(ctx, m1.op, m1.pub, encPoP(m1)); !changed {
		t.Fatal("first announce should register")
	}
	if changed := k.RecordEncPubKey(ctx, m1.op, m1.pub, encPoP(m1)); changed {
		t.Fatal("re-announcing the same key must be a no-op")
	}
	if got, ok := k.GetEncPubKey(ctx, m1.op); !ok || !bytes.Equal(got, m1.pub) {
		t.Fatal("enc key not stored correctly")
	}
}

// setupTransparentRound opens epoch 1 over the 3 given members via the real EndBlocker,
// after auto-registering their enc keys through ConsumeVoteExtensions (the announce path).
func setupTransparentRound(t *testing.T, members []member) (keeper.Keeper, sdk.Context, types.DkgRound, types.Params) {
	t.Helper()
	vals := make([]stakingtypes.Validator, len(members))
	for i, m := range members {
		vals[i] = bondedVal(m.op, int64(100+i))
	}
	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(2, 0)
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Auto-announce enc keys via the vote-extension consume path (no manual registration).
	ann := make([]keeper.VEEntry, len(members))
	for i, m := range members {
		ann[i] = keeper.VEEntry{Operator: m.op, VE: annVE(m)}
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)
	// EndBlocker opens epoch 1 with the transparent member set.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok || round.Status != types.DkgStatusOpen || len(round.Members) != len(members) {
		t.Fatalf("epoch 1 not opened over transparent members: %+v", round)
	}
	return k, ctx, round, p
}

func buildDealingEntry(t *testing.T, round types.DkgRound, m member) keeper.VEEntry {
	t.Helper()
	idx := idxByOp(round, m.op)
	if idx == 0 {
		t.Fatalf("%s not a member of the round", m.op)
	}
	d, err := dkgnode.BuildDealing(round.Epoch, round.Members, idx, int(round.Threshold))
	if err != nil {
		t.Fatalf("BuildDealing: %v", err)
	}
	return keeper.VEEntry{Operator: m.op, VE: types.VoteExtension{EncPubKey: m.pub, EncPubKeyPoP: encPoP(m), Dealing: d}}
}

// TestTransparent_DealAndFinalize: dealings ingested from vote extensions finalize into an
// active key — the whole transparent DKG loop with NO tx / daemon / declared members.
func TestTransparent_DealAndFinalize(t *testing.T) {
	members := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	k, ctx, round, _ := setupTransparentRound(t, members)

	entries := make([]keeper.VEEntry, len(members))
	for i, m := range members {
		entries[i] = buildDealingEntry(t, round, m)
	}
	// Consume dealings at h=2 (inside the deal window).
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), entries)

	stored := 0
	k.IterateDealings(ctx, 1, func(types.Dealing) { stored++ })
	if stored != 3 {
		t.Fatalf("expected 3 dealings stored, got %d", stored)
	}

	// Finalize at/after the complaint deadline.
	k.EndBlockDKG(ctx.WithBlockHeight(int64(round.ComplaintDeadline)))
	ak, ok := k.GetActiveKey(ctx, 1)
	if !ok {
		t.Fatal("no active key after finalize")
	}
	if len(ak.Qual) != 3 || ak.Threshold != transparentStakeThreshold || len(ak.Pub) != 33 {
		t.Fatalf("unexpected active key: qual=%v t=%d (want %d) publen=%d", ak.Qual, ak.Threshold, transparentStakeThreshold, len(ak.Pub))
	}
	if r, _ := k.GetDkgRound(ctx, 1); r.Status != types.DkgStatusActive {
		t.Fatalf("round not active: %s", r.Status)
	}
}

// TestTransparent_ConsumeOrderIndependent: the SAME dealing payloads consumed in different
// vote orders produce byte-identical stored state (the fork-safety property).
func TestTransparent_ConsumeOrderIndependent(t *testing.T) {
	members := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}

	// Keeper A + its round; build the (random) dealings ONCE against A's round.
	kA, ctxA, roundA, _ := setupTransparentRound(t, members)
	entries := make([]keeper.VEEntry, len(members))
	for i, m := range members {
		entries[i] = buildDealingEntry(t, roundA, m)
	}

	// Keeper B: identical setup -> identical round (index assignment is deterministic).
	kB, ctxB, roundB, _ := setupTransparentRound(t, members)
	for _, m := range members {
		if idxByOp(roundA, m.op) != idxByOp(roundB, m.op) {
			t.Fatal("member indices diverged between identical setups (non-determinism)")
		}
	}

	// Consume forward on A, reversed on B.
	kA.ConsumeVoteExtensions(ctxA.WithBlockHeight(2), append([]keeper.VEEntry(nil), entries...))
	rev := []keeper.VEEntry{entries[2], entries[1], entries[0]}
	kB.ConsumeVoteExtensions(ctxB.WithBlockHeight(2), rev)

	for _, m := range members {
		idx := idxByOp(roundA, m.op)
		da, okA := kA.GetDealing(ctxA, 1, idx)
		db, okB := kB.GetDealing(ctxB, 1, idx)
		if !okA || !okB {
			t.Fatalf("dealing missing for idx %d (A=%v B=%v)", idx, okA, okB)
		}
		if !bytes.Equal(mustJSONBytes(da), mustJSONBytes(db)) {
			t.Fatalf("stored dealing for idx %d differs between consume orders", idx)
		}
	}
}

// TestTransparent_DealingRejects: malformed / stale / non-member / duplicate dealings are
// dropped deterministically and never enter state.
func TestTransparent_DealingRejects(t *testing.T) {
	members := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}
	k, ctx, round, _ := setupTransparentRound(t, members)

	// Non-member operator: dropped.
	good := buildDealingEntry(t, round, members[0])
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), []keeper.VEEntry{{Operator: "opX", VE: good.VE}})
	if _, ok := k.GetDealing(ctx, 1, idxByOp(round, "opX")); ok {
		t.Fatal("non-member dealing must be rejected")
	}

	// Malformed (wrong commitment count): dropped.
	bad := buildDealingEntry(t, round, members[1])
	bad.VE.Dealing.Commitments = bad.VE.Dealing.Commitments[:1] // threshold is 2
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), []keeper.VEEntry{bad})
	if _, ok := k.GetDealing(ctx, 1, idxByOp(round, members[1].op)); ok {
		t.Fatal("malformed dealing must be rejected")
	}

	// Stale epoch: dropped.
	stale := buildDealingEntry(t, round, members[2])
	stale.VE.Dealing.Epoch = 999
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), []keeper.VEEntry{stale})
	if _, ok := k.GetDealing(ctx, 1, idxByOp(round, members[2].op)); ok {
		t.Fatal("stale-epoch dealing must be rejected")
	}

	// First-wins: a second dealing from the same operator does not overwrite the first.
	first := buildDealingEntry(t, round, members[0])
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), []keeper.VEEntry{first})
	stored1, _ := k.GetDealing(ctx, 1, idxByOp(round, members[0].op))
	second := buildDealingEntry(t, round, members[0]) // fresh random dealing
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(2), []keeper.VEEntry{second})
	stored2, _ := k.GetDealing(ctx, 1, idxByOp(round, members[0].op))
	if !bytes.Equal(mustJSONBytes(stored1), mustJSONBytes(stored2)) {
		t.Fatal("first-wins violated: a later dealing overwrote the stored one")
	}
}

// TestTransparent_ShareIngest: decryption shares carried on vote extensions are authorized
// by operator/member-index and deduped first-wins.
func TestTransparent_ShareIngest(t *testing.T) {
	m1 := newMember("op1", "")
	k, ctx := newKeeperSK(t, 10, &mockStaking{vals: []stakingtypes.Validator{bondedVal("op1", 100)}})
	_ = k.SetParams(ctx, transparentParams(1, 0))

	// A round for epoch 5 with op1 at index 1, and an EncTx stamped to epoch 5.
	round := types.DkgRound{Epoch: 5, Threshold: 1, Status: types.DkgStatusActive,
		Members: []types.RoundMember{{Index: 1, OperatorAddr: "op1", EncPubKey: m1.pub}}}
	_ = k.SetDkgRound(ctx, round)
	e := k.SubmitEncTx(ctx, "user", 10, 2, []byte("A-not-verified-here"), make([]byte, threshold.NonceSize), []byte("body"), 5)

	sh := types.VoteExtShare{Epoch: 5, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: 1, D: []byte("d-share"), Proof: nil}
	entry := keeper.VEEntry{Operator: "op1", VE: types.VoteExtension{EncPubKey: m1.pub, Shares: []types.VoteExtShare{sh}}}

	k.ConsumeVoteExtensions(ctx, []keeper.VEEntry{entry})
	got := k.CollectShares(ctx, e.DecryptHeight, e.Seq)
	if len(got) != 1 || got[0].Index != 1 || got[0].Keyper != "op1" {
		t.Fatalf("share not ingested correctly: %+v", got)
	}

	// Wrong index: rejected.
	wrong := entry
	wrong.VE.Shares = []types.VoteExtShare{{Epoch: 5, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: 2, D: []byte("x")}}
	k.ConsumeVoteExtensions(ctx, []keeper.VEEntry{wrong})
	if got := k.CollectShares(ctx, e.DecryptHeight, e.Seq); len(got) != 1 {
		t.Fatalf("wrong-index share must be rejected, have %d shares", len(got))
	}

	// Non-member operator: rejected.
	k.ConsumeVoteExtensions(ctx, []keeper.VEEntry{{Operator: "opZ", VE: types.VoteExtension{Shares: []types.VoteExtShare{sh}}}})
	if got := k.CollectShares(ctx, e.DecryptHeight, e.Seq); len(got) != 1 {
		t.Fatalf("non-member share must be rejected, have %d shares", len(got))
	}
}

// mustJSONBytes marshals a Dealing deterministically for comparison.
func mustJSONBytes(d types.Dealing) []byte {
	b, _ := json.Marshal(d)
	return b
}
