package keeper_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-6 (exhaustive re-audit) — items (c) rekey STORMS and (e) determinism
// across MANY heights x MANY nodes, including through the deferral flood.
// ============================================================================

// dkgDigest is a byte-identical fingerprint of the DKG-relevant module state — every field a
// divergence would show up in. Two nodes over the same committed inputs must produce the same
// digest at every height (the #1 fork-safety property).
func dkgDigest(k keeper.Keeper, ctx sdk.Context) string {
	h := sha256.New()
	cur := k.GetCurrentEpoch(ctx)
	act := k.GetActiveEpoch(ctx)
	fmt.Fprintf(h, "cur=%d act=%d last=%d rounds=%d keys=%d|",
		cur, act, k.GetLastRekeyHeight(ctx), k.CountDkgRounds(ctx), k.CountActiveKeys(ctx))
	if r, ok := k.GetDkgRound(ctx, cur); ok {
		fmt.Fprintf(h, "status=%s t=%d mh=%s members=%d|",
			r.Status, r.Threshold, hex.EncodeToString(r.MembersHash), len(r.Members))
		for _, m := range r.Members {
			fmt.Fprintf(h, "%s:%d:%v;", m.OperatorAddr, m.Index, m.OwnedEvalPoints())
		}
	}
	if ak, ok := k.GetActiveKey(ctx, act); ok {
		fmt.Fprintf(h, "|pub=%s qual=%v", hex.EncodeToString(ak.Pub), ak.Qual)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// inFlightDigest fingerprints the in-flight ciphertext set + its ref-counts (the decrypt-path
// determinism signal used through the flood).
func inFlightDigest(k keeper.Keeper, ctx sdk.Context) string {
	var seqs []uint64
	k.IterateEncTxUpTo(ctx, ^uint64(0)>>1, func(e types.EncTx) { seqs = append(seqs, e.Seq) })
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	h := sha256.New()
	fmt.Fprintf(h, "n=%d glob=%d|", len(seqs), k.GetGlobalEncCount(ctx))
	for _, s := range seqs {
		fmt.Fprintf(h, "%d,", s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func removeValByOp(sk *mockStaking, op string) {
	out := sk.vals[:0:0]
	for _, v := range sk.vals {
		if v.OperatorAddress != op {
			out = append(out, v)
		}
	}
	sk.vals = out
}

func addOrSetVal(sk *mockStaking, op string, tokens int64) {
	for i := range sk.vals {
		if sk.vals[i].OperatorAddress == op {
			sk.vals[i] = bondedVal(op, tokens)
			return
		}
	}
	sk.vals = append(sk.vals, bondedVal(op, tokens))
}

// TestCycle6_RekeyStorm_StakeDriftBoundedByGapAndDeterministic drives a STORM: continuous
// per-block re-delegation (stake drift always "due") plus two membership toggles, across 200
// heights, on TWO nodes sharing one validator view and one canonical dealing stream. It proves
// the storm cannot break the three invariants the cadence/stake-drift rekey rests on:
//
//	(bounded rate) the DkgMinRekeyGap flap-dampener holds every rekey >= gap blocks apart;
//	(bounded state) round-record + active-key state stay O(1) across the whole storm;
//	(deterministic) both nodes hold byte-identical DKG state at EVERY height.
func TestCycle6_RekeyStorm_StakeDriftBoundedByGapAndDeterministic(t *testing.T) {
	const gap = 20
	const H = 200
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", ""), newMember("op4", "")}
	memByOp := map[string]member{}
	for _, m := range mem {
		memByOp[m.op] = m
	}
	sk := &mockStaking{vals: []stakingtypes.Validator{
		bondedVal("op1", 100), bondedVal("op2", 100), bondedVal("op3", 100), bondedVal("op4", 100),
	}}
	mkParams := func() types.Params {
		p := transparentParams(2, 4)
		p.DkgShareBudget = 32
		p.DkgDealWindow = 1
		p.DkgComplaintWindow = 1
		p.DkgRetryBackoff = 1
		p.DkgStartHeight = 1
		p.DkgRekeyOnStakeDriftBps = 1 // any drift triggers => the storm is maximally aggressive
		p.DkgMinRekeyGap = gap
		return p
	}
	kA, ctxA := newKeeperSK(t, 1, sk)
	kB, ctxB := newKeeperSK(t, 1, sk)
	if err := kA.SetParams(ctxA, mkParams()); err != nil {
		t.Fatal(err)
	}
	if err := kB.SetParams(ctxB, mkParams()); err != nil {
		t.Fatal(err)
	}
	for _, m := range mem {
		kA.RecordEncPubKey(ctxA, m.op, m.pub, encPoP(m))
		kB.RecordEncPubKey(ctxB, m.op, m.pub, encPoP(m))
	}

	// feedDealings supplies the current open round (identical on both nodes) with a canonical
	// dealing per member, built ONCE and fed to both so the two nodes ingest identical bytes.
	feedDealings := func(h int) {
		cur := kA.GetCurrentEpoch(ctxA)
		if cur == 0 {
			return
		}
		r, ok := kA.GetDkgRound(ctxA, cur)
		if !ok || r.Status != types.DkgStatusOpen || uint64(h) > r.DealDeadline {
			return
		}
		var entries []keeper.VEEntry
		for _, rm := range r.Members {
			entries = append(entries, buildDealingEntry(t, r, memByOp[rm.OperatorAddr]))
		}
		kA.ConsumeVoteExtensions(ctxA.WithBlockHeight(int64(h)), entries)
		kB.ConsumeVoteExtensions(ctxB.WithBlockHeight(int64(h)), entries)
	}

	var rekeyHeights []int
	stakeDriftRekeys := 0
	prevEpoch := uint64(0)
	for h := 1; h <= H; h++ {
		// Continuous stake drift: op1 grows every block (drift vs the frozen snapshot).
		addOrSetVal(sk, "op1", 100+int64(h)*7)
		// Two near-simultaneous member+stake changes mid-storm.
		if h == 60 {
			removeValByOp(sk, "op4")
		}
		if h == 130 {
			addOrSetVal(sk, "op4", 100)
		}

		feedDealings(h)
		bA := ctxA.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		bB := ctxB.WithBlockHeight(int64(h)).WithEventManager(sdk.NewEventManager())
		kA.EndBlockDKG(bA)
		kB.EndBlockDKG(bB)

		if dA, dB := dkgDigest(kA, ctxA), dkgDigest(kB, ctxB); dA != dB {
			t.Fatalf("NODE DIVERGENCE at height %d:\n A=%s\n B=%s", h, dA, dB)
		}
		stakeDriftRekeys += countEvents(bA, "encmempool_dkg_stake_drift_rekey")

		if ep := kA.GetCurrentEpoch(ctxA); ep != prevEpoch {
			rekeyHeights = append(rekeyHeights, h)
			prevEpoch = ep
		}
		if r := kA.CountDkgRounds(ctxA); r > 5 {
			t.Fatalf("height %d: round-record state grew to %d (storm-unbounded)", h, r)
		}
		if kk := kA.CountActiveKeys(ctxA); kk > 4 {
			t.Fatalf("height %d: active-key state grew to %d (storm-unbounded)", h, kk)
		}
	}

	// rekeyHeights[0] is the genesis "start" open (height 1), which is not dampened (LastRekey
	// is still 0). Every rekey AFTER the first real one must be >= gap blocks past the previous.
	if len(rekeyHeights) < 3 {
		t.Fatalf("storm did not drive repeated re-genesis: rekeys at %v", rekeyHeights)
	}
	for i := 2; i < len(rekeyHeights); i++ {
		if d := rekeyHeights[i] - rekeyHeights[i-1]; d < gap {
			t.Fatalf("DAMPENER BREACHED: rekeys at %d and %d are only %d < gap %d apart (all: %v)",
				rekeyHeights[i-1], rekeyHeights[i], d, gap, rekeyHeights)
		}
	}
	if len(rekeyHeights) > H/gap+5 {
		t.Fatalf("rekey RATE too high: %d rekeys over %d heights at gap %d (%v)", len(rekeyHeights), H, gap, rekeyHeights)
	}
	// Non-vacuous: the STAKE-DRIFT rekey (the cycle-5 feature under audit) must actually be the
	// dominant driver here — the storm is continuous re-delegation with only two membership toggles.
	if stakeDriftRekeys < 3 {
		t.Fatalf("storm did not exercise the stake-drift rekey enough: only %d fired", stakeDriftRekeys)
	}
}

// TestCycle6_Determinism_ManyNodes_ThroughFlood runs 4 independent nodes through the FULL
// transparent DKG loop with each node consuming the SAME committed vote extensions in a
// DIFFERENT order, then floods every node identically with a >128 concurrent shortfall and
// drains it through BeginBlock. It asserts all 4 nodes hold byte-identical DKG state AND
// byte-identical in-flight ciphertext state at EVERY height — the many-node fork-safety
// property, exercised across the never-live path (the cap flood) too.
func TestCycle6_Determinism_ManyNodes_ThroughFlood(t *testing.T) {
	const nodes = 4
	mem := []member{newMember("op1", ""), newMember("op2", ""), newMember("op3", "")}

	// Per-node deterministic permutations of a vote-extension batch (identity, reverse, two rotations).
	perms := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}, {2, 0, 1}}
	shuffle := func(node int, in []keeper.VEEntry) []keeper.VEEntry {
		p := perms[node%len(perms)]
		out := make([]keeper.VEEntry, len(in))
		for i, idx := range p {
			if idx < len(in) {
				out[i] = in[idx]
			} else {
				out[i] = in[i]
			}
		}
		return out
	}

	// Each node gets its own keeper/store over a SHARED staking view.
	sk := &mockStaking{vals: []stakingtypes.Validator{
		bondedVal("op1", 100), bondedVal("op2", 110), bondedVal("op3", 120),
	}}
	ks := make([]keeper.Keeper, nodes)
	ctxs := make([]sdk.Context, nodes)
	for i := 0; i < nodes; i++ {
		k, ctx := newKeeperSK(t, 1, sk)
		p := transparentParams(2, 4)
		p.DkgShareBudget = 32
		p.DkgDealWindow = 1
		p.DkgComplaintWindow = 1
		p.DkgStartHeight = 1
		p.DecryptDelay = 2
		p.MaxInFlightEncTx = 0
		p.MaxInFlightPerSubmitter = 0
		if err := k.SetParams(ctx, p); err != nil {
			t.Fatal(err)
		}
		ks[i], ctxs[i] = k, ctx
	}

	// Announce enc keys (shuffled per node) at height 1, then open epoch 1.
	ann := make([]keeper.VEEntry, len(mem))
	for i, m := range mem {
		ann[i] = keeper.VEEntry{Operator: m.op, VE: annVE(m)}
	}
	for i := 0; i < nodes; i++ {
		ks[i].ConsumeVoteExtensions(ctxs[i].WithBlockHeight(1), shuffle(i, ann))
		ks[i].EndBlockDKG(ctxs[i].WithBlockHeight(1))
	}
	assertAllDigestsEqual(t, ks, ctxs, 1, dkgDigest)

	// Build a canonical dealing batch ONCE against node 0's (identical) round, feed it shuffled
	// per node at height 2, then finalize at the complaint deadline.
	round0, _ := ks[0].GetDkgRound(ctxs[0], 1)
	deals := make([]keeper.VEEntry, 0, len(mem))
	for _, m := range mem {
		deals = append(deals, buildDealingEntry(t, round0, m))
	}
	for i := 0; i < nodes; i++ {
		ks[i].ConsumeVoteExtensions(ctxs[i].WithBlockHeight(2), shuffle(i, deals))
	}
	assertAllDigestsEqual(t, ks, ctxs, 2, dkgDigest)

	finH := int64(round0.ComplaintDeadline)
	for i := 0; i < nodes; i++ {
		ks[i].EndBlockDKG(ctxs[i].WithBlockHeight(finH))
	}
	assertAllDigestsEqual(t, ks, ctxs, finH, dkgDigest)
	ak0, ok := ks[0].GetActiveKey(ctxs[0], 1)
	if !ok {
		t.Fatal("epoch 1 must finalize across all nodes")
	}

	// Flood every node IDENTICALLY with >128 epoch-1 shortfalls (0 shares) submitted at the
	// same height, so all decrypt at the same maturity height — the cap flood, replicated.
	const flood = 300
	submitH := uint64(finH) + 1
	a := make([]byte, 33)
	nonce := make([]byte, threshold.NonceSize)
	for i := 0; i < nodes; i++ {
		sctx := ctxs[i].WithBlockHeight(int64(submitH))
		for j := 0; j < flood; j++ {
			ks[i].SubmitEncTx(sctx, "attacker", submitH, 2, a, nonce, []byte("x"), 1)
		}
	}
	_ = ak0

	// Drain through BeginBlock past grace, asserting byte-identical in-flight state at each height.
	matureH := int64(submitH) + 2
	drained := false
	for h := matureH; h <= matureH+int64(keeper.StrandedDecryptGraceBlocks)+5; h++ {
		for i := 0; i < nodes; i++ {
			bctx := ctxs[i].WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
			if err := ks[i].BeginBlock(bctx); err != nil {
				t.Fatalf("node %d BeginBlock@%d: %v", i, h, err)
			}
		}
		want := inFlightDigest(ks[0], ctxs[0])
		for i := 1; i < nodes; i++ {
			if got := inFlightDigest(ks[i], ctxs[i]); got != want {
				t.Fatalf("IN-FLIGHT DIVERGENCE at height %d: node0=%s node%d=%s", h, want, i, got)
			}
		}
		if countEncTx(ks[0], ctxs[0]) == 0 {
			drained = true
			break
		}
	}
	if !drained {
		t.Fatal("flood did not drain across nodes")
	}
	// All nodes fully drained + epoch pruned identically (epoch 1 is now superseded-and-drained
	// only if a later epoch became active; here epoch 1 stayed active, so its key is retained but
	// the ref-count is released — assert the shared, byte-identical end state).
	for i := 0; i < nodes; i++ {
		if g := ks[i].GetGlobalEncCount(ctxs[i]); g != 0 {
			t.Fatalf("node %d leaked global count: %d", i, g)
		}
		if ec := ks[i].GetEpochEncCount(ctxs[i], 1); ec != 0 {
			t.Fatalf("node %d leaked epoch ref-count: %d", i, ec)
		}
	}
}

// assertAllDigestsEqual checks every node's digest equals node 0's at the given height.
func assertAllDigestsEqual(t *testing.T, ks []keeper.Keeper, ctxs []sdk.Context, h int64, digest func(keeper.Keeper, sdk.Context) string) {
	t.Helper()
	want := digest(ks[0], ctxs[0])
	for i := 1; i < len(ks); i++ {
		if got := digest(ks[i], ctxs[i]); got != want {
			t.Fatalf("node divergence at height %d: node0=%s node%d=%s", h, want, i, got)
		}
	}
}
