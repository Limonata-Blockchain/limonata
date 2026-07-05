package keeper_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-7 ADVERSARIAL RE-AUDIT — lens: CONSENSUS / DETERMINISM / HALT.
//
// The cycle-7 fix moved dkg.VerifyDecryptShare onto the PreBlock consensus path
// (IngestDecryptShareFromVE -> verifyDecryptShareDLEQ). These probes attack that move:
//   (1) can a crafted (D,proof) PANIC the verify path (a chain HALT, or — since
//       ConsumeVoteExtensions wraps a recover — a liveness STARVE of every operator
//       sorted after the attacker)?
//   (2) is the ingest verdict ORDER-INDEPENDENT (fork-safety: nodes see votes in
//       different orders)?
//   (3) is the verify verdict a DETERMINISTIC pure function (same verdict every call)?
// ============================================================================

// randValidPoint returns a random valid compressed secp256k1 point (a well-formed D that
// PASSES parsePoint, so VerifyDecryptShare reaches the deep T1/T2/compressCopy path).
func randValidPoint(t *testing.T) []byte {
	t.Helper()
	pk, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pk.PubKey().SerializeCompressed()
}

// zeroProof64 is 64 zero bytes: ParseDLEQProof accepts it (len==64) as C=0,Z=0. With C=Z=0,
// VerifyDecryptShare computes T1 = z*G - c*Y = inf and T2 = z*A - c*D = inf, so the Fiat-Shamir
// transcript hashes the point at INFINITY through compressCopy — the prime panic suspect.
func zeroProof64() []byte { return make([]byte, 64) }

// TestC7Audit_VerifyDecryptShare_NeverPanics fuzzes the exported verify primitive with the exact
// input domain the ingest gate feeds it: a valid ciphertext A, a real public share key Y, a
// well-formed-but-adversarial D, and adversarial proofs (incl. the C=Z=0 infinity-forcer). A
// panic here is a consensus HALT (or, behind the ConsumeVoteExtensions recover, a liveness starve).
func TestC7Audit_VerifyDecryptShare_NeverPanics(t *testing.T) {
	c := c7Committee(t)
	commitments, err := dkg.ParseCommitmentPoints(c.ak.PublicCommitments)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("halt-probe"))
	if err != nil {
		t.Fatal(err)
	}
	// A real member's public share key Y at a real owned eval point.
	idx := c.memberPoints("attacker")[0]
	Y := dkg.SharePubKey(commitments, idx)

	guarded := func(name string, ds *threshold.DecryptShare, Y *secp256k1.JacobianPoint, proof *dkg.DLEQProof) (panicked bool) {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				t.Errorf("HALT: dkg.VerifyDecryptShare PANICKED on %s: %v", name, r)
			}
		}()
		_ = dkg.VerifyDecryptShare(ct.A, ds, Y, proof)
		return false
	}

	// (a) the C=Z=0 zero proof with a valid D -> forces T1=T2=infinity -> compressCopy(inf).
	zp, err := dkg.ParseDLEQProof(zeroProof64())
	if err != nil {
		t.Fatalf("zero proof must parse (len==64): %v", err)
	}
	if guarded("zero-proof/valid-D", &threshold.DecryptShare{Index: idx, D: randValidPoint(t)}, Y, zp) {
		return
	}
	// (b) zero proof with the ciphertext's OWN A reused as D (another infinity route).
	if guarded("zero-proof/D=A", &threshold.DecryptShare{Index: idx, D: ct.A}, Y, zp) {
		return
	}
	// (c) fuzz: random 64-byte proofs x random valid D, many iterations.
	for i := 0; i < 4000; i++ {
		pb := make([]byte, 64)
		_, _ = rand.Read(pb)
		proof, perr := dkg.ParseDLEQProof(pb)
		if perr != nil {
			continue
		}
		if guarded("fuzz", &threshold.DecryptShare{Index: idx, D: randValidPoint(t)}, Y, proof) {
			return
		}
	}
	// (d) nil Y (SharePubKey over empty commitments) must be handled, not panic.
	if guarded("nil-Y", &threshold.DecryptShare{Index: idx, D: randValidPoint(t)}, dkg.SharePubKey(nil, idx), zp) {
		return
	}
	t.Log("no panic across zero-proof (infinity), D=A, 4000 fuzz proofs, and nil-Y")
}

// TestC7Audit_ConsumePreBlock_AttackerSortsFirst_NoHaltNoStarve is the money probe. The attacker's
// operator name ("attacker") sorts BEFORE every honest operator, so ConsumeVoteExtensions processes
// its shares FIRST. If a crafted chaff share panicked verifyDecryptShareDLEQ, the module's recover
// guard would abort the whole consume loop and STARVE honest_A/honest_B (sorted after) of ever
// storing a share -> the ciphertext could never heal (a permanent liveness DoS). We spray the
// attacker's worst case (valid-D + C=Z=0 zero proof, the infinity-forcer, at every owned point) and
// assert: (i) no panic escaped, (ii) no consume-panic event, (iii) all 16 honest shares still
// stored, (iv) chaff rejected, (v) the matured-but-short ciphertext DEFERS (not a hard drop).
func TestC7Audit_ConsumePreBlock_AttackerSortsFirst_NoHaltNoStarve(t *testing.T) {
	c := c7Committee(t)
	plain := []byte("attacker-sorts-first must not starve honest shares")

	ctx := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	e := c.k.SubmitEncTx(ctx, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1) // matures @12

	// Attacker chaff: valid-D + zero (C=Z=0) proof at EVERY owned point (drives compressCopy(inf)).
	var atkChaff []types.VoteExtShare
	for _, p := range c.memberPoints("attacker") {
		atkChaff = append(atkChaff, types.VoteExtShare{
			Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: p,
			D: randValidPoint(t), Proof: zeroProof64(),
		})
	}

	ing := ctx.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("HALT: ConsumeVoteExtensions PANICKED (attacker sorts first): %v", r)
			}
		}()
		// Deliberately list attacker FIRST; sort.SliceStable keeps it first (name-min).
		c.k.ConsumeVoteExtensions(ing, []keeper.VEEntry{
			{Operator: "attacker", VE: types.VoteExtension{Shares: atkChaff}},
			{Operator: "honest_A", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_A")}},
			{Operator: "honest_B", VE: types.VoteExtension{Shares: veSharesFor(t, c, ctx, e, ct, "honest_B")}},
		})
	}()

	if hasEvent(ing, "encmempool_dkg_ve_consume_panic") {
		t.Fatal("STARVE: a consume-panic fired — the recover guard caught a verify-path panic; honest shares after the attacker were skipped")
	}
	stored := c.k.CollectShares(ctx, e.DecryptHeight, e.Seq)
	if len(stored) != 16 {
		t.Fatalf("STARVE/HALT: expected 16 honest shares stored despite attacker-first chaff, got %d", len(stored))
	}
	if n := countEvents(ing, "encmempool_dkg_ve_share_rejected"); n != 8 {
		t.Fatalf("expected 8 chaff rejections, got %d", n)
	}
	// The short ciphertext must DEFER (heal-eligible), never hard-drop.
	b12 := c.ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := c.k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if hasEvent(b12, "encmempool_decrypt_failed") {
		t.Fatal("attacker-first chaff forced a HARD DROP instead of a grace defer")
	}
	if !hasEvent(b12, "encmempool_decrypt_missed") {
		t.Fatal("matured-but-short ciphertext must DEFER")
	}
	t.Log("attacker-sorts-first zero-proof chaff: no panic, honest shares survived, ciphertext deferred")
}

// TestC7Audit_IngestVerdict_OrderIndependent is a rigorous fork-safety proxy: CometBFT can list the
// same votes in ANY order on different nodes; ConsumeVoteExtensions must canonicalize so committed
// state is byte-identical. We fix ONE ciphertext + ONE set of VE entries, then consume two different
// input ORDERINGS of those SAME entries into two CacheContext() BRANCHES of the SAME committed state
// (the exact two-node model: identical base state, different vote order) and assert the stored
// VERIFIED share sets are byte-for-byte identical (Index, D, and Proof).
func TestC7Audit_IngestVerdict_OrderIndependent(t *testing.T) {
	c := c7Committee(t)
	base := c.ctx.WithBlockHeight(30).WithEventManager(sdk.NewEventManager())
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("order-independence"))
	if err != nil {
		t.Fatal(err)
	}
	// Submit the ciphertext into the BASE (committed) state, so both branches see the same EncTx.
	e := c.k.SubmitEncTx(base, "user", 30, 2, ct.A, ct.Nonce, ct.Body, 1)

	// Build the VE entries ONCE (fixed D/proof bytes), including attacker chaff.
	byName := map[string]keeper.VEEntry{
		"honest_A": {Operator: "honest_A", VE: types.VoteExtension{Shares: veSharesFor(t, c, base, e, ct, "honest_A")}},
		"honest_B": {Operator: "honest_B", VE: types.VoteExtension{Shares: veSharesFor(t, c, base, e, ct, "honest_B")}},
		"attacker": {Operator: "attacker", VE: types.VoteExtension{Shares: chaffVESharesAt(c, e, "attacker")}},
	}
	order := func(names ...string) []keeper.VEEntry {
		out := make([]keeper.VEEntry, 0, len(names))
		for _, n := range names {
			out = append(out, byName[n])
		}
		return out
	}
	consumeOn := func(entries []keeper.VEEntry) []types.EncShare {
		branch, _ := base.CacheContext() // isolated overlay over identical committed state (a "node")
		c.k.ConsumeVoteExtensions(branch.WithBlockHeight(31).WithEventManager(sdk.NewEventManager()), entries)
		got := c.k.CollectShares(branch, e.DecryptHeight, e.Seq)
		sortShares(got)
		return got
	}

	a := consumeOn(order("attacker", "honest_A", "honest_B"))
	b := consumeOn(order("honest_B", "attacker", "honest_A"))
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("expected 16 verified shares each order, got %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Index != b[i].Index || !bytes.Equal(a[i].D, b[i].D) || !bytes.Equal(a[i].Proof, b[i].Proof) {
			t.Fatalf("FORK: stored share set differs by input order at %d: idx %d/%d", i, a[i].Index, b[i].Index)
		}
	}
	t.Log("stored VERIFIED share set byte-identical across two vote orderings on branched state (chaff rejected in both)")
}

// TestC7Audit_VerifyDeterministic_RepeatedVerdict asserts the verify primitive is a pure function:
// the same (A,ds,Y,proof) yields the same bool every call (no RNG/time/map-order in the path).
func TestC7Audit_VerifyDeterministic_RepeatedVerdict(t *testing.T) {
	c := c7Committee(t)
	commitments, err := dkg.ParseCommitmentPoints(c.ak.PublicCommitments)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := threshold.Encrypt(c.ak.Pub, []byte("determinism"))
	if err != nil {
		t.Fatal(err)
	}
	// a REAL valid proved share (verdict must be stably true) and a chaff share (stably false)
	sh := deriveShareFor(t, c, c.ctx, "attacker", c.memberPoints("attacker")[0])
	ds, proof, err := dkg.ProveDecryptShare(sh, ct)
	if err != nil {
		t.Fatal(err)
	}
	Yvalid := dkg.SharePubKey(commitments, ds.Index)
	zp, _ := dkg.ParseDLEQProof(zeroProof64())

	var firstValid, firstChaff bool
	for i := 0; i < 256; i++ {
		v := dkg.VerifyDecryptShare(ct.A, ds, Yvalid, proof)
		ch := dkg.VerifyDecryptShare(ct.A, &threshold.DecryptShare{Index: ds.Index, D: randValidPoint(t)}, Yvalid, zp)
		if i == 0 {
			firstValid, firstChaff = v, ch
			continue
		}
		if v != firstValid {
			t.Fatalf("NONDETERMINISM: valid share verdict flipped at i=%d (%v vs %v)", i, v, firstValid)
		}
		if ch != firstChaff {
			t.Fatalf("NONDETERMINISM: chaff verdict flipped at i=%d", i)
		}
	}
	if !firstValid {
		t.Fatal("REGRESSION: a genuinely valid proved share verified FALSE (would strand honest decryption)")
	}
	if firstChaff {
		t.Fatal("SOUNDNESS: a zero-proof chaff share verified TRUE")
	}
	t.Log("verify verdict stable over 256 repeats: valid=true, chaff=false")
}

// sortShares orders by Index (insertion sort; small n) so two runs compare canonically.
func sortShares(s []types.EncShare) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1].Index > s[j].Index; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
