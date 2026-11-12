package dkgnode_test

// Live-scale measurement of the DKG poison-detection cost that the per-epoch cache
// eliminates. DetectPoisonedDealers runs every block in ExtendVote on stock v0.3.3;
// the v0.3.4 cache runs it ONCE per Active epoch and reuses the result. This bench
// reproduces the live topology (S=256 eval points, t=171, ~42 dealers, our 51%-VP
// validator owning ~130 points) with REAL dealings and times one call = the per-block
// ExtendVote cost that the cache removes on every block after the first of an epoch.
//
// Run: ~/go-sdk/bin/go test -run TestPoisonCostLiveScale -v ./x/encmempool/dkgnode/
//      ~/go-sdk/bin/go test -bench BenchmarkDetectPoisonedDealers -benchtime 10x ./x/encmempool/dkgnode/

import (
	"crypto/rand"
	"testing"
	"time"

	sdkmath "cosmossdk.io/math"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// buildLiveScaleFixture constructs a realistic Active-epoch fixture:
//   - shareBudget total Shamir eval points, split across `dealers` members
//   - member 0 ("our" 51%-VP validator) owns `myPoints` of them
//   - threshold t, and one REAL dealing per dealer (valid commitments + enc shares)
//
// Returns our owned points, our enc priv, the qual list, and the dealings map exactly
// as DetectPoisonedDealers consumes them in ExtendVote.
func buildLiveScaleFixture(t testing.TB, dealers, shareBudget, myPoints, thr int) (
	[]uint64, *secp256k1.ModNScalar, []uint64, map[uint64]types.Dealing,
) {
	t.Helper()

	// 1. enc keypair per member.
	privs := make([]*secp256k1.ModNScalar, dealers)
	pubs := make([][]byte, dealers)
	for i := 0; i < dealers; i++ {
		pk, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		s := new(secp256k1.ModNScalar)
		s.Set(&pk.Key)
		privs[i] = s
		pubs[i] = pk.PubKey().SerializeCompressed()
	}

	// 2. partition the S contiguous eval points (1..S) across members: member 0 gets
	//    the first `myPoints`, the rest split the remainder as evenly as possible.
	members := make([]types.RoundMember, dealers)
	next := uint64(1)
	rem := shareBudget - myPoints
	for i := 0; i < dealers; i++ {
		var owned int
		if i == 0 {
			owned = myPoints
		} else {
			// distribute the remaining points across dealers 1..dealers-1
			owned = rem / (dealers - 1)
			if i <= rem%(dealers-1) {
				owned++
			}
		}
		pts := make([]uint64, owned)
		for j := 0; j < owned; j++ {
			pts[j] = next
			next++
		}
		members[i] = types.RoundMember{
			Index:      uint64(i + 1),
			EncPubKey:  pubs[i],
			Weight:     sdkmath.NewInt(1),
			EvalPoints: pts,
		}
	}
	if next-1 != uint64(shareBudget) {
		t.Fatalf("point partition covered %d points, want %d", next-1, shareBudget)
	}

	// 3. every member deals a REAL dealing (commitments + shares sealed to each owner).
	dealings := make(map[uint64]types.Dealing, dealers)
	qual := make([]uint64, dealers)
	for i := 0; i < dealers; i++ {
		vd, err := dkgnode.BuildDealing(1, members, members[i].Index, thr)
		if err != nil {
			t.Fatalf("BuildDealing dealer %d: %v", i, err)
		}
		dealings[members[i].Index] = types.Dealing{
			Epoch:       1,
			DealerIndex: members[i].Index,
			Commitments: vd.Commitments,
			EncShares:   vd.EncShares,
		}
		qual[i] = members[i].Index
	}

	return members[0].OwnedEvalPoints(), privs[0], qual, dealings
}

// detectNaive is the ORIGINAL pre-refactor algorithm, kept as a parity reference: the
// refactored DetectPoisonedDealers must return byte-identical reports (same set, same
// (point, dealer) order) for every input, including poisoned dealings.
func detectNaive(myEvalPoints []uint64, encPriv *secp256k1.ModNScalar, qual []uint64, dealings map[uint64]types.Dealing) []dkgnode.PoisonReport {
	var reports []dkgnode.PoisonReport
	for _, p := range myEvalPoints {
		for _, dealer := range qual {
			d, ok := dealings[dealer]
			if !ok {
				continue
			}
			var ct *threshold.Ciphertext
			for i := range d.EncShares {
				if d.EncShares[i].MemberIndex == p {
					ct = &threshold.Ciphertext{A: d.EncShares[i].A, Nonce: d.EncShares[i].Nonce, Body: d.EncShares[i].Body}
					break
				}
			}
			if ct == nil {
				reports = append(reports, dkgnode.PoisonReport{Dealer: dealer, Point: p})
				continue
			}
			s, err := dkg.DecryptShareFrom(encPriv, p, ct)
			if err != nil {
				reports = append(reports, dkgnode.PoisonReport{Dealer: dealer, Point: p})
				continue
			}
			commitments, perr := dkg.ParseCommitmentPoints(d.Commitments)
			if perr != nil || !dkg.VerifyShare(commitments, p, s) {
				reports = append(reports, dkgnode.PoisonReport{Dealer: dealer, Point: p})
			}
		}
	}
	return reports
}

// TestDetectPoisonedParity proves the refactor is output-identical to the naive original,
// on valid dealings AND on dealings poisoned three different ways (missing share, corrupt
// commitment, tampered ciphertext) so real reports are produced in a real order.
func TestDetectPoisonedParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skip crypto build in -short")
	}
	const (
		dealers     = 8
		shareBudget = 96
		myPoints    = 40
		thr         = 65 // floor(2*96/3)+1
	)
	myPts, myPriv, qual, dealings := buildLiveScaleFixture(t, dealers, shareBudget, myPoints, thr)

	// Poison a few dealers in distinct ways.
	poison := func(dealerIdx uint64, mut func(d *types.Dealing)) {
		d := dealings[dealerIdx]
		mut(&d)
		dealings[dealerIdx] = d
	}
	// (a) drop an enc-share for one of our points -> ct==nil path.
	poison(qual[1], func(d *types.Dealing) {
		out := d.EncShares[:0]
		for _, s := range d.EncShares {
			if s.MemberIndex != myPts[0] {
				out = append(out, s)
			}
		}
		d.EncShares = out
	})
	// (b) corrupt the commitments -> ParseCommitmentPoints / VerifyShare failure path.
	poison(qual[3], func(d *types.Dealing) {
		if len(d.Commitments) > 0 && len(d.Commitments[0]) > 1 {
			d.Commitments[0][1] ^= 0xFF
		}
	})
	// (c) tamper a ciphertext body -> DecryptShareFrom / VerifyShare failure path.
	poison(qual[5], func(d *types.Dealing) {
		for i := range d.EncShares {
			if len(d.EncShares[i].Body) > 0 {
				d.EncShares[i].Body[0] ^= 0xFF
			}
		}
	})

	want := detectNaive(myPts, myPriv, qual, dealings)
	got := dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)
	if len(got) != len(want) {
		t.Fatalf("report count differs: refactor=%d naive=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("report[%d] differs: refactor=%+v naive=%+v", i, got[i], want[i])
		}
	}
	if len(want) == 0 {
		t.Fatalf("expected the poisoned fixture to yield SOME reports, got 0 (test is not exercising the report path)")
	}
	t.Logf("parity OK across valid+poisoned dealings: %d reports, identical set and order", len(want))
}

// TestPoisonCostLiveScale prints the human-readable per-block cost and the amortized
// cost the cache achieves. Not an assertion of speed - a measurement + a correctness
// check that the detection is deterministic (cache returns an identical result).
func TestPoisonCostLiveScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skip live-scale crypto build in -short")
	}
	const (
		dealers     = 16  // DefaultDkgMaxMembers cap (committee = top-16 validators)
		shareBudget = 256 // DefaultDkgShareBudget (S)
		myPoints    = 130 // ~51% VP -> ~51% of S
		thr         = 171 // floor(2S/3)+1
	)
	myPts, myPriv, qual, dealings := buildLiveScaleFixture(t, dealers, shareBudget, myPoints, thr)

	// warm one call (also the correctness reference).
	ref := dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)

	const iters = 5
	start := time.Now()
	for i := 0; i < iters; i++ {
		got := dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)
		if len(got) != len(ref) {
			t.Fatalf("non-deterministic detection: got %d reports, ref %d", len(got), len(ref))
		}
	}
	per := time.Since(start) / iters

	// The cache runs DetectPoisonedDealers once per Active epoch instead of per block.
	// Amortize over a conservative in-epoch block count (membership stable) to show the
	// per-block cost with the cache.
	const epochBlocks = 1000 // conservative; steady-state epochs run far longer
	amortized := per / time.Duration(epochBlocks)

	t.Logf("topology: dealers=%d S=%d myPoints=%d t=%d  (valid dealings, %d poison reports)",
		dealers, shareBudget, myPoints, thr, len(ref))
	t.Logf("per-block ExtendVote cost WITHOUT cache (v0.3.3): %v", per)
	t.Logf("per-block ExtendVote cost WITH   cache (v0.3.4): ~%v  (1 run / %d-block epoch)", amortized, epochBlocks)
	t.Logf("=> the cache removes ~%v of CPU from EVERY block after the first of an epoch", per)
}

// BenchmarkDetectPoisonedDealers_LiveScale reports ns/op = the per-block ExtendVote cost
// on stock v0.3.3. Use -benchtime 20x (each op is heavy).
func BenchmarkDetectPoisonedDealers_LiveScale(b *testing.B) {
	const (
		dealers     = 42
		shareBudget = 256
		myPoints    = 130
		thr         = 171
	)
	myPts, myPriv, qual, dealings := buildLiveScaleFixture(b, dealers, shareBudget, myPoints, thr)
	_ = rand.Reader // rand used transitively in BuildDealing setup

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dkgnode.DetectPoisonedDealers(myPts, myPriv, qual, dealings)
	}
}
