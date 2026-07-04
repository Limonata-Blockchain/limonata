package keeper_test

import (
	"fmt"
	"sort"
	"testing"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// CYCLE-3 H-B — FLIPPED into the safety/liveness PROPERTY regression suite.
//
// The original probes proved two breaks on 19d5cb6f:
//   - LIVENESS BAND: t = floor(2S/3)+1 plus Hamilton rounding slop stranded an honest
//     ONLINE stake-supermajority below t (whale 66.70% owned 170 < t=171 at the live
//     default S=256), and decryptMatured then SILENTLY dropped the matured ciphertext;
//   - the load-bearing claim "an honest >2/3 supermajority always holds >= t" was false.
//
// The fix sets t = floor(2S/3) - n + 1 under the enforced coupling S >= 8n. These tests
// now assert BOTH inequalities hold with NO residual band, across the full committee
// range and adversarial stake shapes (the exact families the auditors swept):
//   (SAFETY)   any coalition with <= 1/3 of snapshotted stake holds < t points;
//   (LIVENESS) any online set with > 2/3 of snapshotted stake holds >= t points;
// and that a share-shortfall at maturity is a BOUNDED, LOUD deferral — never a silent drop.
// ============================================================================

// tNew mirrors keeper.stakeThreshold for a WEIGHTED round: t = floor(2S/3) - n + 1.
func tNew(S, n int) int {
	t := (2*S)/3 - n + 1
	if t > S {
		t = S
	}
	if t < 1 {
		t = 1
	}
	return t
}

// mkMembers builds an operator-sorted RoundMember slice with the given integer weights.
// (TransparentMembers hands openRound an operator-sorted slice, so we mirror that.)
func mkMembers(weights []int64) []types.RoundMember {
	type mw struct {
		op string
		w  int64
	}
	ms := make([]mw, len(weights))
	for i, w := range weights {
		ms[i] = mw{op: fmt.Sprintf("op%04d", i), w: w}
	}
	sort.Slice(ms, func(a, b int) bool { return ms[a].op < ms[b].op })
	out := make([]types.RoundMember, len(ms))
	for i, m := range ms {
		out[i] = types.RoundMember{Index: uint64(i + 1), OperatorAddr: m.op, Weight: sdkmath.NewInt(m.w)}
	}
	return out
}

// pointsHeld allocates with the given epoch seed and sums the points held by the members
// whose weight matches inSet.
func pointsHeld(weights []int64, S int, epoch uint64, inSet func(w int64, i int) bool) (setPts, total, thr int) {
	members := keeper.AllocateEvalPoints(mkMembers(weights), S, epoch)
	n := len(members)
	for _, m := range members {
		np := len(m.OwnedEvalPoints())
		total += np
		// recover the ORIGINAL index i from the operator name (op%04d).
		var i int
		fmt.Sscanf(m.OperatorAddr, "op%04d", &i)
		if inSet(m.Weight.Int64(), i) {
			setPts += np
		}
	}
	return setPts, total, tNew(total, n)
}

// TestReg_HB_Liveness_NoSupermajorityStranded (flipped
// TestProbe_H3_Liveness_HonestSupermajorityStranded): re-run the EXACT search family that
// found the pre-fix counterexample (one honest online whale just above 2/3 + offline dust
// farming the remainder seats, at the LIVE default S=256) and require that NO
// counterexample exists any more: every whale holding > 2/3 of committee stake holds
// >= t points. This test FAILS on 19d5cb6f (the search finds whale 66.70% with 170 < 171).
func TestReg_HB_Liveness_NoSupermajorityStranded(t *testing.T) {
	const S = 256
	for dust := 1; dust <= 15; dust++ {
		for dw := int64(1); dw <= 60; dw++ {
			for w := int64(300); w <= 900; w++ {
				var total int64 = w + int64(dust)*dw
				if 3*w <= 2*total {
					continue // whale not a stake supermajority
				}
				weights := make([]int64, 0, dust+1)
				weights = append(weights, w)
				for i := 0; i < dust; i++ {
					weights = append(weights, dw)
				}
				whalePts, _, thr := pointsHeld(weights, S, 1, func(mw int64, _ int) bool { return mw == w })
				if whalePts < thr {
					t.Fatalf("H-B REGRESSION (liveness band re-opened): honest ONLINE whale %d/%d = %.4f (>2/3) "+
						"owns %d < t=%d points at S=%d, n=%d — matured ciphertexts would strand",
						w, total, float64(w)/float64(total), whalePts, thr, S, dust+1)
				}
			}
		}
	}
}

// TestReg_HB_BothInequalities_PropertySweep is the required property/fuzz regression: for
// committee sizes n across the FULL cap range [2..128] at the minimum coupled budget S=8n
// (the worst case — larger S only widens the margins) and at the live default when it
// applies, over the adversarial stake shapes from the audit (boundary coalitions, dust
// swarms vs whales, near-boundary offline sets), assert BOTH:
//
//	SAFETY:   a coalition holding EXACTLY the 1/3 boundary (or less) holds < t points;
//	LIVENESS: an online set holding one token above 2/3 holds >= t points, with the
//	          offline remainder just under 1/3 — squarely inside the BFT fault model.
//
// Every allocation is also re-run with several epoch seeds: the inequalities are
// seed-independent (the L-2 tie-break rotation must never affect either bound).
func TestReg_HB_BothInequalities_PropertySweep(t *testing.T) {
	seeds := []uint64{1, 2, 7, 1000003}
	for n := 2; n <= 128; n++ {
		budgets := []int{8 * n}
		if 256 >= 8*n {
			budgets = append(budgets, 256) // the live default, where valid for this n
		}
		for _, S := range budgets {
			for _, seed := range seeds {
				// --- SAFETY at the exact 1/3 boundary, dust-swarm adversary vs one whale:
				// n-1 adversary members of stake 1 each (total n-1), honest whale 2(n-1).
				// Adversary stake is EXACTLY 1/3, spread across the maximum seat count —
				// the strongest remainder-seat-farming shape within the model.
				adv := int64(n - 1)
				weights := make([]int64, n)
				for i := 0; i < n-1; i++ {
					weights[i] = 1
				}
				weights[n-1] = 2 * adv
				advPts, _, thr := pointsHeld(weights, S, seed, func(w int64, _ int) bool { return w == 1 })
				if advPts >= thr {
					t.Fatalf("SAFETY broken: n=%d S=%d seed=%d: exact-1/3 dust swarm holds %d >= t=%d points",
						n, S, seed, advPts, thr)
				}

				// --- SAFETY, balanced boundary coalition: n_a = n/2 members sharing exactly
				// 1/3 (each 2*n_h), honest n_h = n - n_a members sharing 2/3 (each 4*n_a).
				na := n / 2
				if na >= 1 && n-na >= 1 {
					nh := n - na
					weights = make([]int64, n)
					for i := 0; i < na; i++ {
						weights[i] = 2 * int64(nh)
					}
					for i := na; i < n; i++ {
						weights[i] = 4 * int64(na)
					}
					advPts, _, thr = pointsHeld(weights, S, seed, func(_ int64, i int) bool { return i < na })
					if advPts >= thr {
						t.Fatalf("SAFETY broken: n=%d S=%d seed=%d: balanced exact-1/3 coalition holds %d >= t=%d",
							n, S, seed, advPts, thr)
					}
				}

				// --- LIVENESS, whale one token above 2/3 online, all dust offline (the
				// offline set holds just under 1/3 — the chain itself is still live):
				// dust n-1 members of stake 3 each (total D), whale 2D+1.
				D := 3 * int64(n-1)
				weights = make([]int64, n)
				for i := 0; i < n-1; i++ {
					weights[i] = 3
				}
				weights[n-1] = 2*D + 1
				whalePts, _, thr := pointsHeld(weights, S, seed, func(w int64, _ int) bool { return w == 2*D+1 })
				if whalePts < thr {
					t.Fatalf("LIVENESS broken: n=%d S=%d seed=%d: online whale at 2/3+1token holds %d < t=%d",
						n, S, seed, whalePts, thr)
				}

				// --- LIVENESS, spread online set one token above 2/3 (k = ceil(n/2) online
				// members), offline remainder just under 1/3.
				k := (n + 1) / 2
				off := n - k
				if off >= 1 {
					offEach := int64(3 * k)
					offTotal := offEach * int64(off)
					// online total = 2*offTotal + 1, spread as evenly as integers allow.
					onTotal := 2*offTotal + 1
					weights = make([]int64, n)
					for i := 0; i < off; i++ {
						weights[i] = offEach
					}
					base := onTotal / int64(k)
					rem := onTotal % int64(k)
					for i := 0; i < k; i++ {
						weights[off+i] = base
						if int64(i) < rem {
							weights[off+i]++
						}
					}
					onPts, _, thr := pointsHeld(weights, S, seed, func(_ int64, i int) bool { return i >= off })
					if onPts < thr {
						t.Fatalf("LIVENESS broken: n=%d S=%d seed=%d: online %d-member set at 2/3+1token holds %d < t=%d",
							n, S, seed, k, onPts, thr)
					}
				}
			}
		}
	}
}

// TestReg_M1_RealDecryptBar documents + enforces the HONEST decrypt bar (cycle-3 M-1):
// the advertised ">2/3 stake to decrypt" is NOT deliverable together with guaranteed
// >2/3-liveness (rounding slop is +-n points), and the code no longer claims it. The
// PROVEN bar is: any coalition reaching t holds f >= (t-n+1)/S > 2/3 - 2n/S, which is
// ALWAYS > 1/3 under the enforced coupling (>= 5/12 at S=8n; ~54.7% at the live default).
// This sweep hunts for the lowest-stake reconstructing coalition across the audit's
// families and asserts it never dips to the 1/3 Byzantine bound.
func TestReg_M1_RealDecryptBar(t *testing.T) {
	worstFrac := 1.0
	worstDesc := ""
	consider := func(desc string, weights []int64, S int, inSet func(w int64, i int) bool) {
		pts, total, thr := pointsHeld(weights, S, 1, inSet)
		if pts < thr {
			return
		}
		var cs, all int64
		for i, w := range weights {
			all += w
			if inSet(w, i) {
				cs += w
			}
		}
		frac := float64(cs) / float64(all)
		if frac < worstFrac {
			worstFrac = frac
			worstDesc = fmt.Sprintf("%s (S=%d total=%d t=%d pts=%d stake=%d/%d)", desc, S, total, thr, pts, cs, all)
		}
	}
	// Prefix coalitions over equal stake; dust swarms vs whales; half-committee minorities —
	// all at VALID coupled budgets.
	for _, n := range []int{4, 8, 16, 32, 64, 128} {
		S := 8 * n
		w := make([]int64, n)
		for i := range w {
			w[i] = 1_000_000
		}
		for m := 1; m <= n; m++ {
			m := m
			consider(fmt.Sprintf("equal-stake prefix n=%d m=%d", n, m), w, S,
				func(_ int64, i int) bool { return i < m })
		}
		for _, swarm := range []int{n / 2, n - 1} {
			if swarm < 1 || swarm >= n {
				continue
			}
			w2 := make([]int64, n)
			for i := 0; i < swarm; i++ {
				w2[i] = 3
			}
			for i := swarm; i < n; i++ {
				w2[i] = 100
			}
			consider(fmt.Sprintf("swarm n=%d swarm=%d", n, swarm), w2, S,
				func(_ int64, i int) bool { return i < swarm })
		}
	}
	if worstDesc != "" {
		t.Logf("lowest-stake reconstructing coalition found: %.4f — %s", worstFrac, worstDesc)
	}
	if worstFrac <= 1.0/3.0 {
		t.Fatalf("M-1/SAFETY broken: a %.4f-stake coalition (<= 1/3) reconstructs: %s", worstFrac, worstDesc)
	}
}

// TestReg_HB_Liveness_E2E_HonestSupermajorityDecrypts (flipped
// TestProbe_H3_Liveness_E2E_HonestSupermajorityCannotDecrypt): the exact committee that
// stranded the honest supermajority pre-fix — whale 21 (online, honest, 67.74%) + dust 10
// (offline), S=24 — now RECONSTRUCTS: the whale's stake share of the domain
// (floor(21*24/31)=16) meets t = floor(2*24/3) - 2 + 1 = 15. Drives the FULL stake-weighted
// DKG and the REAL off-chain recovery path. FAILS on 19d5cb6f (t was 17 > 16).
func TestReg_HB_Liveness_E2E_HonestSupermajorityDecrypts(t *testing.T) {
	stakes := map[string]int64{"honest_whale": 21, "offline_dust": 10}
	c := runTransparentDKG(t, stakes, 24) // n=2: 24 >= 8*2 honors the coupling

	honest := opsWithPrefix(c, "honest")
	whaleStake := c.coalitionStake(honest)
	total := whaleStake + c.coalitionStake(opsWithPrefix(c, "offline"))
	if 3*whaleStake <= 2*total {
		t.Fatalf("precondition: honest online set must be a stake supermajority (%d/%d)", whaleStake, total)
	}

	plain := []byte("honest supermajority MUST be able to decrypt at maturity")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	pts, recovered := c.coalitionReconstructs(t, honest, ct, plain)
	t.Logf("honest ONLINE supermajority stake=%d/%d = %.4f (> 2/3); owns %d eval points; t=%d; recovered=%v",
		whaleStake, total, float64(whaleStake)/float64(total), pts, c.ak.Threshold, recovered)
	if pts < int(c.ak.Threshold) {
		t.Fatalf("H-B REGRESSION: honest supermajority stranded below t (%d < %d)", pts, c.ak.Threshold)
	}
	if !recovered {
		t.Fatalf("H-B REGRESSION: honest supermajority held %d >= t=%d points but failed to reconstruct", pts, c.ak.Threshold)
	}
}

// TestReg_HB_MaturedShortfallDefersThenHeals_NeverSilent locks in the NON-SILENT decrypt
// semantics (cycle-3 H-B): a matured ciphertext short of t shares is
//  1. DEFERRED — kept in state with a loud decrypt_missed — not dropped (pre-fix it was
//     UNCONDITIONALLY released: the user's encrypted tx silently vanished);
//  2. DECRYPTED as soon as the missing share lands during the grace (deferral heals);
//  3. for a ciphertext whose shares never arrive, DROPPED at grace expiry with the LOUD
//     dedicated encmempool_decrypt_stranded event (epoch/height/reason), via releaseEncTx
//     (every ref-count zero — no strand, no leak).
func TestReg_HB_MaturedShortfallDefersThenHeals_NeverSilent(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	keypers := []string{"k1", "k2", "k3"}
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, enableParams(pub, 2, 2, keypers)); err != nil {
		t.Fatal(err)
	}

	// Two ciphertexts maturing at 12: "heals" gets its 2nd share late; "strands" never does.
	ctHeal, _ := threshold.Encrypt(pub, []byte("late shares must still decrypt"))
	eHeal := k.SubmitEncTx(ctx, "user", 10, 2, ctHeal.A, ctHeal.Nonce, ctHeal.Body, 0)
	ctStrand, _ := threshold.Encrypt(pub, []byte("never enough shares"))
	eStrand := k.SubmitEncTx(ctx, "user2", 10, 2, ctStrand.A, ctStrand.Nonce, ctStrand.Body, 0)

	ds0, _ := threshold.ComputeShare(shares[0], ctHeal)
	_ = k.SetEncShare(ctx, types.EncShare{Keyper: keypers[0], DecryptHeight: eHeal.DecryptHeight, Seq: eHeal.Seq, Index: ds0.Index, D: ds0.D})

	// (1) Maturity: 1 < t=2 shares — DEFER, loudly, keep in state.
	b12 := ctx.WithBlockHeight(12).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b12); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(b12, "encmempool_decrypt_missed") {
		t.Fatal("expected a loud decrypt_missed on the shortfall")
	}
	if _, ok := k.GetEncTx(b12, eHeal.DecryptHeight, eHeal.Seq); !ok {
		t.Fatal("H-B REGRESSION: matured ciphertext SILENTLY DROPPED at maturity (must defer within the grace)")
	}
	if _, ok := k.GetEncTx(b12, eStrand.DecryptHeight, eStrand.Seq); !ok {
		t.Fatal("H-B REGRESSION: share-less matured ciphertext silently dropped at maturity")
	}

	// (2) The missing share lands two blocks later — the deferred ciphertext DECRYPTS.
	ds1, _ := threshold.ComputeShare(shares[1], ctHeal)
	_ = k.SetEncShare(ctx, types.EncShare{Keyper: keypers[1], DecryptHeight: eHeal.DecryptHeight, Seq: eHeal.Seq, Index: ds1.Index, D: ds1.D})
	b14 := ctx.WithBlockHeight(14).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(b14); err != nil {
		t.Fatal(err)
	}
	if pt, ok := decryptedPlaintext(b14); !ok || string(pt) != "late shares must still decrypt" {
		t.Fatalf("deferral must HEAL: late-share ciphertext not decrypted (got %q, ok=%v)", pt, ok)
	}
	if _, ok := k.GetEncTx(b14, eHeal.DecryptHeight, eHeal.Seq); ok {
		t.Fatal("decrypted ciphertext must leave state")
	}

	// (3) Grace expiry for the share-less one: LOUD stranded drop, all ref-counts released.
	bx := ctx.WithBlockHeight(12 + int64(keeper.StrandedDecryptGraceBlocks)).WithEventManager(sdk.NewEventManager())
	if err := k.BeginBlock(bx); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(bx, "encmempool_decrypt_stranded") {
		t.Fatal("H-B REGRESSION: final drop of an undecryptable matured ciphertext must emit encmempool_decrypt_stranded")
	}
	if _, ok := k.GetEncTx(bx, eStrand.DecryptHeight, eStrand.Seq); ok {
		t.Fatal("stranded ciphertext must be released at grace expiry (bounded deferral, not a strand)")
	}
	if g := k.GetGlobalEncCount(bx); g != 0 {
		t.Fatalf("ref-count leak after stranded drop: global=%d, want 0", g)
	}
	if g := k.GetSubmitterEncCount(bx, "user2"); g != 0 {
		t.Fatalf("ref-count leak after stranded drop: submitter=%d, want 0", g)
	}
}
