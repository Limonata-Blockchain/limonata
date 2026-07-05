package keeper_test

import (
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// AUDIT PROBE (cycle-8, DROP-DoS lens): does the per-(operator,EPOCH) verify budget
// wrongly DEFER *honest* shares — the exact "defers + heals" guarantee the cycle-7 fix
// promised — when there is MORE THAN ONE in-flight ciphertext in the same epoch?
//
// A decryption share is per-CIPHERTEXT (D = x*A, A is the ciphertext's ephemeral). An
// honest member owes owned_points shares PER ciphertext. buildDecryptShares emits exactly
// that: owned_points * (#in-flight ciphertexts) shares in ONE vote extension. But
// ingestDecryptSharesBounded caps spent[{operator,epoch}] at owned_points — a SINGLE
// ciphertext's worth — so with C ciphertexts in an epoch, only the oldest ciphertext's
// honest shares are stored per block; C-1 ciphertexts' honest shares are budget-deferred
// EVERY block. No attacker involved.
// ============================================================================

// TestProbeC8_MultiHonestCiphertextsPerEpoch_HonestSharesStarved: the in-block smoking gun.
// TWO honest ciphertexts, same epoch, same maturity height. ALL FOUR committee members serve
// their FULL real share sets for BOTH (16 shares each: 8 for ct1, 8 for ct2 — exactly what
// buildDecryptShares produces). The per-(operator,epoch) budget of 8 stores only ct1; ct2 gets
// ZERO stored shares, despite zero attacker and the block using only 32 of its 256-share
// O(S) ceiling. Under cycle-7 (no budget) every honest share was stored and BOTH would heal.
func TestProbeC8_MultiHonestCiphertextsPerEpoch_HonestSharesStarved(t *testing.T) {
	c := c7Committee(t)
	servers := []string{"honest_A", "honest_B", "honest_C", "attacker"} // all serve REAL shares
	shareCap := c.k.GetParams(c.ctx).VoteExtShareCap()                   // 256

	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct1, err := threshold.Encrypt(c.ak.Pub, []byte("ct1 - oldest"))
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := threshold.Encrypt(c.ak.Pub, []byte("ct2 - starved"))
	if err != nil {
		t.Fatal(err)
	}
	e1 := c.k.SubmitEncTx(base, "user", 10, 2, ct1.A, ct1.Nonce, ct1.Body, 1) // (12, seq1)
	e2 := c.k.SubmitEncTx(base, "user", 10, 2, ct2.A, ct2.Nonce, ct2.Body, 1) // (12, seq2)

	// Every member's ONE vote extension carries its real shares for ct1 THEN ct2 (oldest-first,
	// exactly as buildDecryptShares orders them). 8 + 8 = 16 real shares per member.
	ing := base.WithBlockHeight(11).WithEventManager(sdk.NewEventManager())
	var entries []keeper.VEEntry
	for _, op := range servers {
		sh := append(veSharesFor(t, c, base, e1, ct1, op), veSharesFor(t, c, base, e2, ct2, op)...)
		if len(sh) != 16 {
			t.Fatalf("precondition: %s should serve 16 real shares (8 per ct), built %d", op, len(sh))
		}
		entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: sh}})
	}
	c.k.ConsumeVoteExtensions(ing, entries)

	stored1 := len(c.k.CollectShares(c.ctx, e1.DecryptHeight, e1.Seq))
	stored2 := len(c.k.CollectShares(c.ctx, e2.DecryptHeight, e2.Seq))
	rejected := countEvents(ing, "encmempool_dkg_ve_share_rejected")
	verified := stored1 + stored2 + rejected

	t.Logf("ct1 stored=%d  ct2 stored=%d  chaff rejected=%d  total DLEQ verifies=%d  O(S) ceiling=%d",
		stored1, stored2, rejected, verified, shareCap)

	if rejected != 0 {
		t.Fatalf("no attacker: expected 0 chaff rejections, got %d", rejected)
	}
	// The regression: every honest member served ct2, the block had 224 spare ceiling slots,
	// yet the per-epoch budget stored NONE of ct2's honest shares.
	if stored2 != 0 {
		t.Logf("NOTE: ct2 got %d shares — throttle weaker than modeled; still a partial starve if < 32", stored2)
	}
	if stored2 >= 24 { // >= t=18 worth would mean ct2 could also decrypt this block
		t.Fatalf("expected ct2 honest shares to be budget-DEFERRED (starved), but %d were stored", stored2)
	}
	if verified > shareCap {
		t.Fatalf("sanity: verifications %d exceeded ceiling %d", verified, shareCap)
	}
	t.Logf("CONFIRMED: with 2 honest ciphertexts in one epoch, honest ct2 was starved to %d stored "+
		"shares (ct1=%d) despite %d/%d spare O(S) ceiling and NO attacker — cycle-8 defers honest "+
		"shares cycle-7 would have stored+healed.", stored2, stored1, shareCap-verified, shareCap)
}

// TestProbeC8_DrainRateOneCtPerBlock_TailStrands: escalate the in-block starve to a DROP. A burst
// of K honest ciphertexts matures together in one epoch; every committee member faithfully serves
// every in-flight ciphertext each block (oldest-first, capped at VoteExtShareCap, exactly as
// buildDecryptShares does). The per-(operator,epoch) budget drains only ONE ciphertext's honest
// shares per block, so throughput is ~1 decrypt/block regardless of the 2048/block decrypt budget.
// With K > StrandedDecryptGraceBlocks, the tail ciphertexts age past their 32-block grace and
// HARD-STRAND — the cycle-7 "defers + heals" turned into "defers + DROPS", all-honest, no attacker.
func TestProbeC8_DrainRateOneCtPerBlock_TailStrands(t *testing.T) {
	c := c7Committee(t)
	servers := []string{"honest_A", "honest_B", "honest_C"} // 24 pts >= t=18: enough to decrypt any ct
	shareCap := c.k.GetParams(c.ctx).VoteExtShareCap()       // 256
	const K = 40                                             // > grace(32): forces a tail strand

	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())

	type ctRec struct {
		e  types.EncTx
		ct *threshold.Ciphertext
	}
	var cts []ctRec
	// Precompute each (ciphertext, server) real share set ONCE (D=x*A is fixed per member+ct).
	cache := map[uint64]map[string][]types.VoteExtShare{}
	for i := 0; i < K; i++ {
		ct, err := threshold.Encrypt(c.ak.Pub, []byte(fmt.Sprintf("swap-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		e := c.k.SubmitEncTx(base, "user", 10, 2, ct.A, ct.Nonce, ct.Body, 1) // all mature @12
		cts = append(cts, ctRec{e: e, ct: ct})
		cache[e.Seq] = map[string][]types.VoteExtShare{}
		for _, op := range servers {
			cache[e.Seq][op] = veSharesFor(t, c, base, e, ct, op)
		}
	}

	decByBlock := map[int64]int{}
	strandsByBlock := map[int64]int{}
	totalDecrypted, totalStranded := 0, 0

	for h := int64(12); h <= 47; h++ {
		// ---- PreBlock: every server serves EVERY still-in-flight ciphertext, oldest-first,
		// capped at VoteExtShareCap (faithful buildDecryptShares behavior) ----
		var inflight []ctRec
		for _, r := range cts {
			if _, ok := c.k.GetEncTx(c.ctx, r.e.DecryptHeight, r.e.Seq); ok {
				inflight = append(inflight, r) // cts iterate in submit (seq) order = oldest-first
			}
		}
		preb := base.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		var entries []keeper.VEEntry
		for _, op := range servers {
			var sh []types.VoteExtShare
			for _, r := range inflight {
				if len(sh) >= shareCap {
					break
				}
				sh = append(sh, cache[r.e.Seq][op]...)
			}
			if len(sh) > shareCap {
				sh = sh[:shareCap]
			}
			entries = append(entries, keeper.VEEntry{Operator: op, VE: types.VoteExtension{Shares: sh}})
		}
		c.k.ConsumeVoteExtensions(preb, entries)

		// ---- BeginBlock: decrypt matured / defer short / strand past-grace ----
		bb := base.WithBlockHeight(h).WithEventManager(sdk.NewEventManager())
		if err := c.k.BeginBlock(bb); err != nil {
			t.Fatal(err)
		}
		decByBlock[h] = countEvents(bb, "encmempool_decrypted")
		strandsByBlock[h] = countEvents(bb, "encmempool_decrypt_stranded")
		totalDecrypted += decByBlock[h]
		totalStranded += strandsByBlock[h]
	}

	for h := int64(12); h <= 47; h++ {
		if decByBlock[h] > 0 || strandsByBlock[h] > 0 {
			t.Logf("h=%d  decrypted=%d  stranded=%d", h, decByBlock[h], strandsByBlock[h])
		}
	}
	t.Logf("K=%d honest ciphertexts (all mature @12, one epoch, %d honest servers, NO attacker): "+
		"totalDecrypted=%d  totalStranded=%d", K, len(servers), totalDecrypted, totalStranded)

	// Throughput throttle: at least one block decrypted <= 1 ct even though the decrypt budget is 2048.
	maxPerBlock := 0
	for _, n := range decByBlock {
		if n > maxPerBlock {
			maxPerBlock = n
		}
	}
	if maxPerBlock > 2 {
		t.Fatalf("expected the ingest budget to throttle decryption to ~1 ct/block, saw %d in a block", maxPerBlock)
	}
	// The DROP: honest ciphertexts stranded purely because their honest shares were budget-deferred
	// past the 32-block grace. This is the cycle-7 heal guarantee broken by the cycle-8 bound.
	if totalStranded == 0 {
		t.Fatalf("expected the tail (K=%d > grace=%d) to HARD-STRAND under the 1-ct/block drain, but none did", K, keeper.StrandedDecryptGraceBlocks)
	}
	t.Logf("CONFIRMED (drop): %d/%d honest ciphertexts HARD-STRANDED (encmempool_decrypt_stranded) with a "+
		"fully honest committee — the per-(operator,epoch) verify budget throttled honest healing to "+
		"~1 ct/block, so the burst aged past grace. Cycle-7 'defers + heals' regressed to 'defers + DROPS'.",
		totalStranded, K)
}
