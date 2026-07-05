// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

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
// CYCLE-9 FIX VERIFICATION (DROP-DoS lens): the per-(operator,CIPHERTEXT) verify budget no longer
// DEFERS *honest* shares — the "defers + heals" guarantee cycle-7 promised — when there is MORE
// THAN ONE in-flight ciphertext in the same epoch.
//
// A decryption share is per-CIPHERTEXT (D = x*A, A is the ciphertext's ephemeral). An honest member
// owes owned_points shares PER ciphertext. buildDecryptShares emits exactly that: owned_points *
// (#in-flight ciphertexts) shares in ONE vote extension. Cycle-8 capped spent[{operator,epoch}] at
// owned_points — a SINGLE ciphertext's worth — starving the rest. Cycle-9 keys the budget per
// (operator, ciphertext) at owned_points, so ALL in-flight ciphertexts of an epoch accrue their honest
// shares each block (up to the bounded processed set), and nothing ages into a HARD strand.
// ============================================================================

// TestC9_MultiHonestCiphertextsPerEpoch_BothHeal: the in-block proof. TWO honest ciphertexts, same
// epoch, same maturity height. ALL FOUR committee members serve their FULL real share sets for BOTH
// (16 shares each: 8 for ct1, 8 for ct2 — exactly what buildDecryptShares produces). The per-
// (operator,ciphertext) budget stores BOTH ciphertexts' 32 shares — under cycle-8 ct2 was starved.
func TestC9_MultiHonestCiphertextsPerEpoch_BothHeal(t *testing.T) {
	c := c7Committee(t)
	servers := []string{"honest_A", "honest_B", "honest_C", "attacker"} // all serve REAL shares
	s := c.k.GetParams(c.ctx).EffectiveShareBudget()
	ceiling := keeper.MaxVerifyCiphertextsPerBlock * s

	base := c.ctx.WithBlockHeight(10).WithEventManager(sdk.NewEventManager())
	ct1, err := threshold.Encrypt(c.ak.Pub, []byte("ct1 - oldest"))
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := threshold.Encrypt(c.ak.Pub, []byte("ct2 - was starved"))
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

	t.Logf("ct1 stored=%d  ct2 stored=%d  chaff rejected=%d  total DLEQ verifies=%d  O(cap*S) ceiling=%d",
		stored1, stored2, rejected, verified, ceiling)

	if rejected != 0 {
		t.Fatalf("no attacker: expected 0 chaff rejections, got %d", rejected)
	}
	// THE FIX: both honest ciphertexts got ALL 32 of their shares stored in the same block.
	if stored1 != 4*8 || stored2 != 4*8 {
		t.Fatalf("cycle-9: both ciphertexts must accrue all 32 honest shares in one block, got ct1=%d ct2=%d", stored1, stored2)
	}
	if verified > ceiling {
		t.Fatalf("sanity: verifications %d exceeded O(cap*S) ceiling %d", verified, ceiling)
	}
	t.Logf("RESTORED: with 2 honest ciphertexts in one epoch BOTH accrued their full %d shares (ct1=%d ct2=%d) in one block — cycle-8 would have starved ct2 to 0.", 4*8, stored1, stored2)
}

// TestC9_BurstOfManyCiphertexts_NoTailStrand: the cross-block proof. A burst of K honest ciphertexts
// matures together in one epoch; every committee member faithfully serves every in-flight ciphertext
// each block (oldest-first, capped at VoteExtShareCap, exactly as buildDecryptShares does). Under the
// per-(operator,ciphertext) budget the whole burst is served within a couple of blocks (bounded only
// by the per-VE cap and the decrypt budget), so NONE of the K age past the 32-block grace — the cycle-7
// "defers + heals" guarantee is intact, all-honest, no attacker. Cycle-8 hard-STRANDED the tail here.
func TestC9_BurstOfManyCiphertexts_NoTailStrand(t *testing.T) {
	c := c7Committee(t)
	servers := []string{"honest_A", "honest_B", "honest_C"} // 24 pts >= t=18: enough to decrypt any ct
	shareCap := c.k.GetParams(c.ctx).VoteExtShareCap()      // 256
	const K = 40                                            // > grace(32): cycle-8 forced a tail strand here

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

	// THE FIX: every honest ciphertext decrypts, none strand. The per-(operator,ciphertext) budget
	// serves the whole burst within a couple of blocks (bounded by the per-VE cap, then the 2048/block
	// decrypt budget), so nothing ages past the 32-block grace.
	if totalStranded != 0 {
		t.Fatalf("cycle-9 REGRESSION: honest burst must NOT strand any ciphertext, got %d stranded", totalStranded)
	}
	if totalDecrypted != K {
		t.Fatalf("cycle-9 liveness: expected all %d honest ciphertexts to decrypt, got %d", K, totalDecrypted)
	}
	// Full throughput: at least one block decrypted MANY ciphertexts (not throttled to ~1/block).
	maxPerBlock := 0
	for _, n := range decByBlock {
		if n > maxPerBlock {
			maxPerBlock = n
		}
	}
	if maxPerBlock <= 2 {
		t.Fatalf("cycle-9: expected high per-block throughput (not ~1/block), max decrypted in a block was %d", maxPerBlock)
	}
	t.Logf("RESTORED (no drop): all %d/%d honest ciphertexts decrypted, 0 stranded, up to %d decrypted in a single block — "+
		"the per-(operator,ciphertext) budget serves the whole burst well within grace. Cycle-7 'defers + heals' preserved.",
		totalDecrypted, K, maxPerBlock)
}
