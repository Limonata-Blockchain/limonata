package keeper_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	sdkmath "cosmossdk.io/math"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// AUDIT PROBE (VOTE-EXTENSION CONSENSUS SAFETY re-sweep of the HIGH fixes).
// ============================================================================

// TestProbe_H3_StakeMinorityOffChainCapture demonstrates that the HIGH-3 fix
// (keeper.DecryptingSetMeetsStake, an ON-CHAIN strict-stake-majority gate) does
// NOT prevent a stake-MINORITY that holds a seat-MAJORITY from decrypting: it
// reconstructs the epoch secret OFF-CHAIN from the t Shamir shares its seats learn,
// entirely bypassing the on-chain gate.
func TestProbe_H3_StakeMinorityOffChainCapture(t *testing.T) {
	// 3 honest whales (stake 1000) + 9 attacker mid-stake vals (stake 200).
	// Attacker is a stake MINORITY (1800 < 3000) but a seat MAJORITY.
	var vals []stakingtypes.Validator
	byOp := map[string]member{}
	reg := func(op string, tokens int64) {
		m := newMember(op, "")
		byOp[op] = m
		vals = append(vals, bondedVal(op, tokens))
	}
	honestStake, attackerStake := int64(0), int64(0)
	for _, op := range []string{"honest_A", "honest_B", "honest_C"} {
		reg(op, 1000)
		honestStake += 1000
	}
	for i := 0; i < 9; i++ {
		op := "attacker_" + string(rune('a'+i))
		reg(op, 200)
		attackerStake += 200
	}

	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(0, 0) // count-majority threshold, committee cap 16
	if err := k.SetParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Auto-announce every validator's enc key (with valid PoP) via the consume path.
	ann := make([]keeper.VEEntry, 0, len(vals))
	for _, m := range byOp {
		ann = append(ann, keeper.VEEntry{Operator: m.op, VE: annVE(m)})
	}
	k.ConsumeVoteExtensions(ctx.WithBlockHeight(1), ann)

	// Open epoch 1 over the full committee.
	k.EndBlockDKG(ctx.WithBlockHeight(1))
	round, ok := k.GetDkgRound(ctx, 1)
	if !ok || round.Status != types.DkgStatusOpen {
		t.Fatalf("epoch 1 not opened: %+v", round)
	}
	n := len(round.Members)
	tThr := int(round.Threshold)

	// Precondition of the finding: attacker holds a COUNT/seat majority (>= t) while a stake minority.
	attackerSeats := 0
	attackerPresent := map[uint64]bool{}
	attackerMembersByIdx := map[uint64]member{}
	for _, rm := range round.Members {
		if op := rm.OperatorAddr; len(op) >= 8 && op[:8] == "attacker" {
			attackerSeats++
			attackerPresent[rm.Index] = true
			attackerMembersByIdx[rm.Index] = byOp[op]
		}
	}
	t.Logf("committee n=%d threshold t=%d attackerSeats=%d attackerStake=%d honestStake=%d",
		n, tThr, attackerSeats, attackerStake, honestStake)
	if attackerSeats < tThr {
		t.Fatalf("expected attacker to hold >= t=%d seats, got %d", tThr, attackerSeats)
	}
	if attackerStake >= honestStake {
		t.Fatalf("expected attacker to be a stake MINORITY, got %d >= %d", attackerStake, honestStake)
	}

	// Everyone deals honestly so the round finalizes (full QUAL).
	dealCtx := ctx.WithBlockHeight(2)
	entries := make([]keeper.VEEntry, 0, n)
	for _, rm := range round.Members {
		m := byOp[rm.OperatorAddr]
		entries = append(entries, buildDealingEntry(t, round, m))
	}
	k.ConsumeVoteExtensions(dealCtx, entries)
	k.EndBlockDKG(ctx.WithBlockHeight(int64(round.ComplaintDeadline)))
	ak, ok := k.GetActiveKey(ctx, 1)
	if !ok {
		t.Fatal("no active key after finalize")
	}

	// --- ON-CHAIN gate: the attacker-only set is (correctly) REJECTED by HIGH-3's gate. ---
	if keeper.DecryptingSetMeetsStake(round.Members, attackerPresent) {
		t.Fatal("gate precondition broken: attacker set should fail the on-chain stake gate")
	}

	// --- OFF-CHAIN capture: the attacker reconstructs the secret from its OWN t shares. ---
	// Gather committed dealings (public, on-chain) and each attacker seat derives its Xi.
	dealings := map[uint64]types.Dealing{}
	k.IterateDealings(ctx, 1, func(d types.Dealing) { dealings[d.DealerIndex] = d })

	// Encrypt a secret to the epoch master pubkey (as a user's mempool tx would be).
	plain := []byte("front-run me: stake-minority seat-majority decrypts off-chain")
	ct, err := threshold.Encrypt(ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	commitments, err := dkg.ParseCommitmentPoints(ak.PublicCommitments)
	if err != nil {
		t.Fatal(err)
	}

	// The attacker uses exactly t of its OWN seats — no honest share, no on-chain msg.
	var partials []dkg.VerifiedShare
	used := 0
	for idx, m := range attackerMembersByIdx {
		if used >= tThr {
			break
		}
		share, err := dkgnode.DeriveShare(idx, m.priv, ak.Qual, dealings)
		if err != nil {
			t.Fatalf("attacker seat %d derive share: %v", idx, err)
		}
		ds, proof, err := dkg.ProveDecryptShare(share, ct)
		if err != nil {
			t.Fatalf("attacker seat %d prove: %v", idx, err)
		}
		partials = append(partials, dkg.VerifiedShare{Share: ds, Proof: proof})
		used++
	}
	shared, err := dkg.RecoverVerified(commitments, ct.A, tThr, partials)
	if err != nil {
		t.Fatalf("attacker off-chain RecoverVerified failed: %v", err)
	}
	got, err := threshold.Decrypt(shared, ct)
	if err != nil {
		t.Fatalf("attacker off-chain Decrypt failed: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("attacker off-chain plaintext mismatch: got %q", got)
	}
	t.Logf("EXPLOIT CONFIRMED: stake-minority (%d of %d) seat-majority decrypted OFF-CHAIN "+
		"despite the on-chain stake gate rejecting it. Recovered: %q", attackerStake, attackerStake+honestStake, got)
}

// TestProbe_PoP_PanicSafeOnAdversarialBytes fuzzes VerifyEncKeyPoP with adversarial
// key/sig bytes — it runs inside the deterministic consume path, so it must never panic.
func TestProbe_PoP_PanicSafeOnAdversarialBytes(t *testing.T) {
	m := newMember("opX", "")
	seeds := [][]byte{
		nil, {}, {0x00}, {0x30}, {0x30, 0x00}, {0x30, 0x81},
		bytes.Repeat([]byte{0xff}, 8), bytes.Repeat([]byte{0x30}, 72),
		bytes.Repeat([]byte{0x02}, 70),
	}
	for i := 0; i < 2000; i++ {
		b := make([]byte, i%140)
		_, _ = rand.Read(b)
		seeds = append(seeds, b)
	}
	for _, pop := range seeds {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VerifyEncKeyPoP panicked on adversarial pop %x: %v", pop, r)
				}
			}()
			_ = dkg.VerifyEncKeyPoP(m.pub, m.op, pop)
			// also with a garbage "pubkey"
			junk := make([]byte, 33)
			_, _ = rand.Read(junk)
			junk[0] = 0x02
			_ = dkg.VerifyEncKeyPoP(junk, m.op, pop)
		}()
	}
}

// TestProbe_StakeGate_Determinism checks the HIGH-3 gate is a pure function of committed
// state under large/zero/mixed weights (overflow-safe, order-independent).
func TestProbe_StakeGate_Determinism(t *testing.T) {
	big1, _ := sdkmath.NewIntFromString("340282366920938463463374607431768211456") // 2^128
	big2, _ := sdkmath.NewIntFromString("170141183460469231731687303715884105728") // 2^127
	members := []types.RoundMember{
		{Index: 1, Weight: big1},
		{Index: 2, Weight: big2},
		{Index: 3, Weight: big2},
	}
	// present {1} => 2^128 vs total (2^128 + 2^128) => exactly half => NOT strict majority.
	if keeper.DecryptingSetMeetsStake(members, map[uint64]bool{1: true}) {
		t.Fatal("exactly-half stake must NOT be a strict majority")
	}
	// present {1,2} => 2^128 + 2^127 > half => majority.
	if !keeper.DecryptingSetMeetsStake(members, map[uint64]bool{1: true, 2: true}) {
		t.Fatal("above-half stake must be a majority")
	}
}
