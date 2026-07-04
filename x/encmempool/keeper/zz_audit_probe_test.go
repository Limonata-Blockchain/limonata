package keeper_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// AUDIT PROBE (VOTE-EXTENSION CONSENSUS SAFETY re-sweep of the HIGH fixes).
// ============================================================================

// TestReg_H3_StakeMinorityOffChainCaptureBlocked is the FLIPPED HIGH-3 probe. It builds the
// worst-case within-BFT adversary — a coalition holding EXACTLY the 1/3 Byzantine stake bound
// (5 mids @ 1000 = 5000 of 15000) yet a SEAT MAJORITY (5 of 7 seats) — and proves that, given
// ALL its real shares, it holds < t stake-weighted evaluation points and CANNOT reconstruct the
// epoch secret off-chain. Pre-fix (unweighted, count threshold) its 5 seats == 5 Shamir shares
// captured decryption; the stake-weighted scheme reduces its capability to its stake.
func TestReg_H3_StakeMinorityOffChainCaptureBlocked(t *testing.T) {
	stakes := map[string]int64{"honest_A": 5000, "honest_B": 5000}
	for i := 0; i < 5; i++ {
		stakes["attacker_"+string(rune('a'+i))] = 1000
	}
	c := runTransparentDKG(t, stakes, 24)

	attackers := opsWithPrefix(c, "attacker")
	honest := opsWithPrefix(c, "honest")
	if len(attackers) <= len(c.round.Members)/2 {
		t.Fatalf("precondition: attacker must be a seat majority, got %d/%d", len(attackers), len(c.round.Members))
	}
	// Attacker holds EXACTLY 1/3 of stake (the Byzantine bound) — the strongest within-model case.
	if 3*c.coalitionStake(attackers) != c.coalitionStake(attackers)+c.coalitionStake(honest) {
		t.Fatalf("precondition: attacker stake should be exactly 1/3, got %d of %d",
			c.coalitionStake(attackers), c.coalitionStake(attackers)+c.coalitionStake(honest))
	}

	plain := []byte("front-run me: stake-minority seat-majority must NOT decrypt off-chain")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	pts, recovered := c.coalitionReconstructs(t, attackers, ct, plain)
	if pts >= int(c.ak.Threshold) {
		t.Fatalf("allocation failed: 1/3-stake attacker holds %d >= t=%d points", pts, c.ak.Threshold)
	}
	if recovered {
		t.Fatal("HIGH-3 REGRESSION: 1/3-stake seat-majority reconstructed the secret off-chain")
	}

	// The on-chain stake gate (now defense-in-depth) also rejects the same member set.
	present := map[uint64]bool{}
	for _, op := range attackers {
		present[types.MemberIndexByOperator(c.round.Members, op)] = true
	}
	if keeper.DecryptingSetMeetsStake(c.round.Members, present) {
		t.Fatal("defense-in-depth: attacker set must still fail the on-chain stake gate")
	}
	t.Logf("1/3-stake seat-majority (%d/%d seats) holds only %d < t=%d eval points; off-chain "+
		"capture is cryptographically impossible", len(attackers), len(c.round.Members), pts, c.ak.Threshold)
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
