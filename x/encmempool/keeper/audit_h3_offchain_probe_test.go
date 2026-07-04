package keeper_test

import (
	"bytes"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// TestProbe_H3_OffChainReconstructionBypassesStakeGate demonstrates that the shipped
// HIGH-3 fix (keeper.DecryptingSetMeetsStake gating the ON-CHAIN decrypt combine) does
// NOT close the actual HIGH-3 vulnerability: a stake-MINORITY holding a seat-MAJORITY
// (>= t seats) holds >= t Shamir shares and reconstructs the epoch key OFF-CHAIN,
// decrypting the encrypted mempool early — the exact front-running break the feature
// exists to prevent. The on-chain gate is irrelevant to an attacker who computes the
// plaintext themselves.
func TestProbe_H3_OffChainReconstructionBypassesStakeGate(t *testing.T) {
	// n=4 committee, count threshold t = floor(4/2)+1 = 3 (the DEFAULT roundThreshold,
	// used by the proven 4-node run with dkg_threshold=0).
	n, thr := 4, 3
	parties := dkg.NewParties(n, thr)
	res, err := dkg.RunDKGSecure(parties)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}

	// A submitter encrypts a would-be-front-run tx to the committee public key.
	secret := []byte("SWAP 1000 ETH -> USDC at block N (front-run me)")
	ct, err := threshold.Encrypt(res.Pub, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Committee seats are STAKE-ranked. Model a stake-MINORITY seat-MAJORITY:
	//   - 1 honest whale  (index 1) with 100 tokens
	//   - 3 attacker dust (indices 2,3,4) with 1 token each
	// The 3 attacker validators are all bonded (small validator set => all seated), so
	// they hold 3 of 4 seats (a seat majority == t) while holding 3/103 of committee stake.
	members := []types.RoundMember{
		{Index: 1, OperatorAddr: "opHONEST", Weight: sdkmath.NewInt(100)},
		{Index: 2, OperatorAddr: "opATK2", Weight: sdkmath.NewInt(1)},
		{Index: 3, OperatorAddr: "opATK3", Weight: sdkmath.NewInt(1)},
		{Index: 4, OperatorAddr: "opATK4", Weight: sdkmath.NewInt(1)},
	}
	attackerSeats := map[uint64]bool{2: true, 3: true, 4: true} // 3 seats = seat majority = t

	// (A) The shipped fix works AS DESIGNED for the ON-CHAIN combine: the attacker-only
	//     set is a stake minority, so DecryptingSetMeetsStake rejects it.
	if keeper.DecryptingSetMeetsStake(members, attackerSeats) {
		t.Fatal("precondition: expected on-chain stake gate to REJECT the stake-minority set")
	}
	t.Log("on-chain gate DecryptingSetMeetsStake(attacker seats) = false (fix blocks on-chain combine)")

	// (B) ...but the SAME 3 shares reconstruct the shared secret and decrypt OFF-CHAIN,
	//     with no chain involvement whatsoever. The attacker controls its own nodes and
	//     trivially extracts the derived shares X_m.
	byIndex := map[uint64]threshold.Share{}
	for _, s := range res.Shares {
		byIndex[s.Index] = s
	}
	var ds []*threshold.DecryptShare
	for _, idx := range []uint64{2, 3, 4} {
		s, ok := byIndex[idx]
		if !ok {
			t.Fatalf("attacker share %d missing from DKG output", idx)
		}
		d, err := threshold.ComputeShare(s, ct)
		if err != nil {
			t.Fatalf("compute share %d: %v", idx, err)
		}
		ds = append(ds, d)
	}
	shared, err := threshold.Recover(ds) // off-chain Lagrange combine of t=3 shares
	if err != nil {
		t.Fatalf("off-chain recover: %v", err)
	}
	pt, err := threshold.Decrypt(shared, ct)
	if err != nil {
		t.Fatalf("off-chain decrypt (attack FAILED, would mean HIGH-3 is closed): %v", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("off-chain decrypt mismatch: %q", pt)
	}

	// If we reach here the attack SUCCEEDED: a stake-minority (3/103) seat-majority (t of n)
	// decrypted the ciphertext EARLY, OFF-CHAIN, despite the on-chain stake gate rejecting
	// the same set. HIGH-3 SURVIVES the fix.
	t.Logf("HIGH-3 SURVIVES: stake-minority (3/103) seat-majority recovered plaintext off-chain: %q", pt)
}

// TestProbe_H3_MirrorsShippedRegressionCommittee reproduces the OFF-CHAIN break using the
// EXACT committee shape the shipped HIGH-3 regression (TestReg_H3_StakeMinoritySeatMajority
// CannotDecrypt) declares "fixed": 3 honest whales (1000 each) + 9 attacker mid validators
// (200 each) => n=12, t=7, attacker holds 9 seats (stake minority 1800 < 3000). Their
// regression only asserts DecryptingSetMeetsStake==false; it never checks that the 9
// attacker shares reconstruct the key. They do.
func TestProbe_H3_MirrorsShippedRegressionCommittee(t *testing.T) {
	n := 12
	thr := n/2 + 1 // = 7, exactly roundThreshold(DkgThreshold=0, n=12)
	parties := dkg.NewParties(n, thr)
	res, err := dkg.RunDKGSecure(parties)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}
	secret := []byte("victim tx body — must stay sealed until maturity")
	ct, err := threshold.Encrypt(res.Pub, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Attacker holds member indices 4..12 (9 seats). Honest whales hold 1..3.
	members := make([]types.RoundMember, n)
	present := map[uint64]bool{}
	for i := 0; i < n; i++ {
		idx := uint64(i + 1)
		if i < 3 {
			members[i] = types.RoundMember{Index: idx, OperatorAddr: "honest", Weight: sdkmath.NewInt(1000)}
		} else {
			members[i] = types.RoundMember{Index: idx, OperatorAddr: "attacker", Weight: sdkmath.NewInt(200)}
			present[idx] = true // 9 attacker seats
		}
	}
	if keeper.DecryptingSetMeetsStake(members, present) {
		t.Fatal("precondition: on-chain gate should reject the 9-seat stake-minority set")
	}

	byIndex := map[uint64]threshold.Share{}
	for _, s := range res.Shares {
		byIndex[s.Index] = s
	}
	var ds []*threshold.DecryptShare
	for idx := uint64(4); idx <= 12; idx++ { // the 9 attacker shares
		d, err := threshold.ComputeShare(byIndex[idx], ct)
		if err != nil {
			t.Fatalf("compute share %d: %v", idx, err)
		}
		ds = append(ds, d)
	}
	shared, err := threshold.Recover(ds)
	if err != nil {
		t.Fatalf("off-chain recover: %v", err)
	}
	pt, err := threshold.Decrypt(shared, ct)
	if err != nil {
		t.Fatalf("off-chain decrypt failed (would mean HIGH-3 closed): %v", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("plaintext mismatch")
	}
	t.Logf("HIGH-3 SURVIVES on the shipped regression's own committee (n=12,t=7): 9 attacker "+
		"shares (stake minority 1800<3000) recovered plaintext off-chain: %q", pt)
}
