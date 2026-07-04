package keeper_test

import (
	"testing"

	"github.com/cosmos/evm/x/encmempool/threshold"
)

// ============================================================================
// HIGH-3 — OFF-CHAIN reconstruction regression (FLIPPED).
//
// The original probes here DEMONSTRATED the break: with plain (unweighted) Shamir the decryption
// threshold was a member COUNT, so a stake-MINORITY holding a seat-MAJORITY held >= t legitimate
// shares and reconstructed the epoch secret OFF-CHAIN — an anti-MEV/front-running break no
// on-chain gate could stop. The fix bakes stake into the cryptography (stake-weighted evaluation
// points, threshold t = floor(2S/3)+1 of the budget S), so these tests now assert the OPPOSITE:
// a stake-minority holds < t points and CANNOT reconstruct, while a stake-supermajority can.
// ============================================================================

// TestReg_H3_OffChainReconstructionRequiresStakeSupermajority: a committee of 1 honest whale
// (stake 100, ~77%) + 3 attacker validators (stake 10 each). The 3 attackers are a SEAT MAJORITY
// (3 of 4) but a STAKE MINORITY (30 < 100). Under stake weighting they hold only ~6 of S=24 eval
// points (< t=17), so — even given ALL their real derived shares and ignoring every on-chain
// gate — they cannot recover the epoch secret. The whale alone (a stake supermajority) holds
// >= t points and can, proving the capability now tracks stake, not seat count.
func TestReg_H3_OffChainReconstructionRequiresStakeSupermajority(t *testing.T) {
	stakes := map[string]int64{"whale_honest": 100, "atk_a": 10, "atk_b": 10, "atk_c": 10}
	c := runTransparentDKG(t, stakes, 24)

	attackers := opsWithPrefix(c, "atk")
	whale := opsWithPrefix(c, "whale")
	if len(attackers) <= len(c.round.Members)/2 {
		t.Fatalf("precondition: attackers must be a seat majority, got %d/%d", len(attackers), len(c.round.Members))
	}
	if c.coalitionStake(attackers) >= c.coalitionStake(whale) {
		t.Fatalf("precondition: attackers must be a stake minority, got %d>=%d",
			c.coalitionStake(attackers), c.coalitionStake(whale))
	}

	plain := []byte("victim tx body — must stay sealed until maturity")
	ct, err := threshold.Encrypt(c.ak.Pub, plain)
	if err != nil {
		t.Fatal(err)
	}

	// (A) The stake-minority seat-majority CANNOT reconstruct off-chain.
	atkPts, atkRecovered := c.coalitionReconstructs(t, attackers, ct, plain)
	if atkPts >= int(c.ak.Threshold) {
		t.Fatalf("attacker holds %d >= t=%d points — allocation failed to bound the minority", atkPts, c.ak.Threshold)
	}
	if atkRecovered {
		t.Fatal("HIGH-3 REGRESSION: stake-minority seat-majority reconstructed the secret off-chain")
	}

	// (B) The whale (a stake supermajority) CAN — liveness of the honest path is preserved.
	whalePts, whaleRecovered := c.coalitionReconstructs(t, whale, ct, plain)
	if whalePts < int(c.ak.Threshold) || !whaleRecovered {
		t.Fatalf("stake supermajority must reconstruct: points=%d t=%d recovered=%v",
			whalePts, c.ak.Threshold, whaleRecovered)
	}
	t.Logf("attacker seat-majority holds %d < t=%d points (cannot decrypt); whale supermajority "+
		"holds %d >= t and decrypts — capability tracks STAKE, not seats", atkPts, c.ak.Threshold, whalePts)
}
