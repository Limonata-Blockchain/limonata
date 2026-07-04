package keeper_test

import (
	"strings"
	"testing"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// Regression tests for the four HIGH audit findings on the transparent in-node DKG.
// Each asserts the FIXED behaviour and fails against the pre-fix source (noted inline).
// The original probes (which reproduced the vulnerabilities) are superseded by these.
// ============================================================================

// HIGH-2 / HIGH-4 — an enc key is registered ONLY with a valid, operator-bound
// proof-of-possession, and a key already bound to another operator is rejected. This
// closes the impersonation/collision that let an attacker announce a victim's public key.
//
// PRE-FIX: RecordEncPubKey(operator, key) took no PoP and did no uniqueness check, so
// every assertion below (reject-without-PoP, reject-impersonation, reject-duplicate) failed.
func TestReg_H2_EncKeyPoPAndUniqueness(t *testing.T) {
	victim := newMember("opVICTIM", "")
	k, ctx := newKeeperSK(t, 1, &mockStaking{})
	_ = k.SetParams(ctx, transparentParams(1, 0))

	// (a) No PoP -> rejected.
	if k.RecordEncPubKey(ctx, victim.op, victim.pub, nil) {
		t.Fatal("HIGH-2: an announcement with NO proof-of-possession must be rejected")
	}
	if _, ok := k.GetEncPubKey(ctx, victim.op); ok {
		t.Fatal("a rejected (no-PoP) announcement must not be stored")
	}

	// (b) Valid PoP -> accepted, and idempotent thereafter.
	if !k.RecordEncPubKey(ctx, victim.op, victim.pub, dkg.SignEncKeyPoP(victim.priv, victim.op)) {
		t.Fatal("a valid, operator-bound PoP must register the key")
	}
	if k.RecordEncPubKey(ctx, victim.op, victim.pub, dkg.SignEncKeyPoP(victim.priv, victim.op)) {
		t.Fatal("re-announcing the identical key must be an idempotent no-op")
	}

	// (c) Impersonation: an attacker (no private key) replays the victim's public key +
	// PoP under its OWN operator. The PoP is operator-bound, so it fails to verify.
	attackerOp := "opATTACKER"
	replay := dkg.SignEncKeyPoP(victim.priv, victim.op) // victim's PoP, bound to opVICTIM
	if k.RecordEncPubKey(ctx, attackerOp, victim.pub, replay) {
		t.Fatal("HIGH-2: replaying a victim's key+PoP under a different operator must be rejected")
	}

	// (d) Uniqueness: even a party that DOES hold the key (e.g. a copied key file on a
	// second operator) is rejected, because the key is already bound to opVICTIM.
	secondOp := "opSECOND"
	if k.RecordEncPubKey(ctx, secondOp, victim.pub, dkg.SignEncKeyPoP(victim.priv, secondOp)) {
		t.Fatal("HIGH-2: a key already bound to another operator must be rejected (uniqueness)")
	}
	if owner, _ := k.GetEncKeyOwner(ctx, victim.pub); owner != victim.op {
		t.Fatalf("the key must remain solely owned by the victim, got owner %q", owner)
	}
}

// HIGH-4 — a node self-identifies by OPERATOR (its real consensus identity), never by an
// enc-key first-match, so a colliding key cannot misindex and silence it.
//
// PRE-FIX: the live path used EncKey.MyIndex (enc-key first-match), which returns the
// ATTACKER's lower seat when both members carry the same key -> the honest member's shares
// were rejected. The assertion that the operator-keyed index is the TRUE seat is the fix.
func TestReg_H4_SelfIdentifyByOperator(t *testing.T) {
	victim := newMember("opVICTIM", "") // "opVICTIM" sorts AFTER "opATTACK"
	round := types.DkgRound{
		Epoch: 1, Threshold: 2, Status: types.DkgStatusOpen,
		Members: []types.RoundMember{
			{Index: 1, OperatorAddr: "opATTACK", EncPubKey: victim.pub}, // hypothetical collision
			{Index: 2, OperatorAddr: "opVICTIM", EncPubKey: victim.pub},
		},
	}
	if got := types.MemberIndexByOperator(round.Members, "opVICTIM"); got != 2 {
		t.Fatalf("HIGH-4: the victim must self-identify by operator to its TRUE index 2, got %d", got)
	}
	// Contrast (documents why the switch matters): the old enc-key first-match returns the
	// attacker's seat 1 for the very same member set.
	ek := &dkgnode.EncKey{Priv: victim.priv, Pub: victim.pub}
	if old := ek.MyIndex(round.Members); old != 1 {
		t.Fatalf("sanity: enc-key first-match returns the spoofed seat 1, got %d", old)
	}
}

// HIGH-3 — the committee is STAKE-ranked but the Shamir threshold is a member COUNT, so a
// stake-minority Sybil can hold a seat-majority. The decrypt path now additionally requires
// the contributing set to hold a STRICT MAJORITY of committee stake, so a stake-minority
// seat-majority can no longer form a valid decrypting set.
//
// PRE-FIX: there was no stake gate; the attacker's >= t seats alone decrypted. The
// DecryptingSetMeetsStake(attacker)==false assertion is the fix and fails pre-fix.
func TestReg_H3_StakeMinoritySeatMajorityCannotDecrypt(t *testing.T) {
	var vals []stakingtypes.Validator
	members := map[string]member{}
	reg := func(op string, tokens int64) {
		m := newMember(op, "")
		members[op] = m
		vals = append(vals, bondedVal(op, tokens))
	}
	// 3 honest whales (stake 3000) + 9 attacker mid-stake validators (stake 1800): the
	// attacker is a stake MINORITY but a seat MAJORITY.
	reg("honest_A", 1000)
	reg("honest_B", 1000)
	reg("honest_C", 1000)
	honestStake := int64(3000)
	attackerStake := int64(0)
	for i := 0; i < 9; i++ {
		op := "attacker_" + string(rune('a'+i))
		reg(op, 200)
		attackerStake += 200
	}

	k, ctx := newKeeperSK(t, 1, &mockStaking{vals: vals})
	p := transparentParams(0, 0) // DkgThreshold=0 -> count majority; default committee cap 16
	_ = k.SetParams(ctx, p)
	for _, m := range members {
		k.RecordEncPubKey(ctx, m.op, m.pub, dkg.SignEncKeyPoP(m.priv, m.op))
	}

	committee := k.ActiveMembers(ctx, p)
	n := len(committee)
	tThreshold := n/2 + 1

	attacker := map[uint64]bool{}
	attackerSeats := 0
	for _, cm := range committee {
		if strings.HasPrefix(cm.OperatorAddr, "attacker") {
			attacker[cm.Index] = true
			attackerSeats++
		}
	}

	// Preconditions of the finding still hold: attacker is a COUNT-majority and a stake-MINORITY.
	if attackerSeats < tThreshold {
		t.Fatalf("expected attacker to hold a count-majority (>= t=%d) of seats, got %d", tThreshold, attackerSeats)
	}
	if attackerStake >= honestStake {
		t.Fatalf("expected attacker to be a stake minority, got attacker=%d honest=%d", attackerStake, honestStake)
	}

	// THE FIX: the stake-minority seat-majority is NOT a valid decrypting set.
	if keeper.DecryptingSetMeetsStake(committee, attacker) {
		t.Fatal("HIGH-3: a stake-minority seat-majority must NOT form a valid decrypting set")
	}
	// The full committee (a stake majority) still decrypts — liveness preserved.
	full := map[uint64]bool{}
	for _, cm := range committee {
		full[cm.Index] = true
	}
	if !keeper.DecryptingSetMeetsStake(committee, full) {
		t.Fatal("the full committee (stake majority) must form a valid decrypting set")
	}
}
